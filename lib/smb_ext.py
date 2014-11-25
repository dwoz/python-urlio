"""
Override pysmb's listPath method to be able to limit the number of
results returned.
"""
from smb.base import (
    _PendingRequest, SharedFile, NotConnectedError, NotReadyError
)
from smb.smb_constants import *
from smb.smb_structs import *
from smb.smb2_structs import *
DFLTSEARCH = (
    SMB_FILE_ATTRIBUTE_READONLY |
    SMB_FILE_ATTRIBUTE_HIDDEN |
    SMB_FILE_ATTRIBUTE_SYSTEM |
    SMB_FILE_ATTRIBUTE_DIRECTORY |
    SMB_FILE_ATTRIBUTE_ARCHIVE
)

def listPath(conn, service_name, path,
             search = DFLTSEARCH,
             pattern = '*', timeout = 30, limit=0):
    """
    Retrieve a directory listing of files/folders at *path*

    :param string/unicode service_name: the name of the shared folder for the *path*
    :param string/unicode path: path relative to the *service_name* where we are interested to learn about its files/sub-folders.
    :param integer search: integer value made up from a bitwise-OR of *SMB_FILE_ATTRIBUTE_xxx* bits (see smb_constants.py).
                           The default *search* value will query for all read-only, hidden, system, archive files and directories.
    :param string/unicode pattern: the filter to apply to the results before returning to the client.
    :return: A list of :doc:`smb.base.SharedFile<smb_SharedFile>` instances.
    """
    if not conn.sock:
        raise NotConnectedError('Not connected to server')

    results = [ ]

    def cb(entries):
        conn.is_busy = False
        results.extend(entries)

    def eb(failure):
        conn.is_busy = False
        raise failure

    conn.is_busy = True
    try:
        if conn.is_using_smb2:
            _listPath_SMB2(
                conn, service_name, path, cb, eb, search = search,
                pattern = pattern, timeout = timeout, limit=limit
            )
        else:
            _listPath_SMB1(
                conn, service_name, path, cb, eb, search = search,
                pattern = pattern, timeout = timeout, limit=limit
            )
        while conn.is_busy:
            conn._pollForNetBIOSPacket(timeout)
    finally:
        conn.is_busy = False

    return results


def _listPath_SMB2(
        conn, service_name, path, callback, errback, search, pattern,
        timeout=30, limit=0,
    ):
    if not conn.has_authenticated:
        raise NotReadyError('SMB connection not authenticated')

    expiry_time = time.time() + timeout
    path = path.replace('/', '\\')
    if path.startswith('\\'):
        path = path[1:]
    if path.endswith('\\'):
        path = path[:-1]
    messages_history = [ ]
    results = [ ]

    def sendCreate(tid):
        create_context_data = binascii.unhexlify(
            "28 00 00 00 10 00 04 00 00 00 18 00 10 00 00 00 "
            "44 48 6e 51 00 00 00 00 00 00 00 00 00 00 00 00 "
            "00 00 00 00 00 00 00 00 18 00 00 00 10 00 04 00 "
            "00 00 18 00 00 00 00 00 4d 78 41 63 00 00 00 00 "
            "00 00 00 00 10 00 04 00 00 00 18 00 00 00 00 00 "
            "51 46 69 64 00 00 00 00".replace(' ', '').replace('\n', ''))
        m = SMB2Message(SMB2CreateRequest(path,
                                          file_attributes = 0,
                                          access_mask = FILE_READ_DATA | FILE_READ_EA | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
                                          share_access = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                          oplock = SMB2_OPLOCK_LEVEL_NONE,
                                          impersonation = SEC_IMPERSONATE,
                                          create_options = FILE_DIRECTORY_FILE,
                                          create_disp = FILE_OPEN,
                                          create_context_data = create_context_data))
        m.tid = tid
        conn._sendSMBMessage(m)
        conn.pending_requests[m.mid] = _PendingRequest(m.mid, expiry_time, createCB, errback)
        messages_history.append(m)

    def createCB(create_message, **kwargs):
        messages_history.append(create_message)
        if create_message.status == 0:
            sendQuery(create_message.tid, create_message.payload.fid, '')
        else:
            errback(OperationFailure('Failed to list %s on %s: Unable to open directory' % ( path, service_name ), messages_history))

    def sendQuery(tid, fid, data_buf):
        m = SMB2Message(SMB2QueryDirectoryRequest(fid, pattern,
                                                  info_class = 0x03,   # FileBothDirectoryInformation
                                                  flags = 0,
                                                  output_buf_len = conn.max_transact_size))
        m.tid = tid
        conn._sendSMBMessage(m)
        conn.pending_requests[m.mid] = _PendingRequest(m.mid, expiry_time, queryCB, errback, fid = fid, data_buf = data_buf)
        messages_history.append(m)

    def queryCB(query_message, **kwargs):
        messages_history.append(query_message)
        if query_message.status == 0:
            data_buf = decodeQueryStruct(
                kwargs['data_buf'] + query_message.payload.data,
                query_message.tid, kwargs['fid']
            )
            if data_buf is False:
                closeFid(query_message.tid, kwargs['fid'], results = results)
            else:
                sendQuery(query_message.tid, kwargs['fid'], data_buf)
        elif query_message.status == 0x80000006L:  # STATUS_NO_MORE_FILES
            closeFid(query_message.tid, kwargs['fid'], results = results)
        else:
            closeFid(query_message.tid, kwargs['fid'], error = query_message.status)

    def decodeQueryStruct(data_bytes, tid, fid):
        # SMB_FIND_FILE_BOTH_DIRECTORY_INFO structure. See [MS-CIFS]: 2.2.8.1.7 and [MS-SMB]: 2.2.8.1.1
        info_format = '<IIQQQQQQIIIBB24s'
        info_size = struct.calcsize(info_format)

        data_length = len(data_bytes)
        offset = 0
        while offset < data_length:
            if offset + info_size > data_length:
                return data_bytes[offset:]

            next_offset, _, \
            create_time, last_access_time, last_write_time, last_attr_change_time, \
            file_size, alloc_size, file_attributes, filename_length, ea_size, \
            short_name_length, _, short_name = struct.unpack(info_format, data_bytes[offset:offset+info_size])

            offset2 = offset + info_size
            if offset2 + filename_length > data_length:
                return data_bytes[offset:]

            filename = data_bytes[offset2:offset2+filename_length].decode('UTF-16LE')
            short_name = short_name.decode('UTF-16LE')
            results.append(SharedFile(convertFILETIMEtoEpoch(create_time), convertFILETIMEtoEpoch(last_access_time),
                                      convertFILETIMEtoEpoch(last_write_time), convertFILETIMEtoEpoch(last_attr_change_time),
                                      file_size, alloc_size, file_attributes, short_name, filename))
            if limit != 0 and len(results) >= limit:
                return False
            if next_offset:
                offset += next_offset
            else:
                break
        return ''

    def closeFid(tid, fid, results = None, error = None):
        m = SMB2Message(SMB2CloseRequest(fid))
        m.tid = tid
        conn._sendSMBMessage(m)
        conn.pending_requests[m.mid] = _PendingRequest(m.mid, expiry_time, closeCB, errback, results = results, error = error)
        messages_history.append(m)

    def closeCB(close_message, **kwargs):
        if kwargs['results'] is not None:
            callback(kwargs['results'])
        elif kwargs['error'] is not None:
            errback(OperationFailure('Failed to list %s on %s: Query failed with errorcode 0x%08x' % ( path, service_name, kwargs['error'] ), messages_history))

    if not conn.connected_trees.has_key(service_name):
        def connectCB(connect_message, **kwargs):
            messages_history.append(connect_message)
            if connect_message.status == 0:
                conn.connected_trees[service_name] = connect_message.tid
                sendCreate(connect_message.tid)
            else:
                errback(OperationFailure('Failed to list %s on %s: Unable to connect to shared device' % ( path, service_name ), messages_history))

        m = SMB2Message(SMB2TreeConnectRequest(r'\\%s\%s' % ( conn.remote_name.upper(), service_name )))
        conn._sendSMBMessage(m)
        conn.pending_requests[m.mid] = _PendingRequest(m.mid, expiry_time, connectCB, errback, path = service_name)
        messages_history.append(m)
    else:
        sendCreate(conn.connected_trees[service_name])


def _listPath_SMB1(
        self, service_name, path, callback, errback, search,
        pattern, timeout = 30, limit=0
    ):
    if not self.has_authenticated:
        raise NotReadyError('SMB connection not authenticated')

    expiry_time = time.time() + timeout
    path = path.replace('/', '\\')
    if not path.endswith('\\'):
        path += '\\'
    messages_history = [ ]
    results = [ ]

    def sendFindFirst(tid):
        setup_bytes = struct.pack('<H', 0x0001)  # TRANS2_FIND_FIRST2 sub-command. See [MS-CIFS]: 2.2.6.2.1
        params_bytes = \
            struct.pack('<HHHHI',
                        search, # SearchAttributes
                        100,    # SearchCount
                        0x0006, # Flags: SMB_FIND_CLOSE_AT_EOS | SMB_FIND_RETURN_RESUME_KEYS
                        0x0104, # InfoLevel: SMB_FIND_FILE_BOTH_DIRECTORY_INFO
                        0x0000) # SearchStorageType
        params_bytes += (path + pattern).encode('UTF-16LE')

        m = SMBMessage(ComTransaction2Request(max_params_count = 10,
                                              max_data_count = 16644,
                                              max_setup_count = 0,
                                              params_bytes = params_bytes,
                                              setup_bytes = setup_bytes))
        m.tid = tid
        self._sendSMBMessage(m)
        self.pending_requests[m.mid] = _PendingRequest(m.mid, expiry_time, findFirstCB, errback)
        messages_history.append(m)

    def decodeFindStruct(data_bytes):
        # SMB_FIND_FILE_BOTH_DIRECTORY_INFO structure. See [MS-CIFS]: 2.2.8.1.7 and [MS-SMB]: 2.2.8.1.1
        info_format = '<IIQQQQQQIIIBB24s'
        info_size = struct.calcsize(info_format)

        data_length = len(data_bytes)
        offset = 0
        while offset < data_length:
            if offset + info_size > data_length:
                return data_bytes[offset:]

            next_offset, _, \
            create_time, last_access_time, last_write_time, last_attr_change_time, \
            file_size, alloc_size, file_attributes, filename_length, ea_size, \
            short_name_length, _, short_name = struct.unpack(info_format, data_bytes[offset:offset+info_size])

            offset2 = offset + info_size
            if offset2 + filename_length > data_length:
                return data_bytes[offset:]

            filename = data_bytes[offset2:offset2+filename_length].decode('UTF-16LE')
            short_name = short_name.decode('UTF-16LE')
            shared_file = SharedFile(convertFILETIMEtoEpoch(create_time), convertFILETIMEtoEpoch(last_access_time),
                                      convertFILETIMEtoEpoch(last_write_time), convertFILETIMEtoEpoch(last_attr_change_time),
                                      file_size, alloc_size, file_attributes, short_name, filename)
            results.append(shared_file)
            if limit > 0 and len(results) >= limit:
                return False
            if next_offset:
                offset += next_offset
            else:
                break
        return ''

    def findFirstCB(find_message, **kwargs):
        messages_history.append(find_message)
        if not find_message.status.hasError:
            if not kwargs.has_key('total_count'):
                # TRANS2_FIND_FIRST2 response. [MS-CIFS]: 2.2.6.2.2
                sid, search_count, end_of_search, _, last_name_offset = struct.unpack('<HHHHH', find_message.payload.params_bytes[:10])
                kwargs.update({ 'sid': sid, 'end_of_search': end_of_search, 'last_name_offset': last_name_offset, 'data_buf': '' })
            else:
                sid, end_of_search, last_name_offset = kwargs['sid'], kwargs['end_of_search'], kwargs['last_name_offset']

            send_next = True
            if find_message.payload.data_bytes:
                d = decodeFindStruct(kwargs['data_buf'] + find_message.payload.data_bytes)
                if d is False:
                    send_next = True
                    end_of_search = True
                elif not kwargs.has_key('data_count'):
                    if len(find_message.payload.data_bytes) != find_message.payload.total_data_count:
                        kwargs.update({ 'data_count': len(find_message.payload.data_bytes),
                                        'total_count': find_message.payload.total_data_count,
                                        'data_buf': d,
                                        })
                        send_next = False
                else:
                    kwargs['data_count'] += len(find_message.payload.data_bytes)
                    kwargs['total_count'] = min(find_message.payload.total_data_count, kwargs['total_count'])
                    kwargs['data_buf'] = d
                    if kwargs['data_count'] != kwargs['total_count']:
                        send_next = False

            if not send_next:
                self.pending_requests[find_message.mid] = _PendingRequest(find_message.mid, expiry_time, findFirstCB, errback, **kwargs)
            elif end_of_search:
                callback(results)
            else:
                sendFindNext(find_message.tid, sid, last_name_offset)
        else:
            errback(OperationFailure('Failed to list %s on %s: Unable to retrieve file list' % ( path, service_name ), messages_history))

    def sendFindNext(tid, sid, resume_key):
        setup_bytes = struct.pack('<H', 0x0002)  # TRANS2_FIND_NEXT2 sub-command. See [MS-CIFS]: 2.2.6.3.1
        params_bytes = \
            struct.pack('<HHHIH',
                        sid,        # SID
                        100,        # SearchCount
                        0x0104,     # InfoLevel: SMB_FIND_FILE_BOTH_DIRECTORY_INFO
                        resume_key, # ResumeKey
                        0x000a)     # Flags: SMB_FIND_RETURN_RESUME_KEYS | SMB_FIND_CLOSE_AT_EOS | SMB_FIND_RETURN_RESUME_KEYS
        params_bytes += pattern.encode('UTF-16LE')

        m = SMBMessage(ComTransaction2Request(max_params_count = 10,
                                              max_data_count = 16644,
                                              max_setup_count = 0,
                                              params_bytes = params_bytes,
                                              setup_bytes = setup_bytes))
        m.tid = tid
        self._sendSMBMessage(m)
        self.pending_requests[m.mid] = _PendingRequest(m.mid, expiry_time, findNextCB, errback, sid = sid)
        messages_history.append(m)

    def findNextCB(find_message, **kwargs):
        messages_history.append(find_message)
        if not find_message.status.hasError:
            if not kwargs.has_key('total_count'):
                # TRANS2_FIND_NEXT2 response. [MS-CIFS]: 2.2.6.3.2
                search_count, end_of_search, _, last_name_offset = struct.unpack('<HHHH', find_message.payload.params_bytes[:8])
                kwargs.update({ 'end_of_search': end_of_search, 'last_name_offset': last_name_offset, 'data_buf': '' })
            else:
                end_of_search, last_name_offset = kwargs['end_of_search'], kwargs['last_name_offset']

            send_next = True
            if find_message.payload.data_bytes:
                d = decodeFindStruct(kwargs['data_buf'] + find_message.payload.data_bytes)
                if d is False:
                    send_next = True
                    end_of_search = True
                elif not kwargs.has_key('data_count'):
                    if len(find_message.payload.data_bytes) != find_message.payload.total_data_count:
                        kwargs.update({ 'data_count': len(find_message.payload.data_bytes),
                                        'total_count': find_message.payload.total_data_count,
                                        'data_buf': d,
                                        })
                        send_next = False
                else:
                    kwargs['data_count'] += len(find_message.payload.data_bytes)
                    kwargs['total_count'] = min(find_message.payload.total_data_count, kwargs['total_count'])
                    kwargs['data_buf'] = d
                    if kwargs['data_count'] != kwargs['total_count']:
                        send_next = False

            if not send_next:
                self.pending_requests[find_message.mid] = _PendingRequest(find_message.mid, expiry_time, findNextCB, errback, **kwargs)
            elif end_of_search:
                callback(results)
            else:
                sendFindNext(find_message.tid, kwargs['sid'], last_name_offset)
        else:
            errback(OperationFailure('Failed to list %s on %s: Unable to retrieve file list' % ( path, service_name ), messages_history))

    if not self.connected_trees.has_key(service_name):
        def connectCB(connect_message, **kwargs):
            messages_history.append(connect_message)
            if not connect_message.status.hasError:
                self.connected_trees[service_name] = connect_message.tid
                sendFindFirst(connect_message.tid)
            else:
                errback(OperationFailure('Failed to list %s on %s: Unable to connect to shared device' % ( path, service_name ), messages_history))

        m = SMBMessage(ComTreeConnectAndxRequest(r'\\%s\%s' % ( self.remote_name.upper(), service_name ), SERVICE_ANY, ''))
        self._sendSMBMessage(m)
        self.pending_requests[m.mid] = _PendingRequest(m.mid, expiry_time, connectCB, errback, path = service_name)
        messages_history.append(m)
    else:
        sendFindFirst(self.connected_trees[service_name])


def storeFileFromOffset(conn, service_name, path, file_obj, offset = 0L, timeout = 30, overwrite=False):
    """
    Store the contents of the *file_obj* at *path* on the *service_name*.
    :param string/unicode service_name: the name of the shared folder for the *path*
    :param string/unicode path: Path of the file on the remote server. If the file at *path* does not exist, it will be created. Otherwise, it will be overwritten.
                                If the *path* refers to a folder or the file cannot be opened for writing, an :doc:`OperationFailure<smb_exceptions>` will be raised.
    :param file_obj: A file-like object that has a *read* method. Data will read continuously from *file_obj* until EOF.
    :return: Number of bytes uploaded
    """
    if not conn.sock:
        raise NotConnectedError('Not connected to server')

    results = [ ]

    def cb(r):
        conn.is_busy = False
        results.append(r[1])

    def eb(failure):
        conn.is_busy = False
        raise failure

    conn.is_busy = True
    try:
        _storeFileFromOffset_SMB2(conn, service_name, path, file_obj, cb, eb, offset, timeout = timeout, overwrite = overwrite)
        while conn.is_busy:
            conn._pollForNetBIOSPacket(timeout * 1000)
    finally:
        conn.is_busy = False

    return results[0]

def _storeFileFromOffset_SMB2(conn, service_name, path, file_obj, callback, errback, starting_offset, timeout = 30, overwrite = False):
    if not conn.has_authenticated:
        raise NotReadyError('SMB connection not authenticated')

    path = path.replace('/', '\\')
    if path.startswith('\\'):
        path = path[1:]
    if path.endswith('\\'):
        path = path[:-1]
    messages_history = [ ]

    def sendCreate(tid):
        if overwrite:
            OVERWRITE = FILE_OVERWRITE_IF
        else:
            OVERWRITE = FILE_OPEN_IF
        create_context_data = binascii.unhexlify(
            "28 00 00 00 10 00 04 00 00 00 18 00 10 00 00 00"
            "44 48 6e 51 00 00 00 00 00 00 00 00 00 00 00 00"
            "00 00 00 00 00 00 00 00 20 00 00 00 10 00 04 00"
            "00 00 18 00 08 00 00 00 41 6c 53 69 00 00 00 00"
            "85 62 00 00 00 00 00 00 18 00 00 00 10 00 04 00"
            "00 00 18 00 00 00 00 00 4d 78 41 63 00 00 00 00"
            "00 00 00 00 10 00 04 00 00 00 18 00 00 00 00 00"
            "51 46 69 64 00 00 00 00".replace(' ', '').replace('\n', '')
        )
        m = SMB2Message(SMB2CreateRequest(path,
                                          file_attributes = ATTR_ARCHIVE,
                                          access_mask = FILE_READ_DATA | FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES | FILE_READ_EA | FILE_WRITE_EA | WRITE_DAC | READ_CONTROL | SYNCHRONIZE,
                                          share_access = 0,
                                          oplock = SMB2_OPLOCK_LEVEL_NONE,
                                          impersonation = SEC_IMPERSONATE,
                                          create_options = FILE_SEQUENTIAL_ONLY | FILE_NON_DIRECTORY_FILE,
                                          create_disp = OVERWRITE,
                                          create_context_data = create_context_data))
        m.tid = tid
        conn._sendSMBMessage(m)
        conn.pending_requests[m.mid] = _PendingRequest(m.mid, int(time.time()) + timeout, createCB, errback, tid = tid)
        messages_history.append(m)

    def createCB(create_message, **kwargs):
        messages_history.append(create_message)
        if create_message.status == 0:
            sendWrite(create_message.tid, create_message.payload.fid, starting_offset)
        else:
            errback(OperationFailure('Failed to store %s on %s: Unable to open file' % ( path, service_name ), messages_history))

    def sendWrite(tid, fid, offset):
        write_count = conn.max_write_size
        data = file_obj.read(write_count)
        data_len = len(data)
        if data_len > 0:
            m = SMB2Message(SMB2WriteRequest(fid, data, offset))
            m.tid = tid
            conn._sendSMBMessage(m)
            conn.pending_requests[m.mid] = _PendingRequest(m.mid, int(time.time()) + timeout, writeCB, errback, fid = fid, offset = offset+data_len)
        else:
            closeFid(tid, fid, offset = offset)

    def writeCB(write_message, **kwargs):
        # To avoid crazy memory usage when saving large files, we do not save every write_message in messages_history.
        if write_message.status == 0:
            sendWrite(write_message.tid, kwargs['fid'], kwargs['offset'])
        else:
            messages_history.append(write_message)
            closeFid(write_message.tid, kwargs['fid'])
            errback(OperationFailure('Failed to store %s on %s: Write failed' % ( path, service_name ), messages_history))

    def closeFid(tid, fid, error = None, offset = None):
        m = SMB2Message(SMB2CloseRequest(fid))
        m.tid = tid
        conn._sendSMBMessage(m)
        conn.pending_requests[m.mid] = _PendingRequest(m.mid, int(time.time()) + timeout, closeCB, errback, fid = fid, offset = offset, error = error)
        messages_history.append(m)

    def closeCB(close_message, **kwargs):
        if kwargs['offset'] is not None:
            callback(( file_obj, kwargs['offset'] ))  # Note that this is a tuple of 2-elements
        elif kwargs['error'] is not None:
            errback(OperationFailure('Failed to store %s on %s: Write failed' % ( path, service_name ), messages_history))

    if not conn.connected_trees.has_key(service_name):
        def connectCB(connect_message, **kwargs):
            messages_history.append(connect_message)
            if connect_message.status == 0:
                conn.connected_trees[service_name] = connect_message.tid
                sendCreate(connect_message.tid)
            else:
                errback(OperationFailure('Failed to store %s on %s: Unable to connect to shared device' % ( path, service_name ), messages_history))

        m = SMB2Message(SMB2TreeConnectRequest(r'\\%s\%s' % ( conn.remote_name.upper(), service_name )))
        conn._sendSMBMessage(m)
        conn.pending_requests[m.mid] = _PendingRequest(m.mid, int(time.time()) + timeout, connectCB, errback, path = service_name)
        messages_history.append(m)
    else:
        sendCreate(conn.connected_trees[service_name])

