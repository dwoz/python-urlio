from __future__ import unicode_literals, print_function, absolute_import
import io
import os

class BasicIO(io.IOBase):
    """
    Base class for out implimentations of io streams
    """
    #close
    #closed
    #fileno
    #flush
    #isatty
    #readable
    #readline
    #readlines
    #seekable
    #tell
    #writable
    #writelines
    def seek(self, index):
        raise NotImplementedError()

    def tell(self):
        raise NotImplementedError()

    def read(self, size=-1):
        raise NotImplementedError()

    def write(self, data):
        raise NotImplementedError()

    def exists(self):
        raise NotImplementedError()

    def size(self):
        raise NotImplementedError()

    def ctime(self):
        raise NotImplementedError()

    def mtime(self):
        raise NotImplementedError()

    def atime(self):
        raise NotImplementedError()

    def stat(self):
        raise NotImplementedError()

    def ls(self, glb='*', limit=0):
        raise NotImplementedError()

    def close(self):
        raise NotImplementedError()

    def makedirs(self, is_dir=False, exist_ok=False):
        raise NotImplementedError()

    def remove(self):
        raise NotImplementedError()

    def rmtree(self):
        raise NotImplementedError()

    def rename(self, newname):
        raise NotImplementedError()

    def walk(self, top_down=False):
        raise NotImplementedError()

    def join(self, *joins, **kwargs):
        raise NotImplementedError()
