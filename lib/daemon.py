import atexit
import ctypes
import errno
import logging
import os
import resource
import signal
import sys
import time
import traceback

log = logging.getLogger(__name__)
NULL = os.devnull

def writepid(path, pid=None):
    if not pid:
        pid = os.getpid()
    open_flags = (os.O_CREAT | os.O_EXCL | os.O_WRONLY)
    open_mode = 0o644
    pidfile = None
    try:
        pidfile_fd = os.open(path, open_flags, open_mode)
        pidfile = os.fdopen(pidfile_fd, 'w')
        pidfile.write("{0}".format(str(pid)))
        pidfile.close()
    except Exception as e:
        if pidfile:
            pidfile.close()
        #reraise(e)
        raise


def removepid(path):
    try:
        os.remove(path)
    except OSError as exc:
        if exc.errno == errno.ENOENT:
            pass
        else:
            raise


def daemonize(
        stderr=NULL, stdout=NULL, stdin=NULL, uid=None, gid=None,
        at_exit=None, reload=None
    ):
    # Prevent core dumps
    core_limit_ref = resource.getrlimit(resource.RLIMIT_CORE)
    core_limit = (0, 0)
    resource.setrlimit(resource.RLIMIT_CORE, core_limit)

    os.umask(0)
    os.chdir("/")
    if gid:
        os.setgid(gid)
    if uid:
        os.setuid(uid)

    # redirect standard file descriptors
    si = file(stdin, 'r')
    os.dup2(si.fileno(), sys.stdin.fileno())
    so = file(stdout, 'a+')
    os.dup2(so.fileno(), sys.stdout.fileno())
    se = file(stderr, 'a+', 0)
    os.dup2(se.fileno(), sys.stderr.fileno())

    #XXX Causes JoinableQueue to fail with bad file descriptor
    # Close all open file descriptors
    maxfd = resource.getrlimit(resource.RLIMIT_NOFILE)[1]
    if (maxfd == resource.RLIM_INFINITY):
        maxfd = 1024
    for fd in range(0, maxfd):
        try:
            os.close(fd)
        except OSError:
            pass

    pid = os.fork()
    if pid > 0:
        os._exit(0)
    os.setsid()
    pid = os.fork()
    if pid > 0:
        os._exit(0)

    name = os.path.basename(sys.argv[0])
    try:
        buff = ctypes.create_string_buffer(len(name) + 1)
        buff.value = name
        ctypes.cdll.LoadLibrary('libc.so.6').prctl(
            15, ctypes.byref(buff), 0, 0, 0
        )
    except Exception as e:
        log.error("Set procname fail %s", e)
        pass

    if at_exit:
        signal.signal(signal.SIGTERM, at_exit)
        atexit.register(at_exit)
    else:
        log.warn("No atexit handler")
    if reload:
        signal.signal(signal.SIGHUP, reload)
    return os.getpid()


def start_daemon(
        daemon, args=(), opts={}, pidfile='', daemonize=daemonize, stderr=NULL,
        stdout=NULL, stdin=NULL, uid=None, gid=None, at_exit=None, reload=None,
        writepid=writepid
    ):
    if not pidfile:
        path, cmd = os.path.split(sys.argv[0])
        pidfile = '/tmp/{0}.pid'.format(cmd.replace(' ', '_'))
    try:
        with file(pidfile, 'r') as pf:
            a = pf.read().strip()
            if a:
                pid = int(a)
            else:
                pid = None
    except IOError:
        pid = None
    if pid:
        message = "Pid file %s already exist. Daemon already running?\n"
        log.error(message, pidfile)
        sys.stderr.write(message % (pidfile))
        sys.exit(1)
    log.info("Daemonize")
    pid = daemonize(at_exit=at_exit, reload=reload)
    try:
        writepid(pidfile, pid)
    except Exception as e:
        log.error(
            "Unable to write pidfile: %s %s", pidfile, traceback.format_exc(10)
        )
        sys.exit(1)
    args = args or ()
    opts = opts or {}
    nExit = None
    try:
        log.info("Run daemon")
        daemon(*args, **opts)
    except SystemExit as exc:
        nExit = exc.code
    except Exception as e:
        log.error(
            "Unhandled exception. {0} {1}".format(e, traceback.format_exc(10))
        )
        nExit = 3
    if nExit:
        sys.exit(nExit)


def stop_daemon(pidfile, removepid=removepid):
    try:
        with file(pidfile, 'r') as pf:
            pid = int(pf.read().strip())
    except IOError:
        pid = None
    if not pid:
        message = "Pid file unreadable: {0}\n"
        sys.stderr.write(message.format(pidfile))
        sys.exit(1)
    try:
        n = 0
        while n < 1500:
            os.kill(pid, signal.SIGTERM)
            time.sleep(1)
            n += 1
    except OSError, err:
        err = str(err)
        if err.find("No such process") > 0:
            if os.path.exists(pidfile):
                removepid(pidfile)
        else:
            sys.stderr.write("{0}\n".format(str(err)))
            sys.exit(1)


def restart_daemon(daemon, pidfile, starter=start_daemon, stopper=stop_daemon):
    stopper(pidfile)
    starter(daemon, pidfile)
