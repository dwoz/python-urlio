"""
Global session object. Sqlalchemy recommends creating one single session.

Usage:

    from mymodel import User
    from traxcommon.sql_session import Session, connect_session

    engine = connect_session('mysql+mysqldb://richard:stallman@localhost/mysickapp')
    Session.query(User).first()
"""
import os
import logging
import sqlalchemy
import sqlalchemy.orm

log = logging.getLogger(__name__)

class SessionScope(object):
    """
    Sqlalchemy's scoped_session, and engine obects do not handle
    multiprocessing well. This class enforces having a new scoped_session and
    engine for each process in an application. A side effect is the connect_session
    must be called after each os.fork and/or after a subprocess of multiprocessing
    is started.
    """

    def __init__(self, PROCESSES=None):
        self.PROCESSES = PROCESSES or {}

    def _get_session(self):
        pid = os.getpid()
        if pid not in self.PROCESSES:
            self.PROCESSES[pid] = sqlalchemy.orm.scoped_session(sqlalchemy.orm.sessionmaker())
        return self.PROCESSES[pid]

    def __call__(self, *args, **kwargs):
        return self._get_session()(*args, **kwargs)

    def configure(self, *args, **kwargs):
        return self._get_session().configure(*args, **kwargs)

    def connect_session(self, url, autocommit=False, **opts):
        """
        Create a new database engine and bind it to the global session object,
        returning the engine when done.
        """
        Session = self._get_session()
        engine = sqlalchemy.create_engine(url, **opts)
        Session.remove()
        Session.configure(bind=engine, autocommit=autocommit)
        sqlalchemy.orm.configure_mappers()
        return engine

Session = SessionScope()
connect_session = Session.connect_session

def echo_sql(echo=False):
    Session().bind.engine = echo
