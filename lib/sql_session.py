"""
Global session object. Sqlalchemy recommends creating one single session.

Usage:

    from mymodel import User
    from traxcommon.sql_session import Session, connect_session

    connect_session('mysql+mysqldb://richard:stallman@localhost/mysickapp')
    Session.query(User).first()
"""
import sqlalchemy
import sqlalchemy.orm
Session = sqlalchemy.orm.scoped_session(sqlalchemy.orm.sessionmaker())
def echo_sql(echo=False):
    Session().bind.engine = echo

def connect_session(url, **opts):
    """
    Create a new database engine and bind it to the global session object,
    returning the engine when done
    """
    if hasattr(connect_session, 'last_url'):
        if url != connect_session.last_url:
            log.warn('Connecting session to another db: old=%s new=%s', connect.last_url, url)
    engine = sqlalchemy.create_engine(url, **opts)
    Session.configure(bind=engine, autocommit=True)
    connect_session.last_url = url
    sqlalchemy.orm.configure_mappers()
