import pgdb
import traceback

from ct.client.db import database

class pgSQLConnection(object):
    """A thin wrapper around PyGreSQL Connection for automatically closing the
    connection."""
    def __init__(self, db, host, user, password, keepalive=False):
        """Create a new connection object.
        Args:
            db:        database name"
            host:      hostname or IP address of the PostgreSQL server
            user:      username to use for server authentication
            password:  password to use for server authentication
            keepalive: If True, don't close upon __exit__'ing.
        Usage:
            with pgSQLConnection(db_name, db_host, db_user, db_passwd) as conn:
                # conn.execute(...)
                # ...
        """
        self.__keepalive = keepalive
        try:
            self.__conn = pgdb.connect(database=db, host=host, user=user,
                    password=password)
            self.__conn.cursor_type = DictCursor
        except pgdb.OperationalError as e:
            raise database.OperationalError(e)

    def __repr__(self):
        return "%r(%r, %r, %r, keepalive=%r)" % (self.__class__.__name__,
                                                 self.__db,
                                                 self.__host,
                                                 self.__user,
                                                 self.__password,
                                                 self.__keepalive)

    def __str__(self):
        return "%s(%s, %s, %s, keepalive=%s)" % (self.__class__.__name__,
                                                 self.__db,
                                                 self.__host,
                                                 self.__user,
                                                 self.__password,
                                                 self.__keepalive)

    def __enter__(self):
        """Return the underlying raw pgdb Connection object."""
        #self.__conn.__enter__()
        return self.__conn

    def __exit__(self, exc_type, exc_value, traceback):
        """Commit or rollback, and close the connection."""
        ret = self.__conn.__exit__(exc_type, exc_value, traceback)
        if not self.__keepalive:
            self.__conn.close()
        return ret

# Currently a very stupid manager that doesn't limit the number of connections -
# connections are simply closed and reopened every time. This could be refined
# by having the manager maintain a connection pool.
class pgSQLConnectionManager(object):
    def __init__(self, db, host, user, password, keepalive=False):
        """Connection manager for a SQLite database.
        Args:
            db:        database name"
            host:      hostname or IP address of the PostgreSQL server
            user:      username to use for server authentication
            password:  password to use for server authentication
            keepalive: If True, maintains a single open connection.
                       If False, returns a new connection to be created for each
                       call. keepalive=True is not thread-safe.
        """
        self.__db = db
        self.__host = host
        self.__user = user
        self.__password = password
        self.__keepalive = keepalive
        self.__conn = None
        if keepalive:
            self.__conn = pgSQLConnection(self.__db, self.__host, self.__user,
                                          self.__password, keepalive=True)

    def __repr__(self):
        return "%r(%r, keepalive=%r)" % (self.__class__.__name__, self.__db,
                                         self.__keepalive)

    def __str__(self):
        return "%s(db: %s, keepalive: %s): " % (self.__class__.__name__,
                                                self.__db, self.__keepalive)

    @property
    def db_name(self):
        return self.__db

    def get_connection(self):
        """In keepalive mode, return the single persistent connection.
        Else return a new connection instance."""
        if self.__keepalive:
            return self.__conn
        else:
            return pgSQLConnection(self.__db, self.__host, self.__user,
                                   self.__password, keepalive=False)

class DictCursor(pgdb.Cursor):
    def row_factory(self, row):
        return {key: value for key, value in zip(self.colnames, row)}
