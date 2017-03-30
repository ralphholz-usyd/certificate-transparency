import time
import pgdb
import gflags
import logging

from ct.client.db import cert_db
from ct.client.db import cert_desc

FLAGS = gflags.FLAGS

_MAX_RETRY = 10

class pgSQLCertDB(cert_db.CertDB):
    def __init__(self, connection_manager):
        """Initialize the database and tables.
        Args:
            connection: an pgSQLConnectionManager object."""
        self.__mgr = connection_manager
        cert_repeated_field_tables = [
            ("issuer", [("type", "TEXT"), ("name", "TEXT"),]),
            ("subject", [("type", "TEXT"), ("name", "TEXT"),]),
            ("subject_alternative_names", [("type", "TEXT"),
                                           ("name", "TEXT"),]),
            # subject common names and dnsnames for easy lookup of given
            # domain name
            ("subject_names", [("name", "TEXT")]),
            ("root_issuer", [("type", "TEXT"), ("name", "TEXT")])]
        cert_single_field_tables = [("version", "INTEGER"),
                                    ("serial_number", "TEXT")]
        with self.__mgr.get_connection() as conn:
            # the |cert| data is also unique but we don't force this as it would
            # create a superfluous index.
            conn.execute("CREATE TABLE IF NOT EXISTS certs("
                         "sha256_hash BYTEA UNIQUE,"
                         "cert BYTEA," +
                         ', '.join(['%s %s' % (column, type_) for column, type_
                                    in cert_single_field_tables]) +
                         ", PRIMARY KEY(sha256_hash))")

            conn.execute("CREATE TABLE IF NOT EXISTS log_certs("
                         "log INTEGER,"
                         "log_index INTEGER,"
                         "sha256_hash BYTEA,"
                         "PRIMARY KEY (log, log_index, sha256_hash))")

            for entry in cert_repeated_field_tables:
                self.__create_table_for_field(conn, *entry)
            try:
                conn.execute("CREATE INDEX log_certs_idx "
                             "on log_certs(log, log_index)  TABLESPACE ctscan_indexes")

                conn.execute("CREATE INDEX certs_by_subject "
                             "on subject_names(name) TABLESPACE ctscan_indexes")
            except pgdb.ProgrammingError as e:
                if "already exists" not in str(e):
                    raise e

        self.__tables = (["logs", "certs"] +
                         [column for column, _ in cert_repeated_field_tables])

    @staticmethod
    def __create_table_for_field(cursor, table_name, fields):
        """Helper method that creates table for given certificate field. Each
        row in that table refers to some certificate in certs table.
        Args:
            table_name:   name of the table
            fields:       iterable of (column_name, type) tuples"""
        cursor.execute("CREATE TABLE IF NOT EXISTS {table_name}("
                     "cert_sha256_hash BYTEA,"
                     "{fields},"
                     "FOREIGN KEY(cert_sha256_hash) REFERENCES certs(sha256_hash))"
                     .format(table_name=table_name,
                             fields=','.join(
                                     ["%s %s" % field for field in fields])))

    def __repr__(self):
        return "%r(db: %r)" % (self.__class__.__name__, self.__db)

    def __str__(self):
        return "%s(db: %s, tables: %s): " % (self.__class__.__name__, self.__db,
                                             self.__tables)


    @staticmethod
    def __compare_processed_names(prefix, name):
        return prefix == name[:len(prefix)]

    def __store_log_cert(self, cert, index, log_key, cursor):
        try:
            # Need None type for empty strings inserted into INTEGER field
            cert_version = None if cert.version == '' else cert.version

            # insert relationship between this cert and the (log_id, index)
            cursor.execute("INSERT INTO log_certs(log, log_index, sha256_hash) "
                           "VALUES(%s, %s, %s) ON CONFLICT DO NOTHING",
                            (log_key, index,
                             pgdb.Binary(cert.sha256_hash),))

        except pgdb.DatabaseError as err:
            logging.error('pgdb store_log_cert: %s' % err)
            raise err

    def __store_cert(self, cert, index, log_key, cursor):
        try:
            # Need None type for empty strings inserted into INTEGER field
            cert_version = None if cert.version == '' else cert.version

            # conditionally insert if the cert does not exist already
            cursor.execute("INSERT INTO certs(sha256_hash, cert, "
                           "version, serial_number) VALUES(%s, %s, %s, %s) "
                           "WHERE NOT EXISTS (
                               SELECT 1
                                 FROM certs
                                WHERE sha256_hash = %s) ",
                           (pgdb.Binary(cert.sha256_hash),
                            pgdb.Binary(cert.der),
                            cert_version,
                            cert.serial_number,
                            pgdb.Binary(cert.sha256_hash),)

            # if the cert already existed, just stop here
            if cursor.rowcount < 1:
                return

        except pgdb.DatabaseError as err:
            # cert already exists or something went horribly wrong
            # either way, stop right here
            logging.error('pgdb store_log_cert: %s' % err)
            raise err

        for sub in cert.subject:
            cursor.execute("INSERT INTO subject(cert_sha256_hash, type, name)"
                           "VALUES(%s, %s, %s)",
                           (pgdb.Binary(cert.sha256_hash), sub.type, sub.value))
            if sub.type == "CN":
                cursor.execute("INSERT INTO subject_names(cert_sha256_hash, name)"
                               "VALUES(%s, %s)",
                               (pgdb.Binary(cert.sha256_hash), sub.value))

        for alt in cert.subject_alternative_names:
            cursor.execute("INSERT INTO subject_alternative_names(cert_sha256_hash,"
                           "type, name) VALUES(%s, %s, %s)",
                           (pgdb.Binary(cert.sha256_hash), alt.type, alt.value))
            if alt.type == "dNSName":
                cursor.execute("INSERT INTO subject_names(cert_sha256_hash, name)"
                               "VALUES(%s, %s)",
                               (pgdb.Binary(cert.sha256_hash), alt.value))

        for iss in cert.issuer:
            cursor.execute("INSERT INTO issuer(cert_sha256_hash, type, name)"
                           "VALUES(%s, %s, %s)",
                           (pgdb.Binary(cert.sha256_hash), iss.type, iss.value))

        for iss in cert.root_issuer:
            cursor.execute("INSERT INTO root_issuer(cert_sha256_hash, type, name)"
                           "VALUES(%s, %s, %s)",
                           (pgdb.Binary(cert.sha256_hash), iss.type, iss.value))

    def __cert_hash_exists(self, cert_sha256_hash, cursor):
        return (len(cursor.execute("SELECT 1 FROM certs "
                                   "WHERE sha256_hash = %s LIMIT 1",
                    (pgdb.Binary(cert_sha256_hash),)).fetchall()) == 1)

    def store_certs_desc(self, certs, log_key):
        """Store certificates using their descriptions.

        Args:
            certs:         iterable of (CertificateDescription, index) tuples
            log_key:       log id in LogDB"""

        logging.info("pgdb store_certs_desc: storing %s certs" % len(certs))
        _delta = time.time()
        certs.sort(key=lambda t: t[0][0].sha256_hash)
        _delta = time.time() - _delta
        logging.info("pgdb store_certs_desc: sorted %s certs in %s seconds"
                     % (len(certs), _delta))

        with self.__mgr.get_connection() as conn:
            for i in range(_MAX_RETRY):
                try:
                    cursor = conn.cursor()
                    for cert in certs:
                        self.__store_log_cert(cert[0], cert[1], log_key, cursor)
                        self.__store_cert(cert[0], cert[1], log_key, cursor)
                    conn.commit()
                    return

                except pgdb.DatabaseError as err:
                    conn.rollback()

                    if i+1 < _MAX_RETRY:
                        logging.error("pgdb store_certs_desc: error encountered, "
                                      "ROLLBACK and retry (%s/%s)" % (i+2, _MAX_RETRY))
                    else:
                        logging.exception("pgdb store_certs_desc: error encountered,
                          could not store cert batch after %s attempts" % (_MAX_RETRY))
                        raise err

    def store_cert_desc(self, cert, index, log_key):
        """Store a certificate using its description.

        Args:
            cert:          CertificateDescription
            index:         position in log
            log_key:       log id in LogDB"""
        self.store_certs_desc([(cert, index)], log_key)

    def get_cert_by_sha256_hash(self, cert_sha256_hash):
        """Fetch a certificate with a matching SHA256 hash
        Args:

            cert_sha256_hash: the SHA256 hash of the certificate
        Returns:
            A DER-encoded certificate, or None if the cert is not found."""
        with self.__mgr.get_connection() as conn:
            res = conn.execute("SELECT cert FROM certs WHERE sha256_hash = %s",
                               (pgdb.Binary(cert_sha256_hash),))
            try:
                return str(res.next()["cert"])
            except StopIteration:
                pass

    def scan_certs(self, limit=0):
        """Scan all certificates.
        Args:
            limit: maximum number of entries to yield. Default is no limit.
        Yields:
            DER-encoded certificates."""
        query = "SELECT cert FROM certs"
        query_params = tuple()

        if limit > 0:
            query += " LIMIT %i"
            query_params = (limit,)

        with self.__mgr.get_connection() as conn:
            for row in conn.execute(query, query_params):
                yield str(row["cert"])

    # RFC 2818 (HTTP over TLS) states that "names may contain the wildcard
    # character * which is considered to match any single domain name
    # component or component fragment."
    #
    # So theoretically a cert for www.*.com or www.e*.com is valid for
    # www.example.com (although common browsers reject overly broad certs).
    # This makes wildcard matching in index scans difficult.
    #
    # The subject index scan thus does not match wildcards: it is not intended
    # for fetching all certificates that may be deemed valid for a given domain.
    # Applications should define their own rules for detecting wildcard certs
    # and anything else of interest.
    def scan_certs_by_subject(self, subject_name, limit=0):
        """Scan certificates matching a subject name.
        Args:
            subject_name: a subject name, usually a domain. A scan for
                          example.com returns certificates for www.example.com,
                          *.example.com, test.mail.example.com, etc. Similarly
                          'com' can be used to look for all .com certificates.
                          Wildcards are treated as literal characters: a search
                          for *.example.com returns certificates for
                          *.example.com but not for mail.example.com and vice
                          versa.
                          Name may also be a common name rather than a DNS name,
                          e.g., "Trustworthy Certificate Authority".
            limit:        maximum number of entries to yield. Default is no
                          limit.
        Yields:
            DER-encoded certificates."""
        prefix = cert_desc.process_name(subject_name)
        query = """
                SELECT certs.cert as cert, subject_names.name as name
                  FROM certs, subject_names
                 WHERE name >= %s AND certs.sha256_hash = subject_names.cert_sha256_hash
                 ORDER BY name ASC
                """
        query_params = (".".join(prefix),)

        if limit > 0:
            query += " LIMIT %i"
            query_params = (".".join(prefix), limit,)

        with self.__mgr.get_connection() as conn:
            for row in conn.execute(query, query_params):
                name = cert_desc.process_name(row["name"], reverse=False)
                if self.__compare_processed_names(prefix, name):
                    yield str(row["cert"])
                else:
                    break
