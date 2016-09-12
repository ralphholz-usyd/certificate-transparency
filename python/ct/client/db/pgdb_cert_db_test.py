#!/usr/bin/env python

import unittest

import sys
from ct.client.db import pgdb_connection as pgdbcon
from ct.client.db import pgdb_cert_db
from ct.client.db import cert_db_test
import gflags

from ct.client.db.pgsql_test_config import TEST_CONN_PARAMS

class pgSQLCertDBTest(unittest.TestCase, cert_db_test.CertDBTest):
    def setUp(self):
        self.__conn_manager = pgdbcon.pgSQLConnectionManager(*TEST_CONN_PARAMS, keepalive=True)
        with self.__conn_manager.get_connection() as conn:
            conn.execute("SET client_min_messages TO WARNING")
            conn.execute("DROP SCHEMA IF EXISTS ct_cert_db_test CASCADE")
            conn.execute("CREATE SCHEMA IF NOT EXISTS ct_cert_db_test")
            conn.execute("SET search_path TO ct_cert_db_test")

        self.database = pgdb_cert_db.pgSQLCertDB(self.__conn_manager)

    def tearDown(self):
        with self.__conn_manager.get_connection() as conn:
            conn.execute("SET client_min_messages TO WARNING")
            conn.commit()
            conn.execute("DROP SCHEMA IF EXISTS ct_cert_db_test CASCADE")
            conn.commit()

        conn.close()

    def db(self):
        return self.database

if __name__ == '__main__':
    sys.argv = gflags.FLAGS(sys.argv)
    unittest.main()
