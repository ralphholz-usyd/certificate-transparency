#!/usr/bin/env python

import unittest
import pgdb

from ct.client.db import pgdb_connection as pgcon

TEST_CONNECTION = [
    'ct_test',   # db:       database name
    '127.0.0.1', # host:     server hostname or IP
    'ct_test',   # user:     auth username
    'ct_test',   # password: auth password
]

class pgSQLConnectionTest(unittest.TestCase):

    def setUp(self):
        with pgcon.pgSQLConnection(*TEST_CONNECTION) as conn:
            conn.execute("DROP TABLE IF EXISTS words CASCADE")

    def test_connection_works(self):
        with pgcon.pgSQLConnection(*TEST_CONNECTION) as conn:
            conn.execute("CREATE TABLE words(word TEXT)")
            conn.execute("INSERT INTO words VALUES (%s)", ("hello",))
            conn.commit()
            results = conn.execute("SELECT * FROM words")
            self.assertEqual("hello", results.next()["word"])
            self.assertRaises(StopIteration, results.next)

    def test_exit_autocommits(self):
        with pgcon.pgSQLConnection(*TEST_CONNECTION, keepalive=True) as conn:
            conn.execute("CREATE TABLE words(word TEXT)")
            conn.execute("INSERT INTO words VALUES (%s)", ("hello",))
        results = conn.execute("SELECT * FROM words")
        conn.commit()
        self.assertEqual("hello", results.next()["word"])

    def test_no_keepalive_closes_connection(self):
        con = pgcon.pgSQLConnection(*TEST_CONNECTION, keepalive=False)
        with con as conn:
            conn.execute("CREATE TABLE words(word TEXT)")
        self.assertRaises(pgdb.OperationalError, conn.execute,
                          "SELECT * FROM words")

class pgSQLConnectionManagerTest(unittest.TestCase):
    def test_get_connection(self):
        mgr = pgcon.pgSQLConnectionManager(*TEST_CONNECTION)
        self.assertIsInstance(mgr.get_connection(), pgcon.pgSQLConnection)

    def test_keepalive_returns_same_connection(self):
        mgr = pgcon.pgSQLConnectionManager(*TEST_CONNECTION, keepalive=True)
        conn1 = None

        with mgr.get_connection() as conn:
            conn1 = conn

        with mgr.get_connection() as conn:
            self.assertEqual(conn, conn1)

    def test_no_keepalive_returns_new_connection(self):
        mgr = pgcon.pgSQLConnectionManager(*TEST_CONNECTION, keepalive=False)
        conn1 = None

        with mgr.get_connection() as conn:
            conn1 = conn

        with mgr.get_connection() as conn:
            self.assertNotEqual(conn1, conn)

if __name__ == '__main__':
    unittest.main()
