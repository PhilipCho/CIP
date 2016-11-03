#!/usr/bin/env python3

from mysql.connector import MySQLConnection, Error
import re
import argparse
from python_mysql_dbconfig import read_db_config

def get_cvss_score(cve):
    query = "SELECT score FROM cvss2 WHERE name={0!s}".format(cve)
    print(query)
    try:
        db_config = read_db_config()
        conn = MySQLConnection(**db_config)

        cursor = conn.cursor()
        cursor.execute(query)

        for row in cursor.fetchall():
            return row[0]
    except Error as error:
        print('Error:',error)

    finally:
        cursor.close()
        conn.close()

def main():
    print(get_cvss_score("'CVE-2016-0010'"))

if __name__=='__main__':
    main()
