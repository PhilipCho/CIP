#!/usr/bin/env python3
from mysql.connector import MySQLConnection, Error
import re
import argparse
from python_mysql_dbconfig import read_db_config

def insert_cvss_score(scores):
    query = "INSERT INTO cvss2 (name, score) VALUES(%s, %s)"

    try:
        db_config = read_db_config()
        conn = MySQLConnection(**db_config)

        cursor = conn.cursor()
        cursor.executemany(query, scores)

        conn.commit()
    except Error as error:
        print('Error:',error)

    finally:
        cursor.close()
        conn.close()

def parse_cvss_xml(xml):
    scores = []
    with open(xml) as f:
        name = None
        score = None
        for line in f:
            if '<vuln:cve-id>' in line:
                ls = re.split(r'[\<\>]', line)
                name = ls[2]
            if '<cvss:score>' in line:
                ls = re.split(r'[\<\>]', line)
                #print(ls)
                score = float(ls[2])
            if (name != None and score != None):
                scores.append((name, score))
                name = None
                score = None
    insert_cvss_score(scores)
    print(scores)

def main(xml):
    parse_cvss_xml(xml)

if __name__=='__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("file")
    args = parser.parse_args()
    main(args.file)

#create table cvss2 (id int not null primary key auto_increment, name varchar(13), score double);
#create table cvss2 (id int not null primary key auto_increment, name varchar(13), score double, unique (name, score));
