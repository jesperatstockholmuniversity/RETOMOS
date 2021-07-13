#################################################################
# Title: Feed SQLite DB with .json reports from Cuckoo reports
# Author: Jesper Bergman (jesperbe@dsv.su.se)
# Licence: GPLv2
#################################################################

import sqlite3;
import sys;
import os;

def main ():
    # Open DB
    db_connection = sqlite3.connect('cuckoo_reports.db');
    db_cursor = db_connection.cursor();

    # Feed database with web pages
    feed_database(db_cursor);

    # Close DB
    try:
        db_connection.commit();
        db_connection.close();
        print("Database connection closed.");
    except sqlite3.Error as e:
        print(" Sqlite error: ", e.args[0]);

def feed_database(db_cursor):
    db_cursor.execute("select sha256,label,av_organisation from label;");
    query = db_cursor.fetchall();

    for row in query:
        #print("Row: ", row);
        #print("Row says: ", row[1], ". Type: ", type(row[1]));
        if row[2] == "Kaspersky":
            if row[1].find("trojan") != -1 or row[1].find("Trojan") != -1:
                print("Trojan here. ", row[1], "AV: ", row[2] ," SHA256: ", row[0]);
            #db_cursor.execute("INSERT INTO label(washed_label) VALUES(\'trojan\') WHERE sha256=\'" + row[0] + "\';");
            db_cursor.execute("UPDATE OR IGNORE label SET washed_label=\'trojan\' WHERE sha256=\'" + row[0] + "\';");
            #print("UPDATE OR IGNORE label SET washed_label=\'trojan\' WHERE sha256=\'" + row[0] + "\';");

if __name__ == "__main__":
    main();

