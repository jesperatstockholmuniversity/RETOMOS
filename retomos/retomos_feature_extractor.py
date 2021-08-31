#################################################################
# Title: Feed SQLite DB with .json reports from Cuckoo reports
# Author: Jesper Bergman (jesperbe@dsv.su.se)
# Licence: GPLv2
#################################################################

import sqlite3
import sys
import os
import timeit
import json
import argparse

def open_database(database, input_file, tor):
    # Open database connection
    db_connection = sqlite3.connect(database)
    db_cursor = db_connection.cursor()
    sha256 = ""

    # If input is a file
    if os.path.isfile(input_file) is True:
        print("Feeding single file to DB.", input_file)
        input_opener = open(input_file, "r")
        sha256 = feed_database(db_cursor, input_opener, tor)

    # If input is a directory
    if os.path.isdir(input_file) is True:
        # Open all files and feed their content to DB
        for filename in os.listdir(input_file):
            filename_path = input_file + "/" + filename
            directory_file_opener = open(filename_path, "r")

            # Feed database with web pages | In future send tor_related label as argument
            sha256 = feed_database(db_cursor, directory_file_opener, tor)

    # Close DB
    try:
        db_connection.commit()
        db_connection.close()

        return sha256

    except sqlite3.Error as e:
        print(" Sqlite error: ", e.args[0])
    else:
        sys.exit()

def feed_database(db_cursor, file_opener, tor):
    # Suck in content and parse the JSON
    tor_related = tor # 0=false, 1=true, 2=unknown
    index = 0
    document = file_opener.read()
    json_obj = json.loads(document)
    sha256 = str(json_obj['target']['file']['sha256'])

    # Extract signatures and AV organisations 
    signatures = json_obj['signatures']
    label = ""
    av_organisation = ""

    for listitem in signatures:
        if listitem["name"] == "antivirus_virustotal":
            for av_organisations in listitem["marks"]:
                index += 1
                av_organisation = av_organisations["category"]
                label = av_organisations["ioc"]
                print("Label: ", label)
                #label_insert = "UPDATE malware_name SET av_label=\'" + label + "\' WHERE sha256=\'" + sha256 + "\';"
                #av_insert = "UPDATE OR IGNORE malware_name SET av_organisation=\'" + av_organisation + "\' WHERE sha256=\'" + sha256 + "\';"
                db_cursor.execute("INSERT OR IGNORE INTO av_organisation(name) VALUES(?)", [av_organisation,])
                #sha256_sql = "UPDATE OR IGNORE malware_name SET sha256=\'" + sha256 + "\', av_label=\'" + label + "\', av_organisation=\'" + av_organisation + "\';";
                db_cursor.execute("INSERT OR IGNORE INTO malware_name VALUES(?,?,?)", (sha256, label, av_organisation))
                print("Inserting sha256:", sha256)

                db_cursor.execute("INSERT OR IGNORE INTO label(label, sha256, tor_related,  av_organisation) VALUES(?,?,?,?)", (label, sha256, tor_related, av_organisation))

    # Extract DLLs, registry keys, and API calls
    try:
        behaviour = json_obj['behavior']['apistats']
        generic = json_obj['behavior']['generic']
        strings = json_obj['strings']
    except:
        pass

    # Insert API calls into DB
    for behaviouritem in behaviour:
        for apicalls in behaviour[behaviouritem]:
            db_cursor.execute("INSERT INTO api_calls(name, label, tor_related, sha256, av_organisation) VALUES(?,?,?,?,?)", (apicalls, label, tor_related, sha256, av_organisation))

    for entry in generic:
        file_created = entry['summary']
        for iii in file_created:
            # Get DLLs
            if iii == "dll_loaded":
                # Add DLLs to DB 
                for ii in file_created[iii]:
                    db_cursor.execute("INSERT OR IGNORE INTO dlls(name, sha256) VALUES(?,?)", (ii, sha256))
            # Get registry keys written:
            if iii == "regkey_written":
                for ii in file_created[iii]:
                    db_cursor.execute("INSERT OR IGNORE INTO reg_keys(path, access_type, sha256) VALUES(?,?,?)", (ii, "written", sha256))
            if iii == "regkey_opened":
                for ii in file_created[iii]:
                    db_cursor.execute("INSERT OR IGNORE INTO reg_keys(path, access_type, sha256) VALUES(?,?,?)", (ii, "opened", sha256))
            if iii == "regkey_read":
                for ii in file_created[iii]:
                    db_cursor.execute("INSERT OR IGNORE INTO reg_keys(path, access_type, sha256) VALUES(?,?,?)", (ii, "read", sha256))

    strings_dump = ""
    for strings_item in strings:
        strings_dump = strings_dump + " " +  strings_item
    db_cursor.execute("INSERT OR IGNORE INTO strings(sha256, strings) VALUES(?,?)", (sha256, strings_dump))

    # Get network details 
    network = json_obj['network']['hosts']
    domains = json_obj['network']['domains']
    for dns in domains:
        db_cursor.execute("INSERT OR IGNORE INTO network(ip, dns, sha256) VALUES(?,?,?)", (dns['ip'], dns['domain'],sha256))

    print("Added: ", index, " entries into database.")
    return sha256
