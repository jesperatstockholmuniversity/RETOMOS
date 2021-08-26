#################################################################
# Title: Feed SQLite DB with .json reports from Cuckoo reports
# Author: Jesper Bergman (jesperbe@dsv.su.se)
# Licence: GPLv2
#################################################################

import sqlite3;
import sys;
import os;
import timeit;
#from bs4 import BeautifulSoup;
import json;
#import nltk;
#import regex as re;
import argparse;

def open_database(database, input_file):
    # Open DB
    db_connection = sqlite3.connect(database);
    db_cursor = db_connection.cursor();

    # Feed database with web pages | In future send tor_related label as argument
    feed_database(db_cursor, input_file);

    # Close DB
    try:
        db_connection.commit();
        db_connection.close();
        print("Database connection closed.");
    except sqlite3.Error as e:
        print(" Sqlite error: ", e.args[0]);

    else:
        quit();

def feed_database(db_cursor, input_file):
    # Paths - Fetch from argument. Temporary fix: 
    #directory_path = "/home/amoros/mnt/cs-reports/confirmed_Tor_malware_samples/training_set/"
    directory_path = "/home/amoros/mnt/cs-reports/confirmed_non-Tor_malware_samples/training_set/";
    index=1;
    tor_related=0; # 0=false, 1=true; 

    # Open all files and feed their content to DB
    for filename in os.listdir(directory_path):
        index=+1;

        # filename_concatenated = '\'' + filename + '\''
        filename_path = directory_path + "/" + filename;
        input_file = open(filename_path, "r");

        # Suck in content and parse the JSON
        document = input_file.read();
        #print("Input file is: ", filename);
        #print("File name: ", filename);
        json_obj = json.loads(document);
        sha256 = str(json_obj['target']['file']['sha256']);

        # Extract signatures and AV organisations 
        signatures = json_obj['signatures'];
        label = "";
        av_organisation = "";

        for listitem in signatures:
            if listitem["name"] == "antivirus_virustotal":
                for av_organisations in listitem["marks"]:
                    index += 1;
                    av_organisation = av_organisations["category"]
                    label = av_organisations["ioc"];
                    print("Label: ", label);
                    #label_insert = "UPDATE malware_name SET av_label=\'" + label + "\' WHERE sha256=\'" + sha256 + "\';"
                    #av_insert = "UPDATE OR IGNORE malware_name SET av_organisation=\'" + av_organisation + "\' WHERE sha256=\'" + sha256 + "\';"
                    db_cursor.execute("INSERT OR IGNORE INTO av_organisation(name) VALUES(?)", [av_organisation,]);
                    #sha256_sql = "UPDATE OR IGNORE malware_name SET sha256=\'" + sha256 + "\', av_label=\'" + label + "\', av_organisation=\'" + av_organisation + "\';";
                    db_cursor.execute("INSERT OR IGNORE INTO malware_name VALUES(?,?,?)", (sha256, label, av_organisation));
                    print("Inserting sha256:", sha256);

                    db_cursor.execute("INSERT OR IGNORE INTO label(label, sha256, tor_related,  av_organisation) VALUES(?,?,?,?)", (label, sha256, tor_related, av_organisation));

        # Extract DLLs, registry keys, and API calls
        try:
            behaviour = json_obj['behavior']['apistats'];
            generic = json_obj['behavior']['generic'];
            strings = json_obj['strings'];
        except:
            pass;

        # Insert API calls into DB
        for behaviouritem in behaviour:
            for apicalls in behaviour[behaviouritem]:
                db_cursor.execute("INSERT INTO api_calls(name, label, tor_related, sha256, av_organisation) VALUES(?,?,?,?,?)", (apicalls, label, tor_related, sha256, av_organisation));

        for entry in generic:
            file_created = entry['summary'];
            for iii in file_created:
                # Get DLLs
                if iii == "dll_loaded":
                    # Add DLLs to DB 
                    for ii in file_created[iii]:
                   #     print("DLL: ", ii);
                        #print(dll_insert);
                        db_cursor.execute("INSERT OR IGNORE INTO dlls(name, sha256) VALUES(?,?)", (ii, sha256));
                # Get registry keys written:
                if iii == "regkey_written":
                    for ii in file_created[iii]:
                        db_cursor.execute("INSERT OR IGNORE INTO reg_keys(path, access_type, sha256) VALUES(?,?,?)", (ii, "written", sha256));
                #        print("Registry written keys: ", ii);
                if iii == "regkey_opened":
                    for ii in file_created[iii]:
                        db_cursor.execute("INSERT OR IGNORE INTO reg_keys(path, access_type, sha256) VALUES(?,?,?)", (ii, "opened", sha256));
                 #       print("Registry opened keys: ", ii);
                if iii == "regkey_read":
                    for ii in file_created[iii]:
                        db_cursor.execute("INSERT OR IGNORE INTO reg_keys(path, access_type, sha256) VALUES(?,?,?)", (ii, "read", sha256));
                  #      print("Registry read keys: ", ii);

        strings_dump = "";
        for strings_item in strings:
            strings_dump = strings_dump + " " +  strings_item;
        # print("Strings dump: \n\n ", strings_dump);
        db_cursor.execute("INSERT OR IGNORE INTO strings(sha256, strings) VALUES(?,?)", (sha256, strings_dump));

        # Get network details 
        network = json_obj['network']['hosts'];
        domains = json_obj['network']['domains'];
        for dns in domains:
            #    print("IP: ", dns['ip']);
            #    print("DNS: ", dns['domain']);
            db_cursor.execute("INSERT OR IGNORE INTO network(ip, dns, sha256) VALUES(?,?,?)", (dns['ip'], dns['domain'],sha256));

    print("Added: ", index, "entries into database.");
