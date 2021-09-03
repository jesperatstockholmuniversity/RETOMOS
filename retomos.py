#####################################################
# Title: HTML parse- and analyser
# Author: Jesper Bergman (jesperbe@dsv.su.se)
# Licence: GPLv2
#####################################################

#!/usr/bin/python
"""RETOMOS - Recogniser of Tor Malware and Onion Services.

RETOMOS is a small program for analsying and classifying Tor
using malware samples based on API calls etc to find .onion services.
It consists of two scripts: retomos_featue_extractor.py that extracts 
features from Cuckoo reports and retomos_malware_classifier.py that
classifies Cuckoo reports as either Tor dependant or not.

Usage:
    retomos.py -i <input_file>
    retomos.py -d <training_database> ./db/training.db
    retomos.py -i <input_file.json> -m <classification_model>
    retomos.py -t target/class label <0, or 1, or 2>
    retomos.py -f -i <input_file.json> -t <0, or 1, or 2>
    retomos.py -u -d <training_database>

Examples:
    retomos.py -d malware_behaviour_log.db
    retomos.py -d malware_behaviour_log.db -m svm
    retomos.py -h | --help
    retomos.py -f -i <input_file.json> -d <database> -t 1
    retomos.py -i <input_file.json> -m <"nb", or "svm", or "lr", or "rf", or "dt", or "ALL" (default)>
    retomos.py -u -f -t <0, or 1, or 2> -i <input_file.json>

Options:
    -i --input          Input file(s) to analyse (Cuckoo report in .json format)
    -m --model <classification_model>      The type of classification model to use
        SVM, LR, NB, or ALL (default: ALL) [default: ALL]
    -d --database       Training database to use for the classification. Mandatory argument.
    -f --feed           Feed the database with new malware analysis reports (.json format). Requires --input and --database
    -t --target         Target (class) label for input file to feed to training set database. 1 for Tor related, 0 for non-Tor related, and 2 (default) for unknown.
    -u --urls           Extract .onion URLs from Tor classified malware sample reports
"""

# Import standard libraries
from docopt import docopt
import timeit
import sys
import time

# Import self-made code
from retomos import retomos_malware_classifier as rmc
from retomos import retomos_feature_extractor as rfe

# Main menu 
def main(arguments):
    # Extract arguments of interest
    database_file = arguments['<training_database>']
    model = arguments['--model']
    urls = arguments['--urls']
    feed = arguments['--feed']
    input_file = arguments['<input_file>']
    print("Arguments: ", arguments)
    # 

    if input_file:
        # Open and add to temporary SQLite DB. 2 stands for unkown tor label.
        sha256 = rfe.open_database("db/training_set.db", input_file, 2)
        print("Received ", sha256, " in return from fe.")
        # If everything is OK. Continue with classification
        #if database_file:
        #    rmc.connect_to_database(False, database_file, False, True, sha256)

        # If feed and class label (1 or 0), add to DB.
        # if feed: 
        #    rmc.connect_to_database(False, database_file,input_file)

    if database_file:
        # Connect to DB (connect, db, url, unknown_samples, sha256)
        rmc.connect_to_database(False, database_file, urls, False, "")

        # Close DB connection
        rmc.connect_to_database(True, database_file, urls, False, "")


# Slow print strings
def slowprint(string):
    for letter in string:
        sys.stdout.write(letter)
        time.sleep(0.03)
        sys.stdout.flush()
print()

# Main menu constructor
if __name__ == "__main__":
    arguments = docopt(__doc__, version='retomos 0.1')
    main(arguments)
