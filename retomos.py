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
    retomos.py -i <input_file.json>
    retomos.py -d <training_database> [-m <classification_model>
    | --model <classification_model>]
    retomos.py -i <malware_analysis_file> -m <classification_model>
    retomos.py -f -i <input_file>
    retomos.py -w -i <input_file>
    retomos.py -i <input_file.json> -o <output_file.png>
    retomos.py -u -i <input_file> -m <clssification_model>

Examples:
    retomos.py -d malware_behaviour_log.db
    retomos.py -d malware_behaviour_log.db -m naive_bayes
    retomos.py -h | --help
    retomos.py -w -i <input_file>
    retomos.py -f -i <input_file(s)> -d <database>

Options:
    -i --input          Input file(s) to analyse (Cuckoo report in .json format)
    -o --output         Output file for graphs (.png format)
    -m --model <classification_model>      The type of classification model to use
        SVM, LR, NB, or ALL (default: ALL) [default: ALL]
    -d --database       Training database to use for the classification
    -f --feed           Feed the database with new malware analysis reports (.json format)
    -w --wash           Wash the data (requires -i input file)
    -u --urls            Extract .onion URLs from Tor classified malware sample reports
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
    wash = arguments['--wash']
    input_file = arguments['--input']
    print("Arguments: ", arguments)

    if(input_file):
        rfe.open_database("tmp.db", input_file)

    if(database_file):
        # Connect to DB
        rmc.connect_to_database(False, database_file, urls)

        # Create timer
        start = timeit.default_timer()

        # Close DB connection
        rmc.connect_to_database(True, database_file, urls)

        # Stop timer
        stop = timeit.default_timer()
        runtime = stop - start
        slowprint("Run time: " + str(runtime))

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
