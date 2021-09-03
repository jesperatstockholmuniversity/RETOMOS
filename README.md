## RETOMOS 

- **Website:** https://dsv.su.se


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
        retomos.py -f -i <input_file(s)> -d <database> -t 1
        retomos.py --urls --feed --target 2 --model "ALL"

    Options:
        -i --input          Input file(s) to analyse (Cuckoo report in .json format)
        -m --model <classification_model>      The type of classification model to use
            SVM, LR, NB, or ALL (default: ALL) [default: ALL]
        -d --database       Training database to use for the classification. Mandatory argument.
        -f --feed           Feed the database with new malware analysis reports (.json format). Requires --input and --database
        -t --target         Target (class) label for input file to feed to training set database. 1 for Tor related, 0 for non-Tor related, and 2 (default) for unknown.
        -u --urls           Extract .onion URLs from Tor classified malware sample reports


## Nota bene
This code is not beautiful. Neither is it fine-tuned nor very efficient, but it is a proof-of-concept. 

## Licence
RETOMOS is open-sourced software licensed under the [MIT license](https://opensource.org/licenses/MIT).
