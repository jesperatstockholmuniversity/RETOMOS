## RETOMOS 

- **Website:** https://www.numpy.org
- **Documentation:** https://numpy.org/doc

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
        -i --input          Input file to analyse (Cuckoo report in .json format)
        -o --output         Output file for graphs (.png format)
        -m --model <classification_model>      The type of classification model to use
            SVM, LR, NB, or ALL (default: ALL) [default: ALL]
        -d --database       Training database to use for the classification
        -f --feed           Feed the database with new malware analysis reports (.json format)
        -w --wash           Wash the data (requires -i input file)
        -u --url            Extract .onion URLs from Tor classified malware sample reports

## Nota bene
This code is not beautiful. Neither is it fine-tuned and efficient. 

## Licence
RETOMOS is open-sourced software licensed under the [MIT license](https://opensource.org/licenses/MIT).
