from data_updater.updater import *
import argparse
import os

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Knowledge base updater')
    parser.add_argument('-u', '--update', help='full, cve, cwe, cved, attack, capec')

    args = parser.parse_args()
    updater = Updater()
    if args.update == "full":
        updater.update()
        exit(0)
    for base in args.update.split(","):
        if base == "cve":
            updater.update_cve()
        elif base == "cwe":
            updater.update_cwe()
        elif base == "cved":
            updater.update_cve_details()
        elif base == "capec":
            updater.update_capec()
        elif base == "attack":
            updater.update_attack()
        else:
            print("Unknown base: {}".format(base))