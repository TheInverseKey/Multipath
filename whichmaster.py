import json
import sys

query_addr = sys.argv[1]
filename = sys.argv[2]

def whichmaster(query_addr, filename):
    with open(filename, 'r') as dicts:
        for entry in dicts:
            entry = json.loads(entry)
            try:
                if query_addr in entry.values():
                    return entry.keys()[0]
                    break
            except Exception as e:
                print "Corrupt IP relationship file."
                print "Read failed with error: {}".format(e)
                return e

            return "No master found."



if __name__ == '__main__':
    print whichmaster(query_addr, filename)