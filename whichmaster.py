import json
import sys

# ie. $python whichmaster.py "((127.0.0.1, 8080),(127.0.0.1,80))" ip_relationships.json
query_addr = sys.argv[1]
filename = sys.argv[2]

def whichmaster(query_addr, filename):
    with open(filename, 'r') as dicts:
        for entry in dicts:
            entry = json.loads(entry)
            if query_addr in entry.values()[0]:
                return entry.keys()[0]

            return "No master found."


if __name__ == '__main__':
    print whichmaster(query_addr, filename)