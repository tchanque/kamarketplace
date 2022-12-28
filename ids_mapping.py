import os
import pickle

from variables import *


def ids(path=DECOMPILED_SOURCE_CODE_PATH):
    files = [os.path.join(path, f) for f in os.listdir(path) if
             os.path.isfile(os.path.join(path, f)) and f != '.DS_Store' and f != 'ids_mapping.py']
    folders = [os.path.join(path, f) for f in os.listdir(path) if os.path.isdir(os.path.join(path, f))]
    for f in files:
        o = open(f)
        r = o.read()
        o.close()
        first_occurrence = r.find('protocolId:uint =')
        if first_occurrence != -1:  # means the value is found
            id_location = int(
                first_occurrence + 18)  # look 18 characters after (length of 'protocolId:uint = ')
            # to know when the protocolID's value is declared
            end_first_occurrence = int(r.find(';', id_location))
            index = r[id_location: end_first_occurrence]
            nom = os.path.basename(f)[:-3]
            dict_ids[index] = nom

    for d in folders:
        ids(d)


def create_ids(path=DECOMPILED_SOURCE_CODE_PATH):
    # create the dictionary and fill it with ids as keys and action types as values
    global dict_ids
    dict_ids = dict()
    ids(path)
    print('Created a dictionary with %s entries' % (str(len(dict_ids))))


def dump_ids(path=IDS_MAPPING_PATH):
    # create the dictionary for mapping and fill it
    create_ids()
    f = open(path, 'wb')
    pickle.dump(dict_ids, f)
    f.close()


def load_ids():
    # load the dictionary
    f = open(IDS_MAPPING_PATH, 'rb')
    global dict_ids
    dict_ids = pickle.load(f)
    f.close()


if __name__ == "__main__":
    create_ids(DECOMPILED_SOURCE_CODE_PATH)
