from pathlib import Path
import pickle

with (Path(__file__).parent / "protocol.pk").open("rb") as f:
    types = pickle.load(f)
    msg_from_id = pickle.load(f)
    types_from_id = pickle.load(f)
    primitives = pickle.load(f)


def read_message(to_decode, protocol_id):
    msg_structure = msg_from_id[protocol_id]
    var_structures = msg_structure['vars']

    for var_str in var_structures:
        read_type(var_str)

    # return message


def read_type(structure):
    # must return the structure of a variable

    if structure['type'] and structure['type'] not in primitives:
        print("The type %s is complex" % structure['type'])
        # return types_from_id[type_]

    elif structure['type']:
        print("The type %s is a primitive" % structure['type'])
        # return primitives[type_]

    else:
        print("No type")
        # return False
