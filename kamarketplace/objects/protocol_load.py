from pathlib import Path
import pickle
import sys
sys.setrecursionlimit(2000)


with (Path(__file__).parent / "protocol.pk").open("rb") as f:
    types = pickle.load(f)
    msg_from_id = pickle.load(f)
    types_from_id = pickle.load(f)
    primitives = pickle.load(f)


def read_message(to_decode, msg_type):
    msg_structure = types[msg_type]
    var_structures = msg_structure['vars']
    print("Deserialize %s %s" % (msg_type, var_structures))

    while to_decode:

        for var_str in var_structures:
            var_type = var_str['type']
            var_name = var_str['name']
            # var_length = var_str['length']
            var_length = 1

            for iteration in range(0, var_length):

                if var_type and var_type not in primitives:
                    print("The variable %s is a complex type %s" % (var_name, var_type))
                    read_message(to_decode, var_type)

                elif var_type:
                    print("The variable %s is a primitive type %s" % (var_name, var_type))
                    to_decode = to_decode[1:]
                    # do something

                else:
                    print("No type")
                    to_decode = to_decode[1:]
                    # do something

        print("***  END DESERIALIZATION   ***")
        return msg_structure

