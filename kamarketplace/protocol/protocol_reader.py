from abc import abstractmethod
from pathlib import Path
import pickle
from .types_reader import *


with (Path(__file__).parent / "protocol.pk").open("rb") as f:
    types = pickle.load(f)
    msg_from_id = pickle.load(f)
    types_from_id = pickle.load(f)
    primitives = pickle.load(f)


def read_message(bytes_to_decode, type_name):

    structure = types[type_name]
    vars_ = structure['vars']

    print("Decoding %s" % bytes_to_decode)
    print("Type is %s" % type_name)

    while bytes_to_decode:

        for var in vars_:
            var_name = var['name']
            var_length = var['length']
            var_type = var['type']
            # var_optional = var['optional']

            print("Variable name is %s, type is %s and length is %s"
                  % (var_name, var_type, var_length))

            if var_type and var_type not in primitives:
                print("Type %s is complex" % var_type)
                read_message(bytes_to_decode, var_type)

            else:
                print("Type %s is primitive" % var_type)
                func = DIC_TYPES[var_type]
                var_value, bytes_to_decode = func(bytes_to_decode)
                print("%s decoded in %s" % (var_name, var_value))


class Node:
    def __init__(self, name, type_name):
        self.name = name
        self.type_name = type_name

    @abstractmethod
    def to_json(self):
        pass


class PrimitiveNode(Node):
    def __init__(self, value, **kwargs):
        super(PrimitiveNode, self).__init__(**kwargs)
        self.value = value

    def to_json(self):
        return self.value


class CompositeNode(Node):
    def __init__(self, children, **kwargs):
        super(PrimitiveNode, self).__init__(**kwargs)
        self.children = children

    def to_json(self):
        return {
            child.name: child.to_json()
            for child in self.children
        }
