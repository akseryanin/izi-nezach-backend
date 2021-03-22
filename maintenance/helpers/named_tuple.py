from collections import namedtuple


def namedtuple_wrapper(name, fields):
    return namedtuple(name, fields, defaults=(None,) * len(fields))