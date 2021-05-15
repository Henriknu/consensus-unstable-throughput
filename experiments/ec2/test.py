import struct
import random
import os
TR_SIZE = 250


# assumptions: amount of the money transferred can be expressed in 2 bytes.
def encodeTransaction(tr, randomGenerator=None, length=TR_SIZE):
    sourceInd = 1
    targetInd = 1
    if randomGenerator:
        return struct.pack(
            '<BBH', sourceInd, targetInd, tr.amount
        ) + getSomeRandomBytes(TR_SIZE - 5, randomGenerator) + '\x90'
    return struct.pack(
        '<BBH', sourceInd, targetInd, tr.amount
    ) + os.urandom(TR_SIZE - 5) + b'\x90'


LONG_RND_STRING = ''


def getSomeRandomBytes(length, rnd=random):
    maxL = len(LONG_RND_STRING) - 1 - length
    startP = rnd.randint(0, maxL)
    return LONG_RND_STRING[startP:startP+length]


class Transaction:  # assume amout is in term of short
    def __init__(self):
        self.source = 'Unknown'
        self.target = 'Unknown'
        self.amount = 0
        # TODO: Define a detailed transaction

    def __repr__(self):
        return bcolors.OKBLUE + "{{Transaction from %s to %s with %d}}" % (self.source, self.target, self.amount) + bcolors.ENDC

    def __eq__(self, other):
        if isinstance(other, self.__class__):
            return self.source == other.source and self.target == other.target and self.amount == other.amount
        return False

    def __ne__(self, other):
        return not self.__eq__(other)

    def __hash__(self):
        return hash(self.source) ^ hash(self.target) ^ hash(self.amount)


def randomTransaction(randomGenerator=random):
    tx = Transaction()
    tx.source = "brian"
    tx.target = "brian"
    tx.amount = randomGenerator.randint(1, 32767)  # not 0
    return tx


class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


def randomTransactionStr():
    return repr(randomTransaction())


tr = randomTransaction()
print(tr)

encoded = encodeTransaction(tr)

print(len(encoded))
