#!/usr/bin/env python

from z3 import *
import struct
import sys

# variable name used in the output
varname = 'buf'

# characters to avoid
badchars =  b'\x00\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18'
badchars += b'\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28'
badchars += b'\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x3a\x3f\x40\x80\x81\x82\x83\x84'
badchars += b'\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94'
badchars += b'\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4'
badchars += b'\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4'
badchars += b'\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4'
badchars += b'\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4'
badchars += b'\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4'
badchars += b'\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4'
badchars += b'\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff'

# the shellcode to be encoded
shellcode =  b''
shellcode += b'\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90'

def encode_subtraction(asm):
    target = 0xffffffff - asm + 1

    s = Solver()
    x = BitVec('x', 32)
    y = BitVec('y', 32)
    z = BitVec('z', 32)

    # add constraints for each invalid char
    for c in list(badchars):
        # each bitvec is 32 bits, constraints are added for each 8 bits
        for k in range(0, 32, 8):
            s.add(Extract(k+7, k, x) != BitVecVal(c, 8))
            s.add(Extract(k+7, k, y) != BitVecVal(c, 8))
            s.add(Extract(k+7, k, z) != BitVecVal(c, 8))

    # the constraint we're trying to solve for
    # which three values do we need to subtract to get our target?
    s.add(x+y+z == target)
    s.check()

    return [
        s.model()[x].as_long(),
        s.model()[y].as_long(),
        s.model()[z].as_long()
    ]


def encode_zero(value):
    s = Solver()
    target = BitVecVal(value, 32)
    x = BitVec('x', 32)
    y = BitVec('y', 32)

    # add constraints for each invalid char
    for c in list(badchars):
        # each bitvec is 32 bits, constraints are added for each 8 bits
        for k in range(0, 32, 8):
            s.add(Extract(k+7, k, x) != BitVecVal(c, 8))
            s.add(Extract(k+7, k, y) != BitVecVal(c, 8))

    # the constraint we're trying to solve for
    # which two values do we 'and' with our value to get zero?
    s.add(target & x & y == 0)
    s.check()

    return [
        s.model()[x].as_long(),
        s.model()[y].as_long()
    ]

def encode_shellcode(shellcode):
    print ("{}  = b''".format(varname))

    # split shellcode into 4 byte chunks
    chunks = [shellcode[x:x+4] for x in range(0, len(shellcode), 4)]
    chunks.reverse()
    chunks = [struct.unpack('<I',x)[0] for x in chunks]

    # encode and print each chunk
    for chunk in chunks:
        # find out sub instructions for the chunk
        for val in encode_subtraction(chunk):
            hexval = ''.join('\\x{:02x}'.format(x) for x in struct.pack('<I', val))
            sub = "{} += b'\\x2d{}'              # sub  eax, {}".format(varname, hexval, '0x{0:08x}'.format(val))
            print(sub)
        
        # push value on stack
        print("{} += b'\\x50'                              # push eax".format(varname))

        # zero out eax
        for val in encode_zero(chunk):
            hexval = ''.join('\\x{:02x}'.format(x) for x in struct.pack('<I', val))
            _and = "{} += b'\\x25{}'              # and  eax, {}".format(varname, hexval, '0x{0:08x}'.format(val))
            print(_and)

        # newline to delineate chunks
        print()

if __name__ == '__main__':
    encode_shellcode(shellcode)