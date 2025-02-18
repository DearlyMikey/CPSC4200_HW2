#!/usr/bin/python3

# Run me like this:
# $ python3 bleichenbacher.py "coach+username+100.00"
# or select "Bleichenbacher" from the VS Code debugger

from roots import *

import hashlib
import base64
import sys


def main():
    if len(sys.argv) < 2:
        print(f"usage: {sys.argv[0]} MESSAGE", file=sys.stderr)
        sys.exit(-1)
    message = sys.argv[1]

    encoded_message = message.encode("ASCII")
    message_hash = hashlib.sha256(encoded_message).hexdigest()

    # first 4 bytes (4 out of 256)
    sig_start = b'\x00\x01\xFF\x00'
    #next 19 bytes (23 out of 256)
    #ASN.1 "magic" bytes
    ASN = b'\x30\x31\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\x04\x20'

    e = 3

    #add together the first 3 components of the byte-string
    forged_signature = sig_start + ASN + bytes.fromhex(message_hash)
    
    #fill in the remaining bytes of the string to reach 2048 bits
    while len(forged_signature) < 256:
        forged_signature = forged_signature + b'\x00'

    #do all of the conversions
    forged_int = bytes_to_integer(forged_signature)
    forged_three = integer_nthroot(forged_int, e)
    forged_signature_int = forged_three[0]
    #number must be odd
    if not forged_three[1]:
        forged_signature_int = forged_signature_int + 1
    forged_signature_bytes = integer_to_bytes(forged_signature_int, 256)
    print(bytes_to_base64(forged_signature_bytes))

if __name__ == '__main__':
    main()

