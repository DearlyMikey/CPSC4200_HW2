#!/usr/bin/python3

# Run me like this:
# $ python3 padding_oracle.py "http://cpsc4200.mpese.com/mvgonza/paddingoracle/verify" "5a7793d3..."
# or select "Padding Oracle" from the VS Code debugger

import json
import sys
import time
from typing import Union, Dict, List

import requests

# Create one session for each oracle request to share. This allows the
# underlying connection to be re-used, which speeds up subsequent requests!
s = requests.session()


def oracle(url: str, messages: List[bytes]) -> List[Dict[str, str]]:
    while True:
        try:
            r = s.post(url, data={"message": [m.hex() for m in messages]})
            r.raise_for_status()
            response_json = r.json()
            for i, msg_status in enumerate(response_json):
                print(f"[*] Response [{i}]: {msg_status['status']}")
            return r.json()
        # Under heavy server load, your request might time out. If this happens,
        # the function will automatically retry in 10 seconds for you.
        except requests.exceptions.RequestException as e:
            sys.stderr.write(str(e))
            sys.stderr.write("\nRetrying in 10 seconds...\n")
            time.sleep(10)
            continue
        except json.JSONDecodeError as e:
            sys.stderr.write("It's possible that the oracle server is overloaded right now, or that provided URL is wrong.\n")
            sys.stderr.write("If this keeps happening, check the URL. Perhaps your uniqname is not set.\n")
            sys.stderr.write("Retrying in 10 seconds...\n\n")
            time.sleep(10)
            continue

def main():
    if len(sys.argv) != 3:
        print(f"usage: {sys.argv[0]} ORACLE_URL CIPHERTEXT_HEX", file=sys.stderr)
        sys.exit(-1)
    oracle_url, message = sys.argv[1], bytes.fromhex(sys.argv[2])

    if oracle(oracle_url, [message])[0]["status"] != "valid":
        print("Message invalid", file=sys.stderr)
    

# def main():
#     if len(sys.argv) != 3:
#         print(f"usage: {sys.argv[0]} ORACLE_URL CIPHERTEXT_HEX", file=sys.stderr)
#         sys.exit(-1)
#     oracle_url, message = sys.argv[1], bytes.fromhex(sys.argv[2])

#     if oracle(oracle_url, [message])[0]["status"] != "valid":
#         print("Message invalid", file=sys.stderr)

#     #
#     # TODO: Decrypt the message
#     # 
#     blocks = [message[i:i + 16] for i in range(0, len(message), 16)]
#     decrypted = bytes()
#     for i in range(len(blocks) - 1, 0, -1):
#         print(f"Decrypting block {i}...")
#         curr_block = blocks[i]
#         prev_block = blocks[i - 1]
#         decrypted_block = bytearray(16)
#         intermediate = bytearray(16)
#         bruteforce_block = bytearray(prev_block)
#         padding = 0

#         for value in range(16, 0, -1):  # Process each byte
#             print(f"Byte {value}")
#             padding += 1
#             for j in range(0, 256):
#                 bruteforce_block = bytearray(bruteforce_block)
#                 bruteforce_block[value-1] = (bruteforce_block[value-1] + 1) % 256
#                 joined_blocks = bytes(bruteforce_block) + curr_block
#                 # oracle(oracle_url, [joined_blocks])
#                 # if oracle(oracle_url, [joined_blocks])[0]["status"] == "invalid_mac":
#                 #     print(joined_blocks.hex())

#                 if oracle(oracle_url, [joined_blocks])[0]["status"] == "invalid_mac":
#                     print(joined_blocks.hex())
#                     decrypted_block[-padding] = bruteforce_block[-padding] ^ prev_block[-padding] ^ padding
#                     print(decrypted_block.hex())

#                     # Adjust padding for the next byte
#                     for k in range(1, padding + 1):
#                         bruteforce_block[-k] = padding+1 ^ decrypted_block[-k] ^ prev_block[-k]
#                         print(bruteforce_block.hex())
#                     break
#                 # elif oracle(oracle_url, [joined_blocks])[0]["status"] != "valid":
#                 #     print("Message invalid", file=sys.stderr)
        
#         decrypted_msg = bytes(decrypted_block) + bytes(decrypted)


                

#     decrypted = decrypted_msg[:-decrypted_msg[-1]]
#     print(decrypted.decode())


if __name__ == '__main__':
    main()

