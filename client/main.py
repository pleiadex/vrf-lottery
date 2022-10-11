import os, sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from vrf import VRF_verifying, RsaPublicKey

from struct import pack
import requests
from merkletools import MerkleTools
import hashlib
import binascii
# import json

import string
import random

def id_generator(size=6, chars=string.ascii_uppercase + string.digits):
  return ''.join(random.choice(chars) for _ in range(size))

URL = 'http://127.0.0.1:5000'

user_random_data = id_generator()
params = {'data': user_random_data}
req = requests.get(url=URL + '/item', params=params)
req_body = req.json()

# print(json.dumps(req_body, indent=4))

merkle_proof = req_body['merkle_tree']['merkle_proof']
merkle_root = req_body['merkle_tree']['merkle_root']
random_number = req_body['vrf']['random_number']
unpack_random_number_proof = req_body['vrf']['random_number_proof']
v = req_body['vrf']['v']
n = req_body['vrf']['n']
e = req_body['vrf']['e']
total = req_body['probability']['total']
win = req_body['probability']['win']
result = req_body['result']

# merkle validate
values = [user_random_data]
hash_function = getattr(hashlib, 'sha256')
for value in values:
  value = value.encode('utf-8')
  value = hash_function(value).hexdigest()
  value = bytearray.fromhex(value)
user_contribution = binascii.hexlify(value)

mt = MerkleTools()

isvalid_merkle = mt.validate_proof(merkle_proof, user_contribution, merkle_root)
# print(isvalid_merkle)

# random validate
pack_format = '>' + 'H' * 128
pack_random_number_proof = pack(pack_format, *unpack_random_number_proof)
isvalid_random_number = VRF_verifying(RsaPublicKey(n, e), merkle_root, pack_random_number_proof, v)
# print(random_number)

# get the random value
calculated_result = random_number % total < win
# print(result == calculated_result)

if (isvalid_merkle and isvalid_random_number and result == calculated_result):
  # print("Verified!")
  print("WIN" if result else "LOSE")
else:
  if (not isvalid_merkle):
    print("Merkle proof is invalid.")
  if (not isvalid_random_number):
    print("The random number is invalid.")
  if (result != calculated_result):
    print("The result is invalid.")