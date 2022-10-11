import os, sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from vrf import VRF_verifying, RsaPublicKey

from struct import pack
import requests
from merkletools import MerkleTools


URL = 'http://127.0.0.1:5000'

params = {'data': 'hello'}
req = requests.get(url=URL + '/item', params=params)
req_body = req.json()

merkle_proof = req_body['merkle_tree']['merkle_proof']
merkle_root = req_body['merkle_tree']['merkle_root']
merkle_contribution = req_body['merkle_tree']['merkle_contribution']
unpack_random_number = req_body['vrf']['random_number']
unpack_random_number_proof = req_body['vrf']['random_number_proof']
k = req_body['vrf']['k']
n = req_body['vrf']['n']
e = req_body['vrf']['e']
total = req_body['probability']['total']
win = req_body['probability']['win']
result = req_body['result']

# merkle validate
mt = MerkleTools()
isvalid_merkle = mt.validate_proof(merkle_proof, merkle_contribution, merkle_root)
# print(isvalid_merkle)

# random validate
pack_format = '>' + 'H' * 128
pack_random_number_proof = pack(pack_format, *unpack_random_number_proof)
isvalid_random_number = VRF_verifying(RsaPublicKey(n, e), merkle_root, pack_random_number_proof, k)
# print(isvalid_random_number)

# get the random value
calculated_result = unpack_random_number[9] % total < win
# print(result == calculated_result)

if (isvalid_merkle and isvalid_random_number and result == calculated_result):
  # print("Verified!")
  print("WIN" if result else "LOSE")
else:
  if (not isvalid_merkle):
    print("Merkle proof is invalid.")
  if (not isvalid_random_number):
    print("The random number is invalid.")