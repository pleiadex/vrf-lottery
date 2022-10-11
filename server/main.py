# python 2.7
import os, sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from vrf import *
from flask import Flask
from flask import request
from merkletools import MerkleTools
from vrf import *
import struct
from cryptography.hazmat.primitives.asymmetric import rsa


# Initialize merkle tree
mt = MerkleTools()
mt_index = -1

app = Flask(__name__)

@app.route('/', methods=['GET'])
def index():
  return 'send request to /item?data=...'

@app.route('/item', methods=['GET'])
def get_random_number():
  global mt_index

  total = 10
  win = 5

  # Get random data
  data = request.args.get('data')

  # Add merkle leaf
  # TODO: reset merkle tree if it is too big
  mt.add_leaf(data, True)
  mt.make_tree()
  mt_index += 1

  # Get merkle root
  alpha = str(mt.get_merkle_root())

  # VRF
  private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend())
  private_numbers = private_key.private_numbers()
  public_key = private_key.public_key()
  public_numbers = public_key.public_numbers()
  n = public_numbers.n
  e = public_numbers.e
  d = private_numbers.d
  k = 20
  public_key = RsaPublicKey(n, e)
  private_key = RsaPrivateKey(n, d)

  pi = VRF_prove(private_key, alpha, k)
  beta = VRF_proof2hash(pi)

  beta_format = '>' + 'H' * 10
  pi_format = '>' + 'H' * 128
  beta_unpack = struct.unpack(beta_format, beta)
  try:
    pi_unpack = struct.unpack(pi_format, pi)
  except:
    print(list(pi))
    pi_unpack = (0, 0, 0, 0, 0, 0, 0, 0, 0, 0)

  result = beta_unpack[9] % total < win

  # return 1) merkleproof, 2) random value, pi 3) probability
  return {
    "merkle_tree": 
    {
      "merkle_proof": mt.get_proof(mt_index),
      "merkle_root": mt.get_merkle_root()
    },
    "vrf": 
    {
      "random_number": beta_unpack, 
      "random_number_proof": pi_unpack,
      "k": k,
      "n": n,
      "e": e
    },
    "probability": 
    {
      "total": total,
      "win": win
    },
    "result": result
  }