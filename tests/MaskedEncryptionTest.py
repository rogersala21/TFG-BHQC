#This is a test script to replace c2_PublicKeyAggregator.py and p3_ReducedSecurityKeyCipher.py using a new encryption method.
#To enlarge the effective search range on secp192r1 while preserving the public-key relation, each participant takes randomly a mask ai ∈ {0, 1, . . . , 2t − 1}
#Each participant encrypts his Bitcoin private key with a lower security than secp256k1.

import secrets
from bitcoinutils.keys import PrivateKey
from tinyec import registry
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from coincurve import PublicKey


# secp256k1 order
SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

# Transform WIF to integer
def wif_to_int(wif):
    priv = PrivateKey(wif)
    priv_bytes = priv.to_bytes()
    di = int.from_bytes(priv_bytes, 'big')
    print("di:", di)
    return di

# Split di into vi (128 msb) and ki (128 lsb)
def split_di(di):
    vi = di >> 128
    ki = di & ((1 << 128) - 1)
    return vi, ki

# Test
wif = 'cRBU4t4wEqYEHkQYtSeNPuJhKag1ThaMY6sLTmvKvNCcjpGQNry6'
public_key_from_wif = PrivateKey(wif).get_public_key().to_hex()
di = wif_to_int(wif)
vi, ki = split_di(di)
print("vi:", vi)
print("ki:", ki)

# add random mask a
t = 64  # mask bitlength
a = secrets.randbelow(1 << t)
print("mask a:", a)

# build padded shares
v = vi + a
k = (ki - (1 << 128) * a) % SECP256K1_N
print("padded v:", v)
print("padded k:", k)


##### v and k encryption #####

# Secp192r1 curve and generator
curve = registry.get_curve('secp192r1')
generator = curve.g

# Multiply v by generator
pub_point_v = v * generator

# Multiply k by generator
pub_point_k = k * generator

# Serialize v point
x_bytes_v = pub_point_v.x.to_bytes(24, byteorder='big')
y_bytes_v = pub_point_v.y.to_bytes(24, byteorder='big')
encoded_point_v = b'\x04' + x_bytes_v + y_bytes_v

public_key_v = ec.EllipticCurvePublicKey.from_encoded_point(
    ec.SECP192R1(),
    encoded_point_v
)
compressed_bytes_v = public_key_v.public_bytes(
    encoding=serialization.Encoding.X962,
    format=serialization.PublicFormat.CompressedPoint
)
print("secp192r1 pubkey v (compressed):", compressed_bytes_v.hex())

# Serialize k point
x_bytes_k = pub_point_k.x.to_bytes(24, byteorder='big')
y_bytes_k = pub_point_k.y.to_bytes(24, byteorder='big')
encoded_point_k = b'\x04' + x_bytes_k + y_bytes_k

public_key_k = ec.EllipticCurvePublicKey.from_encoded_point(
    ec.SECP192R1(),
    encoded_point_k
)
compressed_bytes_k = public_key_k.public_bytes(
    encoding=serialization.Encoding.X962,
    format=serialization.PublicFormat.CompressedPoint
)
print("secp192r1 pubkey k (compressed):", compressed_bytes_k.hex())

### Now check the corresponding relation
# secp256k1 generator point
generator_bytes = bytes.fromhex(
    "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
)
generator = PublicKey(generator_bytes)

# v scaled
v_scaled = (v * (2 ** 128)) % SECP256K1_N

# Get public keys
Pvi = PublicKey.from_valid_secret(v_scaled.to_bytes(32, 'big'))
Pki = PublicKey.from_valid_secret(k.to_bytes(32, 'big'))

# Combine points
Pi = PublicKey.combine_keys([Pvi, Pki])

print("secp256k1 pubkeys are equal?:", Pi.format().hex() == public_key_from_wif)
