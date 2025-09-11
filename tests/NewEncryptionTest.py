#This is a test script to replace c2_PublicKeyAggregator.py and p3_ReducedSecurityKeyCipher.py using a new encryption method.
#Each participant encrypts his Bitcoin private key with a lower security than secp256k1.

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

# Rebuild di from vi and ki
di_reconstructed = (vi << 128) | ki
print("di and di_reconstructed are equal:", di == di_reconstructed)

##### vi and ki encryption #####

# Secp192r1 curve and generator
curve = registry.get_curve('secp192r1')
generator = curve.g

# Multiply vi by generator
pub_point_vi = vi * generator

# Multiply ki by generator
pub_point_ki = ki * generator


# Serialize vi point
x_bytes_vi = pub_point_vi.x.to_bytes(24, byteorder='big')
y_bytes_vi = pub_point_vi.y.to_bytes(24, byteorder='big')
encoded_point_vi = b'\x04' + x_bytes_vi + y_bytes_vi

public_key_vi = ec.EllipticCurvePublicKey.from_encoded_point(
    ec.SECP192R1(),
    encoded_point_vi
)
compressed_bytes_vi = public_key_vi.public_bytes(
    encoding=serialization.Encoding.X962,
    format=serialization.PublicFormat.CompressedPoint
)
print("secp192r1 pubkey vi (compressed):", compressed_bytes_vi.hex())

# Serialize ki point
x_bytes_ki = pub_point_ki.x.to_bytes(24, byteorder='big')
y_bytes_ki = pub_point_ki.y.to_bytes(24, byteorder='big')
encoded_point_ki = b'\x04' + x_bytes_ki + y_bytes_ki

public_key_ki = ec.EllipticCurvePublicKey.from_encoded_point(
    ec.SECP192R1(),
    encoded_point_ki
)
compressed_bytes_ki = public_key_ki.public_bytes(
    encoding=serialization.Encoding.X962,
    format=serialization.PublicFormat.CompressedPoint
)
print("secp192r1 pubkey ki (compressed):", compressed_bytes_ki.hex())


### Now check the corresponding relation
# secp256k1 generator point
generator_bytes = bytes.fromhex(
    "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
)
generator = PublicKey(generator_bytes)

# vi to secp256k1 range
vi_scaled = vi * (2 ** 128) % SECP256K1_N

# Get public keys
Pvi = PublicKey.from_valid_secret(vi_scaled.to_bytes(32, 'big'))
Pki = PublicKey.from_valid_secret(ki.to_bytes(32, 'big'))

# Combine points
Pi = PublicKey.combine_keys([Pvi, Pki])

print("secp256k1 pubkeys are equal?:", Pi.format().hex() == public_key_from_wif)

