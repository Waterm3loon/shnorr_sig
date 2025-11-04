from ecdsa import SECP256k1
from ecdsa.ellipticcurve import Point
import hashlib
import random 

curve = SECP256k1.curve
G = SECP256k1.generator
n = SECP256k1.order

def generate_keypair():
    d = random.randrange(1, n)
    P = d * G
    return d, P

def point_to_ser(point, compressed=True):
    if compressed:
        prefix = b'\x02' if point.y() % 2 == 0 else b'\x03'
        return prefix + point.x().to_bytes(32, 'big')
    else:
        return b'\x04' + point.x().to_bytes(32, 'big') + point.y().to_bytes(32, 'big')

def sign(message: bytes, d: int) -> tuple:
    k = random.randrange(1, n)
    R = k * G
    P = d * G
    R_ser = point_to_ser(R)
    P_ser = point_to_ser(P)
    e_bytes = hashlib.sha256(R_ser + P_ser + message).digest()
    e = int.from_bytes(e_bytes, 'big') % n
    s = (k + e * d) % n
    return R, s

def verify(message: bytes, P: Point, R: Point, s: int) -> bool:
    R_ser = point_to_ser(R)
    P_ser = point_to_ser(P)
    e_bytes = hashlib.sha256(R_ser + P_ser + message).digest()
    e = int.from_bytes(e_bytes, 'big') % n
    left = s * G
    right = R + (e * P)
    return left == right

d, P = generate_keypair()
message = b'Hello, Schnorr!'
R, s = sign(message, d)
print("Signature valid:", verify(message, P, R, s))