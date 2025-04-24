import random
import math
from hashlib import sha256

def is_prime(n):    #Miller-Rabin Algorithm https://www.geeksforgeeks.org/primality-test-set-3-miller-rabin/

    if n <= 1:
        return False
    if n <= 3:
        return True
    if n % 2 == 0 or n % 3 == 0:
        return False

    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2

    def miller_rabin_trial(a, d, n):
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            return True
        while d != n - 1:
            x = (x * x) % n
            d *= 2
            if x == n - 1:
                return True
            if x == 1:
                return False
        return False

    k = 5
    for _ in range(k):
        a = random.randint(2, n - 2)
        if not miller_rabin_trial(a, d, n):
            return False
    return True

def generate_prime(bits):
    while True:
        n = random.getrandbits(bits) | (1 << bits - 1) | 1
        if is_prime(n):
            return n

def extended_gcd(a, b): # Extended Euclidean Algorithm
    if a == 0:
        return b, 0, 1
    gcd, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return gcd, x, y

def mod_inverse(e, phi):
    gcd, x, _ = extended_gcd(e, phi)
    if gcd != 1:
        raise ValueError("Modular inverse does not exist")
    
    return x % phi

class RSAKey:
    def __init__(self, n, e, d=None):
        self.key_data = {'n': n, 'e': e, 'd': d}

    @property
    def n(self):
        return self.key_data['n']

    @property
    def e(self):
        return self.key_data['e']

    @property
    def d(self):
        return self.key_data['d']

    @property
    def is_private(self):
        return self.key_data['d'] is not None

def generate_keypair(entity_name, size): # Generate RSA key pair for size 1024
    print(f"Generating RSA key pair for {entity_name}")

    p = generate_prime(size)
    q = generate_prime(size)
    
    n = p * q
    phi = (p - 1) * (q - 1)
    
    e = 65537
    d = mod_inverse(e, phi)
    
    public_key = RSAKey(n, e)
    private_key = RSAKey(n, e, d)
    
    return public_key, private_key

def encrypt(message, public_key):
    if isinstance(message, str):
        message = message.encode()
    message_int = int.from_bytes(message, 'big')
    encrypted_int = pow(message_int, public_key.e, public_key.n)
    return encrypted_int

def decrypt(ciphertext, private_key):
    if not private_key.is_private:
        raise ValueError("Cannot decrypt without private key")
    
    plaintext = pow(ciphertext, private_key.d, private_key.n)
    return plaintext.to_bytes((plaintext.bit_length() + 7) // 8, 'big').decode(errors='ignore')

def sign(message, private_key):
    if not private_key.is_private:
        raise ValueError("Cannot sign without private key")
    
    if isinstance(message, str):
        message = message.encode()
        
    hash_value = int.from_bytes(sha256(message).digest(), 'big')

    signature = pow(hash_value, private_key.d, private_key.n)
    return signature

def verify_signature(message, signature, public_key):
    if isinstance(message, str):
        message = message.encode()
        
    hash_value = int.from_bytes(sha256(message).digest(), 'big')

    decrypted_sig = pow(signature, public_key.e, public_key.n)
    return hash_value == decrypted_sig 