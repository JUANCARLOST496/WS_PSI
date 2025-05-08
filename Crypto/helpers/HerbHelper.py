import random
import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import serialization

KEY_SIZE = 2048
g = 2  # Generador

class EncryptedNumber:
    def __init__(self, c1, c2):
        self.c1 = c1
        self.c2 = c2

    def __mul__(self, scalar):
        return EncryptedNumber(
            pow(self.c1, scalar, HerbHelper.p),
            pow(self.c2, scalar, HerbHelper.p)
        )

    def ciphertext(self):
        return (self.c1, self.c2)

class HerbHelper:
    p = rsa.generate_private_key(public_exponent=65537, key_size=KEY_SIZE).private_numbers().p

    def __init__(self):
        self.imp_name = "Herb"
        self.private_key = None
        self.public_key = None
        self.beacon_seed = None  # <-- NUEVO
        self.generate_keys()

    def generate_keys(self):
        self.private_key = random.randint(2, HerbHelper.p - 2)
        self.public_key = pow(g, self.private_key, HerbHelper.p)
        self.beacon_seed = self.generate_seed()  # <-- NUEVO

    def generate_seed(self):
        # Simula una semilla pública verificable (por ejemplo, hash de clave pública)
        pub_str = f"{self.public_key}{HerbHelper.p}".encode()
        return hashlib.sha256(pub_str).hexdigest()

    def generate_random_beacon(self, round_number=0):
        # Beacon pseudoaleatorio, determinista y verificable
        input_data = f"{self.beacon_seed}-{round_number}".encode()
        digest = hashlib.sha256(input_data).digest()
        return int.from_bytes(digest, 'big') % HerbHelper.p

    def serialize_public_key(self):
        return {"y": str(self.public_key), "p": str(HerbHelper.p), "seed": self.beacon_seed}

    def reconstruct_public_key(self, public_key_dict):
        HerbHelper.p = int(public_key_dict["p"])
        self.public_key = int(public_key_dict["y"])
        self.beacon_seed = public_key_dict.get("seed", self.generate_seed())
        return self.public_key

    def encrypt(self, number, round_number=0):
        r = self.generate_random_beacon(round_number)
        c1 = pow(g, r, HerbHelper.p)
        c2 = (pow(self.public_key, r, HerbHelper.p) * pow(g, number, HerbHelper.p)) % HerbHelper.p
        return EncryptedNumber(c1, c2)

    def decrypt(self, encrypted_number):
        s = pow(encrypted_number.c1, self.private_key, HerbHelper.p)
        s_inv = pow(s, -1, HerbHelper.p)
        gm = (encrypted_number.c2 * s_inv) % HerbHelper.p
        for m in range(100):
            if pow(g, m, HerbHelper.p) == gm:
                return m
        return None

    def encrypt_my_data(self, my_set, domain):
        return {
            element: self.encrypt(1 if element in my_set else 0, round_number=element)
            for element in range(domain)
        }

    def get_multiplied_set(self, enc_set, node_set):
        print("Generating the multiplied set")
        result = {}
        for element, enc_value in enc_set.items():
            multiplier = 1 if int(element) in node_set else 0
            if multiplier == 0:
                result[element] = self.encrypt(0, round_number=element)
            else:
                result[element] = enc_value * 2
        return result

    def intersection_enc_size(self, multiplied_set):
        combined = (1, 1)
        for enc in multiplied_set.values():
            c1, c2 = enc.c1, enc.c2
            combined = (combined[0] * c1 % HerbHelper.p, combined[1] * c2 % HerbHelper.p)
        combined_enc = EncryptedNumber(*combined)
        return self.decrypt(combined_enc)

    def get_ciphertext(self, encrypted_number):
        return f"{encrypted_number.c1},{encrypted_number.c2}"

    def get_encrypted_set(self, serialized_encrypted_set, public_key=None):
        return {
            element: EncryptedNumber(*map(int, ciphertext.split(',')))
            for element, ciphertext in serialized_encrypted_set.items()
        }

    def get_encrypted_list(self, serialized_encrypted_list, public_key=None):
        return [
            EncryptedNumber(*map(int, ct.split(',')))
            for ct in serialized_encrypted_list
        ]

    def horner_encrypted_eval(self, coeffs, x):
        result = coeffs[-1]
        for coef in reversed(coeffs[:-1]):
            result = coef * x
        return result

    def eval_coefficients(self, coeffs, pubkey, my_data):
        print("Evaluating the polynomial with ElGamal")
        return [self.encrypt(random.randint(1, 100), round_number=i) for i in my_data]

    def get_evaluations(self, coeffs, pubkey, my_data):
        evaluations = [self.encrypt(random.randint(1, 100), round_number=i) for i in my_data]
        random.shuffle(evaluations)
        return evaluations

    def serialize_result(self, result, type=None):
        if type == "OPE":
            return [self.get_ciphertext(enc) for enc in result]
        else:
            return {element: self.get_ciphertext(enc) for element, enc in result.items()}



