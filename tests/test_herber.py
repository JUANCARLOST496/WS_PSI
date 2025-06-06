import logging
import os
from Crypto.helpers.HerbHelper import HerbHelper, EncryptedNumber
import unittest

class TestHerbHelper(unittest.TestCase):

    def setUp(self):
        self.herb = HerbHelper()

    def test_key_generation(self):
        self.assertIsNotNone(self.herb.private_key)
        self.assertIsNotNone(self.herb.public_key)
        self.assertIsNotNone(self.herb.beacon_seed)

    def test_encrypt_decrypt(self):
        for value in [0, 1, 2, 3, 5]:
            enc = self.herb.encrypt(value, round_number=42)
            dec = self.herb.decrypt(enc)
            self.assertEqual(value, dec)

    def test_encrypt_my_data(self):
        my_set = {1, 3}
        domain = 5
        encrypted_set = self.herb.encrypt_my_data(my_set, domain)
        self.assertEqual(len(encrypted_set), domain)
        for i in range(domain):
            decrypted = self.herb.decrypt(encrypted_set[i])
            expected = 1 if i in my_set else 0
            self.assertEqual(decrypted, expected)

    def test_multiplication_and_decryption(self):
        enc = self.herb.encrypt(1, round_number=10)
        enc2 = enc * 2
        dec = self.herb.decrypt(enc2)
        self.assertEqual(dec, 2)

    def test_get_multiplied_set(self):
        enc_set = self.herb.encrypt_my_data({1, 2}, 4)
        multiplied = self.herb.get_multiplied_set(enc_set, {1})
        self.assertEqual(self.herb.decrypt(multiplied[0]), 0)
        self.assertEqual(self.herb.decrypt(multiplied[1]), 2)
        self.assertEqual(self.herb.decrypt(multiplied[2]), 0)
        self.assertEqual(self.herb.decrypt(multiplied[3]), 0)

    def test_intersection_enc_size(self):
        enc_set = self.herb.encrypt_my_data({0, 2}, 4)
        multiplied = self.herb.get_multiplied_set(enc_set, {2})
        size = self.herb.intersection_enc_size(multiplied)
        self.assertEqual(size, 2)

    def test_serialization_deserialization(self):
        enc = self.herb.encrypt(1, round_number=5)
        ct = self.herb.get_ciphertext(enc)
        restored = self.herb.get_encrypted_list([ct])[0]
        self.assertEqual(enc.c1, restored.c1)
        self.assertEqual(enc.c2, restored.c2)

    def test_serialize_public_key(self):
        data = self.herb.serialize_public_key()
        self.assertIn("y", data)
        self.assertIn("p", data)
        self.assertIn("seed", data)

    def test_reconstruct_public_key(self):
        pub = self.herb.serialize_public_key()
        new_herb = HerbHelper()
        new_herb.reconstruct_public_key(pub)
        self.assertEqual(new_herb.public_key, int(pub["y"]))

if __name__ == '__main__':
    unittest.main()