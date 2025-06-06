import unittest
from Crypto.helpers.ScrapeHelper import ScrapeHelper, EncryptedNumber

class TestScrapeHelper(unittest.TestCase):
    def setUp(self):
        self.helper = ScrapeHelper()

    def test_key_generation(self):
        self.assertIsInstance(self.helper.private_key, int)
        self.assertIsInstance(self.helper.public_key, int)
        self.assertEqual(len(self.helper.beacon_seed), 64)  # SHA256 hex length

    def test_generate_random_beacon_deterministic(self):
        r1 = self.helper.generate_random_beacon(0)
        r2 = self.helper.generate_random_beacon(0)
        r3 = self.helper.generate_random_beacon(1)
        self.assertEqual(r1, r2)
        self.assertNotEqual(r1, r3)

    def test_encrypt_decrypt_basic(self):
        number = 42
        enc = self.helper.encrypt(number, round_number=5)
        dec = self.helper.decrypt(enc)
        self.assertEqual(dec, number)

    def test_encrypted_number_mul(self):
        enc1 = self.helper.encrypt(10, round_number=2)
        enc2 = enc1 * 3
        # Decrypt enc1 * 3 should equal 10 * 3 = 30
        dec = self.helper.decrypt(enc2)
        self.assertEqual(dec, 30)

    def test_encrypt_my_data_and_get_multiplied_set(self):
        my_set = {1, 3, 5}
        domain = 6
        encrypted_set = self.helper.encrypt_my_data(my_set, domain)
        self.assertEqual(len(encrypted_set), domain)

        node_set = {3, 4}
        multiplied = self.helper.get_multiplied_set(encrypted_set, node_set)

        for el in multiplied:
            self.assertIsInstance(multiplied[el], EncryptedNumber)

    def test_intersection_enc_size(self):
        # Create encrypted set for {1,2} in domain 4
        my_set = {1, 2}
        domain = 4
        enc_set = self.helper.encrypt_my_data(my_set, domain)
        node_set = {1, 3}
        multiplied = self.helper.get_multiplied_set(enc_set, node_set)

        size = self.helper.intersection_enc_size(multiplied)
        # Según la multiplicación por 2 para elementos en node_set, 
        # tamaño esperado es 3: 
        # 1 (en intersección) * 2 + 2 (solo en my_set) * 1 = 3
        self.assertEqual(size, 2)

    def test_serialize_and_deserialize(self):
        number = 10
        enc = self.helper.encrypt(number, round_number=1)
        serialized = self.helper.get_ciphertext(enc)

        # Simulate dict of serialized
        ser_dict = {"0": serialized}
        deserialized = self.helper.get_encrypted_set(ser_dict)
        self.assertIsInstance(deserialized["0"], EncryptedNumber)
        self.assertEqual(deserialized["0"].c1, enc.c1)
        self.assertEqual(deserialized["0"].c2, enc.c2)

        ser_list = [serialized]
        deserialized_list = self.helper.get_encrypted_list(ser_list)
        self.assertIsInstance(deserialized_list[0], EncryptedNumber)
        self.assertEqual(deserialized_list[0].c1, enc.c1)
        self.assertEqual(deserialized_list[0].c2, enc.c2)

if __name__ == "__main__":
    unittest.main()




