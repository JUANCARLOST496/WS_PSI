class CSHelper:

    def __init__(self):
        self.imp_name = None
        self.cs = None

    def encrypt(self, plaintext):
        raise NotImplementedError

    def decrypt(self, ciphertext):
        raise NotImplementedError

    def generate_keys(self):
        raise NotImplementedError

    def serialize_public_key(self):
        raise NotImplementedError

    def reconstruct_public_key(self, public_key_dict):
        raise NotImplementedError

    def get_encrypted_set(self, serialized_encrypted_set, public_key):  # From the peer
        raise NotImplementedError

    def get_encrypted_list(self, serialized_encrypted_list, public_key):  # From the peer
        raise NotImplementedError

    def encrypt_my_data(self, my_set, domain):
        raise NotImplementedError

    def get_multiplied_set(self, enc_set, node_set):
        raise NotImplementedError

    def multiply_encrypted_sets(self, encrypted_set1, encrypted_set2):
        raise NotImplementedError

    def eval_coefficients(self, coeffs, pubkey, my_data):
        raise NotImplementedError

    def horner_encrypted_eval(self, coeffs, x):
        raise NotImplementedError

    def intersection_enc_size(self, multiplied_set):
        raise NotImplementedError

    def get_ciphertext(self, encrypted_number):
        raise NotImplementedError

    def get_evaluations(self, coeffs, pubkey, my_data):
        raise NotImplementedError

    def serialize_result(self, result, type):
        raise NotImplementedError
