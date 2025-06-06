import random
import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa

KEY_SIZE = 2048
g = 2  # Generador global

class EncryptedNumber:
    def __init__(self, c1, c2):
        self.c1 = c1
        self.c2 = c2

    def __mul__(self, scalar):
        # Multiplicación homomórfica: (c1,c2)^scalar = (c1^scalar, c2^scalar)
        return EncryptedNumber(
            pow(self.c1, scalar, ScrapeHelper.p),
            pow(self.c2, scalar, ScrapeHelper.p)
        )

    def ciphertext(self):
        return (self.c1, self.c2)


class ScrapeHelper:
    # --------------------------------------------------------------------
    # 1) Generamos 'p' a partir del primo interno de una clave RSA de 2048 bits,
    #    tal como hacía la versión original de HerbHelper.
    # --------------------------------------------------------------------
    p = rsa.generate_private_key(public_exponent=65537, key_size=KEY_SIZE).private_numbers().p

    def __init__(self):
        self.imp_name = "Scrape"
        self.private_key = None
        self.public_key = None
        self.beacon_seed = None   # <-- semilla pública verificable (SCRAPE)
        self.generate_keys()

    def generate_keys(self):
        """
        - Creamos la clave privada x de ElGamal (un entero entre [2, p-2]).
        - Calculamos la clave pública y = g^x mod p.
        - Generamos beacon_seed = SHA256(y || p), que cualquiera puede verificar.
        """
        self.private_key = random.randint(2, ScrapeHelper.p - 2)
        self.public_key = pow(g, self.private_key, ScrapeHelper.p)

        # Beacon seed público verificable (SHA-256 de “public_key || p”)
        pub_str = f"{self.public_key}{ScrapeHelper.p}".encode()
        self.beacon_seed = hashlib.sha256(pub_str).hexdigest()

    def generate_random_beacon(self, round_number=0):
        """
        ----------------------------------------------------------------------
        SCRAPE-style: Beacon pseudoaleatorio, determinista y verificable.
        Hacemos SHA-256(beacon_seed || "-" || round_number) y luego módulo p,
        para obtener un entero 0 <= r < p de forma determinista.
        ----------------------------------------------------------------------
        """
        input_data = f"{self.beacon_seed}-{round_number}".encode()
        digest = hashlib.sha256(input_data).digest()
        return int.from_bytes(digest, 'big') % ScrapeHelper.p

    def serialize_public_key(self):
        """
        Formato de salida idéntico a antes:
          { "y": <public_key>, "p": <p>, "seed": <beacon_seed> }
        De este modo, cualquier otro peer que reciba este dict
        sabrá “p”, “g” (implícito=2) y “y”, y podrá verificar beacon_seed.
        """
        return {
            "y": str(self.public_key),
            "p": str(ScrapeHelper.p),
            "seed": self.beacon_seed
        }

    def reconstruct_public_key(self, public_key_dict):
        """
        Reconstruye p, public_key y beacon_seed de un dict recibido.
        Esto debe devolver self.public_key para que quede listo para encriptar.
        """
        ScrapeHelper.p = int(public_key_dict["p"])
        self.public_key = int(public_key_dict["y"])
        # Si el dict tiene “seed”, la usamos; si no, regeneramos porque
        # en teoría la semilla es SHA256(y||p), pero aquí preferimos tomar la que mandaron.
        self.beacon_seed = public_key_dict.get("seed", self.generate_random_beacon(0))
        return self.public_key

    def encrypt(self, number, round_number=0):
        """
        ------------------------------------------------------------------------
        Cifra un entero 'number' con ElGamal, usando r = generate_random_beacon(round_number).
        SALIDA: EncryptedNumber(c1, c2), idéntico en formato a la versión original.
        ------------------------------------------------------------------------
        """
        # 1) r determinista a partir del beacon + round_number
        r = self.generate_random_beacon(round_number)

        # 2) c1 = g^r mod p
        c1 = pow(g, r, ScrapeHelper.p)
        # 3) c2 = (y^r * g^number) mod p
        c2 = (pow(self.public_key, r, ScrapeHelper.p) * pow(g, number, ScrapeHelper.p)) % ScrapeHelper.p

        return EncryptedNumber(c1, c2)

    def decrypt(self, encrypted_number):
        """
        Descifra el EncryptedNumber (c1,c2) asumiendo que el mensaje m < 100.
        - Calculamos s = c1^x mod p
        - gm = c2 * s^{-1} mod p = g^m (si todo coincide)
        - Buscamos m << 100 por fuerza bruta
        """
        s = pow(encrypted_number.c1, self.private_key, ScrapeHelper.p)
        s_inv = pow(s, -1, ScrapeHelper.p)
        gm = (encrypted_number.c2 * s_inv) % ScrapeHelper.p

        for m in range(100):
            if pow(g, m, ScrapeHelper.p) == gm:
                return m
        return None

    def encrypt_my_data(self, my_set, domain):
        """
        Para cada elemento ∈ {0,1,...,domain-1}, ciframos:
          - 1  si elemento ∈ my_set
          - 0  si no está
        Usamos round_number = element para que cada cifra sea determinista (SCRAPE).
        Salida idéntica: devuelve { element: EncryptedNumber }.
        """
        return {
            element: self.encrypt(1 if element in my_set else 0, round_number=element)
            for element in range(domain)
        }

    def get_multiplied_set(self, enc_set, node_set):
        """
        Para cada elemento en enc_set:
          - si element ∈ node_set → devuelvo enc_set[element] * 2
          - si no → cifro 0 con round_number=element
        SALIDA: { element: EncryptedNumber } idéntico al original.
        """
        result = {}
        for element, enc_value in enc_set.items():
            if int(element) in node_set:
                # Homomórficamente: (c1,c2)^2 = (c1^2, c2^2)
                result[element] = enc_value * 2
            else:
                # Ciframos 0 de forma determinista con SCRAPE (round=element)
                result[element] = self.encrypt(0, round_number=element)
        return result

    def intersection_enc_size(self, multiplied_set):
        """
        Homomórficamente multiplica todos los (c1,c2) de multiplied_set,
        obteniendo un solo ciphertext (combined_c1, combined_c2).
        Luego se descifra en [0, 100) para hallar el tamaño de la intersección.
        Salida: entero ∈ [0,100) o None.
        """
        combined = (1, 1)
        for enc in multiplied_set.values():
            c1, c2 = enc.c1, enc.c2
            combined = (
                (combined[0] * c1) % ScrapeHelper.p,
                (combined[1] * c2) % ScrapeHelper.p
            )
        combined_enc = EncryptedNumber(*combined)
        return self.decrypt(combined_enc)

    def get_ciphertext(self, encrypted_number):
        """
        Serializa un EncryptedNumber como "c1,c2".
        Salida idéntica a la versión original.
        """
        return f"{encrypted_number.c1},{encrypted_number.c2}"

    def get_encrypted_set(self, serialized_encrypted_set, public_key=None):
        """
        Reconstruye un dict { element: EncryptedNumber } a partir de 
        { element: "c1,c2" }.
        Salida idéntica al original.
        """
        return {
            element: EncryptedNumber(*map(int, ciphertext.split(',')))
            for element, ciphertext in serialized_encrypted_set.items()
        }

    def get_encrypted_list(self, serialized_encrypted_list, public_key=None):
        """
        Reconstruye una lista de EncryptedNumber desde ["c1,c2", ...].
        Salida idéntica al original.
        """
        return [
            EncryptedNumber(*map(int, ct.split(',')))
            for ct in serialized_encrypted_list
        ]

    def horner_encrypted_eval(self, coeffs, x):
        """
        Evaluación homomórfica de un polinomio en x (int) usando Horner:
        - coeffs: lista de EncryptedNumber que representan los coeficientes.
        - x: entero en claro.
        Resultado = coeffs[0] * x^{n-1} + coeffs[1] * x^{n-2} + ... + coeffs[n-1].
        Pero en el esquema homomórfico: 
          - Multiplicar un ciphertext E(...) por x = elevar a x.
          - Sumar ciphertexts = multiplicar componente a componente.
        Salida: un solo EncryptedNumber.
        """
        result = coeffs[-1]
        for coef in reversed(coeffs[:-1]):
            result = coef + (result * x)
        return result

    def eval_coefficients(self, coeffs, pubkey, my_data):
        """
        Simulación de evaluación homomórfica de un polinomio para cada elemento ∈ my_data.
        Aquí ya no uso random.randint(...), sino SCRAPE:
          r = generate_random_beacon(round_number = el índice de elemento)
        Luego calculo:
          ej = horner_encrypted_eval(coeffs, element)
          e_elem = encrypt(element, round_number=element)
          dejo como salida e_elem + (ej * r)
        Salida: lista de EncryptedNumber, misma forma que en la versión original.
        """
        evaluations = []
        for element in my_data:
            # r determinista SCRAPE (en lugar de random.randint)
            r = self.generate_random_beacon(round_number=element)
            ej = self.horner_encrypted_eval(coeffs, element)
            e_elem = self.encrypt(element, round_number=element)
            evaluations.append(e_elem + (ej * r))
        return evaluations

    def get_evaluations(self, coeffs, pubkey, my_data):
        """
        Igual que eval_coefficients, pero mezcla el orden final.
        Salida: lista de EncryptedNumber en orden aleatorio, idéntica al original.
        """
        evaluations = self.eval_coefficients(coeffs, pubkey, my_data)
        random.shuffle(evaluations)
        return evaluations

    def serialize_result(self, result, type=None):
        """
        Si type == "OPE", result es lista de EncryptedNumber → devolvemos ["c1,c2",...].
        Si no, result es dict { element: EncryptedNumber } → devolvemos 
          { element: "c1,c2" }.
        Idéntico a la versión original.
        """
        if type == "OPE":
            return [self.get_ciphertext(enc) for enc in result]
        else:
            return {element: self.get_ciphertext(enc) for element, enc in result.items()}




