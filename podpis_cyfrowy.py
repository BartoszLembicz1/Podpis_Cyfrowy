from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from cryptography.hazmat.primitives import serialization
import random
import sys

def generate_keys(seed=None):
    if seed is not None:
        random.seed(seed)

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()
    return private_key, public_key

def load_seed_from_file(filename):
    with open(filename, 'r') as f:
        seed = int(f.read().strip())
    return seed

def generate_keys_from_seed(seed_file):
    seed = load_seed_from_file(seed_file)
    private_key, public_key = generate_keys(seed)
    return private_key, public_key

def save_private_key(private_key, filename):
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open(filename, 'wb') as key_file:
        key_file.write(pem)

def save_public_key(public_key, filename):
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open(filename, 'wb') as key_file:
        key_file.write(pem)

def sign_file(private_key, file_path):
    with open(file_path, 'rb') as f:
        message = f.read()

    # skrot pliku
    digest = hashes.Hash(hashes.SHA256())
    digest.update(message)
    hashed_message = digest.finalize()

    # podpisanie skrotu
    signature = private_key.sign(
        hashed_message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        Prehashed(hashes.SHA256())
    )
    signature_filename = file_path + ".signature"
    with open(signature_filename, 'wb') as sig_file:
        sig_file.write(signature)
    return signature

def load_private_key(filename):
    with open(filename, 'rb') as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
        )
    return private_key

def load_public_key(filename):
    with open(filename, 'rb') as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read(),
        )
    return public_key

def verify_signature(public_key, file_path, signature_path):
    with open(file_path, 'rb') as f:
        message = f.read()

    # skrot pliku
    digest = hashes.Hash(hashes.SHA256())
    digest.update(message)
    hashed_message = digest.finalize()

    with open(signature_path, 'rb') as sig_file:
        signature = sig_file.read()

    # sprawdzenie podpisu
    try:
        public_key.verify(
            signature,
            hashed_message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            Prehashed(hashes.SHA256())
        )
        print("Podpis jest zgodny")
    except:
        print("Podpis jest niezgodny")

sys.set_int_max_str_digits(100000000)
file_path = "plik.txt"
signature_path = "plik.txt.signature"
seed_file = "seed.txt"
while True:
        print("\nOpcje:")
        print("1. Wygeneruj klucze")
        print("2. Podpisz plik: plik.txt")
        print("3. Zweryfikuj podpis pliku: plik.txt")
        choice = input("Wybierz opcję: ")

        if choice == '1':
            private_key, public_key = generate_keys_from_seed(seed_file)
            save_private_key(private_key, "private_key.pem")
            save_public_key(public_key, "public_key.pem")
            print("Klucze zostały wygenereowane i zapisane")

        elif choice == '2':
            try:
                private_key = load_private_key("private_key.pem")
                signature = sign_file(private_key, file_path)
                print("Plik został podpisany")
            except:
                print("Błąd pliku klucza prywatnego lub pliku do podpisania")
        elif choice == '3':
            try:
                public_key = load_public_key("public_key.pem")
                verify_signature(public_key, file_path, signature_path)
            except:
                print("Błąd pliku klucza, pliku z podpisem lub pliku do weryfikacji")