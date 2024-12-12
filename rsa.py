from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes

def generate_keys():
    """Generate RSA private and public keys."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()
    return private_key, public_key

def encrypt_message(message: str, public_key):
    """Encrypt a message using the public key."""
    ciphertext = public_key.encrypt(
        message.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext

def decrypt_message(ciphertext: bytes, private_key):
    """Decrypt a ciphertext using the private key."""
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext.decode()

def main():
    # Generate RSA key pair
    private_key, public_key = generate_keys()

    # Serialize keys (optional, to demonstrate how to store and load keys)
    pem_private_key = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    pem_public_key = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    print("Private Key:")
    print(pem_private_key.decode())

    print("Public Key:")
    print(pem_public_key.decode())

    # Get user input for the message
    message = input("Enter the message you want to encrypt: ")
    print(f"Original Message: {message}")

    # Encrypt the message
    ciphertext = encrypt_message(message, public_key)
    print(f"Encrypted Message: {ciphertext}")

    # Decrypt the message
    decrypted_message = decrypt_message(ciphertext, private_key)
    print(f"Decrypted Message: {decrypted_message}")

if __name__ == "__main__":
    main()
