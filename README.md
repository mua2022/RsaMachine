# RSA Encryption Script

This script demonstrates the use of RSA encryption and decryption in Python. It will allow you to:

1. Generate RSA private and public keys.
2. Encrypt a message using the RSA public key.
3. Decrypt the encrypted message using the RSA private key.

## Features

- **Key Generation**: Dynamically generates RSA key pairs.
- **Encryption**: Uses the RSA public key to encrypt messages securely.
- **Decryption**: Uses the RSA private key to decrypt messages accurately.
- **User Interaction**: Accepts user input for the message to encrypt.

## Prerequisites

Ensure you have Python installed on your system. This script requires the `cryptography` library, which can be installed as follows:

```bash
pip install cryptography
```

## How to Use

1. Clone or download the script to your local machine.
2. Open a terminal or command prompt and navigate to the directory containing the script.
3. Run the script using Python:

   ```bash
   python rsa_encode_decode.py
   ```

4. Follow the prompts:
   - Enter a message when prompted.
   - The script will display the generated RSA keys, the encrypted message, and the decrypted message.

## Example Output

```plaintext
Private Key:
-----BEGIN PRIVATE KEY-----
...
-----END PRIVATE KEY-----

Public Key:
-----BEGIN PUBLIC KEY-----
...
-----END PUBLIC KEY-----

Enter the message you want to encrypt: Hello, RSA!
Original Message: Hello, RSA!
Encrypted Message: b'\x1d\xa5...\xa4\x3b'
Decrypted Message: Hello, RSA!
```

## Customization

- Modify the script to save the keys to files for reuse.
- Change the key size or encryption settings to suit your security requirements.

## Notes

- The `cryptography` library uses industry-standard algorithms and practices, ensuring secure encryption.
- This example is intended for educational purposes; always follow best practices when implementing cryptographic systems in production.

## Troubleshooting

- If you encounter a `ModuleNotFoundError`, ensure the `cryptography` library is installed:
  ```bash
  pip install cryptography
  ```
- For any other issues, consult the [cryptography documentation](https://cryptography.io/en/latest/).

## License

This script is provided under the MIT License. Feel free to use and modify it as needed.

### Quote of the Day 

Every successful person started somewhere and kept pushing, maybe the next project i will be doing with you haha and be the next Rivest, Shamir & Addleman 