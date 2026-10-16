
# RSA Digital Signature System

## Project Description

This project demonstrates RSA digital signatures in Python. A sender signs a message using an RSA private key, and the signature is checked using the corresponding public key.

## Features

- Generate and save an RSA public/private key pair.
- Sign messages using RSA-PSS and SHA-256.
- Display the generated signature in hexadecimal format.
- Allow the signature to be manually modified.
- Verify a signature against a message.
- Detect modified signatures and modified messages.
- Display whether a signature is valid or invalid.
- Load previously generated keys.

## Requirements

- Python 3
- cryptography library

Install the dependency:

```bash
python -m pip install cryptography
```

## How to Run

```bash
python main.py
```

Choose whether to generate new keys or load existing keys. Enter a message to sign. The program displays the signature and allows you to submit a signature for verification.

Press Enter at the signature prompt to use the original signature. To test tampering, change a character in the signature or change the message being verified.

## How Digital Signatures Work

1. The message is hashed using SHA-256.
2. The hash is signed using the sender's RSA private key.
3. The receiver verifies the signature using the sender's public key.
4. If verification succeeds, the signature matches the message and public key. If the message or signature has been modified, verification fails.

The program uses RSA-PSS padding, a modern signature scheme supported by the cryptography library.

## Test Results

- Original message and signature: valid.
- Modified signature: invalid.
- Modified message: invalid.

## Security Notes

The private key is saved without password protection for this educational demonstration. It must not be shared or uploaded to a public repository. The generated output directory should remain local.

## Author

Information Security coursework project.
