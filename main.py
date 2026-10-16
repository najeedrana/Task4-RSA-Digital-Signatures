
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa


OUTPUT_DIR = Path("output")
PRIVATE_KEY_FILE = OUTPUT_DIR / "private_key.pem"
PUBLIC_KEY_FILE = OUTPUT_DIR / "public_key.pem"


def generate_keys():
    """Generate and save an RSA key pair."""
    OUTPUT_DIR.mkdir(exist_ok=True)

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()

    PRIVATE_KEY_FILE.write_bytes(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )

    PUBLIC_KEY_FILE.write_bytes(
        public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )

    return private_key, public_key


def load_keys():
    """Load the saved RSA key pair."""
    private_key = serialization.load_pem_private_key(
        PRIVATE_KEY_FILE.read_bytes(),
        password=None,
    )
    public_key = serialization.load_pem_public_key(
        PUBLIC_KEY_FILE.read_bytes()
    )
    return private_key, public_key


def sign_message(message, private_key):
    """Create an RSA-PSS signature for a message."""
    return private_key.sign(
        message.encode("utf-8"),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )


def verify_signature(message, signature, public_key):
    """Return True if the signature matches the message."""
    try:
        public_key.verify(
            signature,
            message.encode("utf-8"),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        return True
    except InvalidSignature:
        return False


def main():
    print("=== RSA Digital Signature System ===")

    if PRIVATE_KEY_FILE.exists() and PUBLIC_KEY_FILE.exists():
        choice = input(
            "Load existing keys? Enter Y for yes, N for new keys: "
        ).strip().upper()
    else:
        choice = "N"

    try:
        if choice == "Y":
            private_key, public_key = load_keys()
            print("Existing keys loaded.")
        elif choice == "N":
            private_key, public_key = generate_keys()
            print("New RSA key pair generated.")
        else:
            print("Error: Enter Y or N.")
            return
    except (ValueError, TypeError, OSError):
        print("Error: Could not load or generate the RSA keys.")
        return

    message = input("\nEnter the message to sign: ")

    if not message.strip():
        print("Error: Message cannot be empty.")
        return

    signature = sign_message(message, private_key)
    signature_hex = signature.hex()

    print("\nOriginal message:", message)
    print("\nGenerated signature (hex):")
    print(signature_hex)

    modified_signature_hex = input(
        "\nPaste the signature to verify, or press Enter to use "
        "the original signature:\n"
    ).strip()

    if not modified_signature_hex:
        modified_signature_hex = signature_hex

    try:
        modified_signature = bytes.fromhex(modified_signature_hex)
    except ValueError:
        print("\nRESULT: INVALID SIGNATURE — not valid hexadecimal.")
        return

    verification_message = input(
        "\nEnter the message to verify (press Enter to use the original): "
    )
    if verification_message == "":
        verification_message = message

    if verify_signature(
        verification_message,
        modified_signature,
        public_key,
    ):
        print("\nRESULT: VALID SIGNATURE")
    else:
        print("\nRESULT: INVALID SIGNATURE")


if __name__ == "__main__":
    main()
