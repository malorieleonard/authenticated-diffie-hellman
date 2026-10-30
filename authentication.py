from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.exceptions import InvalidSignature


def generate_identity_keypair():
    """
    Generate an Ed25519 identity key pair.
    """
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    return private_key, public_key


def sign_message(private_key, message):
    """
    Sign a message using an Ed25519 private key.
    """
    if not isinstance(private_key, Ed25519PrivateKey):
        raise TypeError("Invalid private signing key.")

    if not isinstance(message, bytes):
        raise TypeError("Message must be bytes.")

    return private_key.sign(message)


def verify_signature(public_key, message, signature):
    """
    Verify an Ed25519 digital signature.

    Return True for a valid signature and False
    for an invalid signature.
    """
    if not isinstance(public_key, Ed25519PublicKey):
        raise TypeError("Invalid public verification key.")

    if not isinstance(message, bytes):
        raise TypeError("Message must be bytes.")

    if not isinstance(signature, bytes):
        raise TypeError("Signature must be bytes.")

    try:
        public_key.verify(signature, message)
        return True

    except InvalidSignature:
        return False