import unittest

from authentication import (
    generate_identity_keypair,
    sign_message,
    verify_signature,
)


class TestAuthentication(unittest.TestCase):

    def test_generate_keypair(self):
        private_key, public_key = generate_identity_keypair()

        self.assertIsNotNone(private_key)
        self.assertIsNotNone(public_key)

    def test_valid_signature(self):
        private_key, public_key = generate_identity_keypair()

        message = b"Hello Bob"

        signature = sign_message(private_key, message)

        self.assertTrue(
            verify_signature(public_key, message, signature)
        )

    def test_modified_message(self):
        private_key, public_key = generate_identity_keypair()

        signature = sign_message(private_key, b"Hello Bob")

        self.assertFalse(
            verify_signature(public_key, b"Hello Eve", signature)
        )

    def test_wrong_public_key(self):
        alice_private, _ = generate_identity_keypair()
        _, bob_public = generate_identity_keypair()

        message = b"Hello Bob"

        signature = sign_message(alice_private, message)

        self.assertFalse(
            verify_signature(bob_public, message, signature)
        )

    def test_invalid_signature(self):
        private_key, public_key = generate_identity_keypair()

        message = b"Hello Bob"

        signature = bytearray(sign_message(private_key, message))
        signature[0] ^= 1

        self.assertFalse(
            verify_signature(public_key, message, bytes(signature))
        )

    def test_message_must_be_bytes(self):
        private_key, _ = generate_identity_keypair()

        with self.assertRaises(TypeError):
            sign_message(private_key, "Hello Bob")

    def test_signature_must_be_bytes(self):
        _, public_key = generate_identity_keypair()

        with self.assertRaises(TypeError):
            verify_signature(public_key, b"Hello Bob", "invalid")

    def test_wrong_private_key_type(self):
        with self.assertRaises(TypeError):
            sign_message("not a key", b"Hello Bob")

    def test_wrong_public_key_type(self):
        with self.assertRaises(TypeError):
            verify_signature("not a key", b"Hello Bob", b"signature")


if __name__ == "__main__":
    unittest.main()