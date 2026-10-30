import unittest

from protocol import (
    run_authenticated_exchange,
    create_signed_message,
    verify_signed_message,
)
from authentication import generate_identity_keypair


class TestProtocol(unittest.TestCase):

    def test_successful_16_bit_exchange(self):
        result = run_authenticated_exchange(16)

        self.assertTrue(result["authenticated"])
        self.assertTrue(result["shared_secret_match"])

        self.assertEqual(
            result["alice_secret"],
            result["bob_secret"]
        )

    def test_successful_24_bit_exchange(self):
        result = run_authenticated_exchange(24)

        self.assertTrue(result["authenticated"])
        self.assertTrue(result["shared_secret_match"])

    def test_successful_32_bit_exchange(self):
        result = run_authenticated_exchange(32)

        self.assertTrue(result["authenticated"])
        self.assertTrue(result["shared_secret_match"])

    def test_modified_signed_message(self):
        private_key, public_key = generate_identity_keypair()

        signed = create_signed_message(
            private_key,
            {"type": "init", "sender": "Alice"}
        )

        signed["message"]["sender"] = "Eve"

        with self.assertRaises(ValueError):
            verify_signed_message(public_key, signed)

    def test_wrong_identity_key(self):
        alice_private, _ = generate_identity_keypair()
        _, bob_public = generate_identity_keypair()

        signed = create_signed_message(
            alice_private,
            {"type": "init", "sender": "Alice"}
        )

        with self.assertRaises(ValueError):
            verify_signed_message(bob_public, signed)

    def test_invalid_signature_encoding(self):
        private_key, public_key = generate_identity_keypair()

        signed = create_signed_message(
            private_key,
            {"type": "init"}
        )

        signed["signature"] = "not hexadecimal"

        with self.assertRaises(ValueError):
            verify_signed_message(public_key, signed)


if __name__ == "__main__":
    unittest.main()