import unittest

from messages import (
    generate_nonce,
    encode_message,
    decode_message,
    validate_fields,
    validate_nonce,
)


class TestMessages(unittest.TestCase):

    def test_nonce_length(self):
        nonce = generate_nonce()
        self.assertEqual(len(nonce), 32)

    def test_nonce_randomness(self):
        nonce1 = generate_nonce()
        nonce2 = generate_nonce()
        self.assertNotEqual(nonce1, nonce2)

    def test_deterministic_encoding(self):
        message1 = {"b": 2, "a": 1}
        message2 = {"a": 1, "b": 2}

        self.assertEqual(
            encode_message(message1),
            encode_message(message2)
        )

    def test_oversized_message(self):
        oversized = b" " * 4097

        with self.assertRaises(ValueError):
            decode_message(oversized)

    def test_encode_decode(self):
        message = {"type": "init", "sender": "Alice"}

        encoded = encode_message(message)
        decoded = decode_message(encoded)

        self.assertEqual(decoded, message)

    def test_invalid_json(self):
        with self.assertRaises(ValueError):
            decode_message(b"{invalid json}")

    def test_non_dictionary_json(self):
        with self.assertRaises(ValueError):
            decode_message(b"[1, 2, 3]")

    def test_missing_fields(self):
        message = {"type": "init"}

        with self.assertRaises(ValueError):
            validate_fields(
                message,
                ["type", "sender"]
            )

    def test_extra_fields(self):
        message = {
            "type": "init",
            "sender": "Alice",
            "extra": "unexpected"
        }

        with self.assertRaises(ValueError):
            validate_fields(
                message,
                ["type", "sender"]
            )

    def test_valid_fields(self):
        message = {"type": "init", "sender": "Alice"}

        self.assertTrue(
            validate_fields(
                message,
                ["type", "sender"]
            )
        )

    def test_valid_nonce(self):
        nonce = generate_nonce().hex()
        self.assertTrue(validate_nonce(nonce))

    def test_short_nonce(self):
        with self.assertRaises(ValueError):
            validate_nonce("abcd")

    def test_invalid_nonce_characters(self):
        with self.assertRaises(ValueError):
            validate_nonce("z" * 64)

    def test_boolean_nonce(self):
        with self.assertRaises(TypeError):
            validate_nonce(True)


if __name__ == "__main__":
    unittest.main()
