import unittest

from authentication import generate_identity_keypair
from messages import generate_nonce
from parameters import generate_prime, find_generator
from participant import Participant
from protocol import create_signed_message
from secure_receiver import SecureReceiver


class TestSecureReceiver(unittest.TestCase):

    def setUp(self):
        self.alice_private, self.alice_public = (
            generate_identity_keypair()
        )

        self.bob = SecureReceiver(self.alice_public)

        self.p = generate_prime(16)
        self.g = find_generator(self.p)

        self.alice = Participant(
            "Alice",
            self.p,
            self.g
        )

    def make_message(self, **overrides):
        message = {
            "type": "init",
            "sender": "Alice",
            "receiver": "Bob",
            "session_id": generate_nonce().hex(),
            "p": self.p,
            "g": self.g,
            "A": self.alice.public_key,
            "nonce_a": generate_nonce().hex()
        }

        message.update(overrides)

        return create_signed_message(
            self.alice_private,
            message
        )

    def test_valid_initiation(self):
        signed = self.make_message()

        received = self.bob.receive_initiation(signed)

        self.assertEqual(received["sender"], "Alice")

    def test_replayed_signed_message(self):
        signed = self.make_message()

        self.bob.receive_initiation(signed)

        with self.assertRaises(ValueError):
            self.bob.receive_initiation(signed)

    def test_reused_session_id(self):
        session_id = generate_nonce().hex()

        first = self.make_message(
            session_id=session_id
        )

        second = self.make_message(
            session_id=session_id
        )

        self.bob.receive_initiation(first)

        with self.assertRaises(ValueError):
            self.bob.receive_initiation(second)

    def test_reused_nonce(self):
        nonce = generate_nonce().hex()

        first = self.make_message(
            nonce_a=nonce
        )

        second = self.make_message(
            nonce_a=nonce
        )

        self.bob.receive_initiation(first)

        with self.assertRaises(ValueError):
            self.bob.receive_initiation(second)

    def test_modified_public_value(self):
        signed = self.make_message()

        original = signed["message"]["A"]

        replacement = 2 if original != 2 else 3

        signed["message"]["A"] = replacement

        with self.assertRaises(ValueError):
            self.bob.receive_initiation(signed)

    def test_wrong_sender(self):
        signed = self.make_message(
            sender="Eve"
        )

        with self.assertRaises(ValueError):
            self.bob.receive_initiation(signed)

    def test_wrong_receiver(self):
        signed = self.make_message(
            receiver="Eve"
        )

        with self.assertRaises(ValueError):
            self.bob.receive_initiation(signed)

    def test_invalid_public_value(self):
        signed = self.make_message(
            A=1
        )

        with self.assertRaises(ValueError):
            self.bob.receive_initiation(signed)

    def test_boolean_public_value(self):
        signed = self.make_message(
            A=True
        )

        with self.assertRaises(ValueError):
            self.bob.receive_initiation(signed)

    def test_invalid_nonce(self):
        signed = self.make_message(
            nonce_a="invalid"
        )

        with self.assertRaises(ValueError):
            self.bob.receive_initiation(signed)

    def test_invalid_session_id(self):
        signed = self.make_message(
            session_id="invalid"
        )

        with self.assertRaises(ValueError):
            self.bob.receive_initiation(signed)

    def test_missing_field(self):
        signed = self.make_message()

        del signed["message"]["nonce_a"]

        with self.assertRaises(ValueError):
            self.bob.receive_initiation(signed)

    def test_extra_field(self):
        signed = self.make_message(
            unexpected="extra"
        )

        with self.assertRaises(ValueError):
            self.bob.receive_initiation(signed)

    def test_wrong_trusted_identity_key(self):
        _, wrong_public = generate_identity_keypair()

        wrong_receiver = SecureReceiver(
            wrong_public
        )

        signed = self.make_message()

        with self.assertRaises(ValueError):
            wrong_receiver.receive_initiation(signed)

    def test_fresh_sessions_are_accepted(self):
        first = self.make_message()
        second = self.make_message()

        self.bob.receive_initiation(first)
        self.bob.receive_initiation(second)

        self.assertEqual(
            len(self.bob.sessions.used_sessions),
            2
        )


if __name__ == "__main__":
    unittest.main()
