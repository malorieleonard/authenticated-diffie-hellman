import unittest

from participant import Participant


class TestParticipant(unittest.TestCase):

    def test_alice_creation(self):
        alice = Participant("Alice", 23, 5, allow_fixture=True)

        self.assertEqual(alice.name, "Alice")
        self.assertEqual(alice.p, 23)
        self.assertEqual(alice.g, 5)

    def test_bob_creation(self):
        bob = Participant("Bob", 23, 5, allow_fixture=True)

        self.assertEqual(bob.name, "Bob")

    def test_private_key_range(self):
        alice = Participant("Alice", 23, 5, allow_fixture=True)

        self.assertTrue(2 <= alice.private_key <= 20)

    def test_public_key_range(self):
        alice = Participant("Alice", 23, 5, allow_fixture=True)

        self.assertTrue(1 <= alice.public_key <= 22)

    def test_shared_secret_matches(self):
        alice = Participant("Alice", 23, 5, allow_fixture=True)
        bob = Participant("Bob", 23, 5, allow_fixture=True)

        alice_secret = alice.compute_shared_secret(
            bob.public_key
        )

        bob_secret = bob.compute_shared_secret(
            alice.public_key
        )

        self.assertEqual(alice_secret, bob_secret)

    def test_invalid_participant_name(self):
        with self.assertRaises(ValueError):
            Participant("Eve", 23, 5, allow_fixture=True)

    def test_invalid_generator(self):
        with self.assertRaises(ValueError):
            Participant("Alice", 23, 2, allow_fixture=True)

    def test_invalid_public_key(self):
        alice = Participant("Alice", 23, 5, allow_fixture=True)

        with self.assertRaises(ValueError):
            alice.compute_shared_secret(1)

    def test_boolean_public_key(self):
        alice = Participant("Alice", 23, 5, allow_fixture=True)

        with self.assertRaises(TypeError):
            alice.compute_shared_secret(True)


if __name__ == "__main__":
    unittest.main()
