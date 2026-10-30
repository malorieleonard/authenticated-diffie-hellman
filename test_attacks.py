import unittest

from attacks import (
    demonstrate_unauthenticated_mitm,
    demonstrate_authenticated_mitm,
)


class TestAttacks(unittest.TestCase):

    def test_unauthenticated_mitm_16_bit(self):
        result = demonstrate_unauthenticated_mitm(16)

        self.assertTrue(result["eve_matches_alice"])
        self.assertTrue(result["eve_matches_bob"])
        self.assertTrue(result["attack_successful"])

    def test_unauthenticated_mitm_24_bit(self):
        result = demonstrate_unauthenticated_mitm(24)

        self.assertTrue(result["attack_successful"])

    def test_unauthenticated_mitm_32_bit(self):
        result = demonstrate_unauthenticated_mitm(32)

        self.assertTrue(result["attack_successful"])

    def test_authenticated_mitm_16_bit(self):
        result = demonstrate_authenticated_mitm(16)

        self.assertTrue(result["attack_rejected"])

    def test_authenticated_mitm_24_bit(self):
        result = demonstrate_authenticated_mitm(24)

        self.assertTrue(result["attack_rejected"])

    def test_authenticated_mitm_32_bit(self):
        result = demonstrate_authenticated_mitm(32)

        self.assertTrue(result["attack_rejected"])


if __name__ == "__main__":
    unittest.main()
