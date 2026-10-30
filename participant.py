import secrets

from modular_math import modular_exponentiation
from parameters import validate_modulus, is_generator


class Participant:
    """
    Represents Alice or Bob in a Diffie-Hellman exchange.
    """

    def __init__(self, name, p, g, allow_fixture=False):

        if name not in ("Alice", "Bob"):
            raise ValueError("Participant must be Alice or Bob.")

        validate_modulus(p, allow_fixture=allow_fixture)

        if not is_generator(g, p):
            raise ValueError("Invalid generator.")

        self.name = name
        self.p = p
        self.g = g

        # Generate a valid private and public key pair
        while True:
            self.private_key = secrets.randbelow(p - 4) + 2

            self.public_key = modular_exponentiation(
                g, self.private_key, p
            )

            if 2 <= self.public_key <= p - 2:
                break

    def compute_shared_secret(self, other_public_key):
        """
        Calculate the shared Diffie-Hellman secret.
        """

        if type(other_public_key) is not int:
            raise TypeError("Public key must be an integer.")

        if not 2 <= other_public_key <= self.p - 2:
            raise ValueError("Invalid public key range.")

        shared_secret = modular_exponentiation(
            other_public_key,
            self.private_key,
            self.p
        )

        return shared_secret