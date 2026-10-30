from protocol import verify_signed_message
from messages import validate_fields, validate_nonce
from parameters import validate_modulus, is_generator
from session import SessionManager


class SecureReceiver:
    """
    Processes authenticated Diffie-Hellman initiation
    messages and rejects replayed or invalid messages.

    This class represents Bob receiving messages from Alice.
    """

    def __init__(self, trusted_alice_public_key):
        self.trusted_alice_public_key = trusted_alice_public_key
        self.sessions = SessionManager()

    def receive_initiation(self, signed_message):
        """
        Verify Alice's signed initiation message.

        Reject:
        - Invalid signatures
        - Incorrect identities
        - Invalid DH parameters
        - Invalid public values
        - Invalid session IDs and nonces
        - Replayed initiation messages
        """

        # Verify Alice's Ed25519 signature.
        message = verify_signed_message(
            self.trusted_alice_public_key,
            signed_message
        )

        # Require the exact expected fields.
        validate_fields(
            message,
            [
                "type",
                "sender",
                "receiver",
                "session_id",
                "p",
                "g",
                "A",
                "nonce_a"
            ]
        )

        # Verify protocol message type and identities.
        if message["type"] != "init":
            raise ValueError("Invalid message type.")

        if message["sender"] != "Alice":
            raise ValueError("Unexpected sender.")

        if message["receiver"] != "Bob":
            raise ValueError("Unexpected receiver.")

        # Validate session identifier and nonce.
        validate_nonce(message["session_id"])
        validate_nonce(message["nonce_a"])

        # Reject an initiation nonce that was already used.
        # This also prevents reuse under a different session ID.
        if not hasattr(self, "used_alice_nonces"):
            self.used_alice_nonces = set()

        if message["nonce_a"] in self.used_alice_nonces:
            raise ValueError("Initiation nonce replay detected.")

        # Validate the modulus and generator.
        validate_modulus(message["p"])

        if not is_generator(message["g"], message["p"]):
            raise ValueError("Invalid generator.")

        # Reject malformed public values.
        if type(message["A"]) is not int:
            raise ValueError("Invalid public value type.")

        if not 2 <= message["A"] <= message["p"] - 2:
            raise ValueError("Public value out of range.")

        # Register the session only after authentication
        # and validation have succeeded.
        self.sessions.start_session(message["session_id"])

        self.sessions.register_message(
            message["session_id"],
            "init"
        )

        self.used_alice_nonces.add(message["nonce_a"])

        return message