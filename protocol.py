from session import SessionManager

from authentication import (
    generate_identity_keypair,
    sign_message,
    verify_signature,
)
from messages import (
    generate_nonce,
    encode_message,
    validate_fields,
    validate_nonce,
)
from participant import Participant
from parameters import (
    generate_prime,
    find_generator,
    validate_modulus,
    is_generator,
)


def create_signed_message(private_key, message):
    """Create a digitally signed JSON message."""

    signature = sign_message(
        private_key,
        encode_message(message)
    )

    return {
        "message": message,
        "signature": signature.hex()
    }


def verify_signed_message(public_key, signed_message):
    """Verify an Ed25519 signature on a JSON message."""

    validate_fields(
        signed_message,
        ["message", "signature"]
    )

    message = signed_message["message"]
    signature_hex = signed_message["signature"]

    if type(message) is not dict:
        raise ValueError(
            "Signed message payload must be a dictionary."
        )

    if type(signature_hex) is not str:
        raise ValueError(
            "Signature must be hexadecimal."
        )

    try:
        signature = bytes.fromhex(signature_hex)
    except ValueError as exc:
        raise ValueError(
            "Invalid signature encoding."
        ) from exc

    if len(signature) != 64:
        raise ValueError(
            "Invalid Ed25519 signature length."
        )

    if not verify_signature(
        public_key,
        encode_message(message),
        signature
    ):
        raise ValueError(
            "Signature verification failed."
        )

    return message


def run_authenticated_exchange(bits=16, session_manager=None):
    """
    Perform a three-message authenticated Diffie-Hellman
    exchange with session tracking.

    Message 1: Alice -> Bob (signed initiation)
    Message 2: Bob -> Alice (signed response)
    Message 3: Alice -> Bob (signed finish)

    This function models both participants locally.
    """

    # --------------------------------------------------
    # 1. Initialize session management
    # --------------------------------------------------

    if session_manager is None:
        session_manager = SessionManager()

    # --------------------------------------------------
    # 2. Generate Diffie-Hellman parameters
    # --------------------------------------------------

    p = generate_prime(bits)
    g = find_generator(p)

    # --------------------------------------------------
    # 3. Create Alice and Bob
    # --------------------------------------------------

    alice = Participant("Alice", p, g)
    bob = Participant("Bob", p, g)

    # --------------------------------------------------
    # 4. Generate trusted identity keys
    # --------------------------------------------------

    alice_private, alice_public = generate_identity_keypair()
    bob_private, bob_public = generate_identity_keypair()

    trusted_keys = {
        "Alice": alice_public,
        "Bob": bob_public
    }

    # --------------------------------------------------
    # 5. Generate fresh nonces and session identifier
    # --------------------------------------------------

    alice_nonce = generate_nonce().hex()
    bob_nonce = generate_nonce().hex()

    session_id = generate_nonce().hex()

    # --------------------------------------------------
    # MESSAGE 1: Alice -> Bob
    # --------------------------------------------------

    message1 = {
        "type": "init",
        "sender": "Alice",
        "receiver": "Bob",
        "session_id": session_id,
        "p": p,
        "g": g,
        "A": alice.public_key,
        "nonce_a": alice_nonce
    }

    signed1 = create_signed_message(
        alice_private,
        message1
    )

    # Bob verifies Alice's signature
    received1 = verify_signed_message(
        trusted_keys["Alice"],
        signed1
    )

    validate_fields(
        received1,
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

    if received1["type"] != "init":
        raise ValueError(
            "Invalid initiation message type."
        )

    if received1["sender"] != "Alice":
        raise ValueError(
            "Unexpected initiation sender."
        )

    if received1["receiver"] != "Bob":
        raise ValueError(
            "Unexpected initiation receiver."
        )

    validate_nonce(received1["session_id"])
    validate_nonce(received1["nonce_a"])

    if received1["session_id"] != session_id:
        raise ValueError(
            "Session ID mismatch."
        )

    validate_modulus(received1["p"])

    if received1["p"] != p:
        raise ValueError(
            "Unexpected Diffie-Hellman modulus."
        )

    if not is_generator(
        received1["g"],
        received1["p"]
    ):
        raise ValueError(
            "Invalid Diffie-Hellman generator."
        )

    if received1["g"] != g:
        raise ValueError(
            "Unexpected Diffie-Hellman generator."
        )

    if type(received1["A"]) is not int:
        raise ValueError(
            "Invalid Alice public value."
        )

    if not 2 <= received1["A"] <= p - 2:
        raise ValueError(
            "Alice public value out of range."
        )

    # Record the authenticated initiation
    session_manager.start_session(session_id)

    session_manager.register_message(
        session_id,
        "init"
    )

    # --------------------------------------------------
    # MESSAGE 2: Bob -> Alice
    # --------------------------------------------------

    message2 = {
        "type": "response",
        "sender": "Bob",
        "receiver": "Alice",
        "session_id": session_id,
        "message1": received1,
        "B": bob.public_key,
        "nonce_b": bob_nonce
    }

    signed2 = create_signed_message(
        bob_private,
        message2
    )

    # Alice verifies Bob's signature
    received2 = verify_signed_message(
        trusted_keys["Bob"],
        signed2
    )

    validate_fields(
        received2,
        [
            "type",
            "sender",
            "receiver",
            "session_id",
            "message1",
            "B",
            "nonce_b"
        ]
    )

    if received2["type"] != "response":
        raise ValueError(
            "Invalid response message type."
        )

    if received2["sender"] != "Bob":
        raise ValueError(
            "Unexpected response sender."
        )

    if received2["receiver"] != "Alice":
        raise ValueError(
            "Unexpected response receiver."
        )

    validate_nonce(received2["session_id"])
    validate_nonce(received2["nonce_b"])

    if received2["session_id"] != session_id:
        raise ValueError(
            "Response session ID mismatch."
        )

    if received2["message1"] != message1:
        raise ValueError(
            "Response transcript mismatch."
        )

    if type(received2["B"]) is not int:
        raise ValueError(
            "Invalid Bob public value."
        )

    if not 2 <= received2["B"] <= p - 2:
        raise ValueError(
            "Bob public value out of range."
        )

    # Record the authenticated response
    session_manager.register_message(
        session_id,
        "response"
    )

    # --------------------------------------------------
    # MESSAGE 3: Alice -> Bob
    # --------------------------------------------------

    message3 = {
        "type": "finish",
        "sender": "Alice",
        "receiver": "Bob",
        "session_id": session_id,
        "message1": message1,
        "message2": received2
    }

    signed3 = create_signed_message(
        alice_private,
        message3
    )

    # Bob verifies Alice's final signature
    received3 = verify_signed_message(
        trusted_keys["Alice"],
        signed3
    )

    validate_fields(
        received3,
        [
            "type",
            "sender",
            "receiver",
            "session_id",
            "message1",
            "message2"
        ]
    )

    if received3["type"] != "finish":
        raise ValueError(
            "Invalid finish message type."
        )

    if received3["sender"] != "Alice":
        raise ValueError(
            "Unexpected finish sender."
        )

    if received3["receiver"] != "Bob":
        raise ValueError(
            "Unexpected finish receiver."
        )

    validate_nonce(received3["session_id"])

    if received3["session_id"] != session_id:
        raise ValueError(
            "Finish session ID mismatch."
        )

    if received3["message1"] != message1:
        raise ValueError(
            "Final message1 transcript mismatch."
        )

    if received3["message2"] != message2:
        raise ValueError(
            "Final message2 transcript mismatch."
        )

    # Record the authenticated finish
    session_manager.register_message(
        session_id,
        "finish"
    )

    # --------------------------------------------------
    # 6. Compute Diffie-Hellman shared secrets
    # --------------------------------------------------

    alice_secret = alice.compute_shared_secret(
        received2["B"]
    )

    bob_secret = bob.compute_shared_secret(
        received1["A"]
    )

    if alice_secret != bob_secret:
        raise ValueError(
            "Shared secrets do not match."
        )

    # --------------------------------------------------
    # 7. Complete the authenticated session
    # --------------------------------------------------

    session_manager.complete_session(session_id)

    # --------------------------------------------------
    # 8. Return exchange results
    # --------------------------------------------------

    return {
        "authenticated": True,
        "shared_secret_match": True,
        "session_id": session_id,
        "session_state": session_manager.active_sessions[
            session_id
        ]["state"],
        "p": p,
        "g": g,
        "A": alice.public_key,
        "B": bob.public_key,
        "alice_secret": alice_secret,
        "bob_secret": bob_secret
    }