from authentication import generate_identity_keypair
from parameters import generate_prime, find_generator
from participant import Participant
from protocol import create_signed_message, verify_signed_message


def demonstrate_unauthenticated_mitm(bits=16):
    """
    Demonstrate a successful man-in-the-middle attack
    against unauthenticated Diffie-Hellman.
    """

    p = generate_prime(bits)
    g = find_generator(p)

    alice = Participant("Alice", p, g)
    bob = Participant("Bob", p, g)

    # Eve uses two separate DH key pairs:
    # one to impersonate Bob to Alice,
    # and another to impersonate Alice to Bob.
    eve_to_alice = Participant("Alice", p, g)
    eve_to_bob = Participant("Bob", p, g)

    # Alice receives Eve's public value instead of Bob's.
    alice_secret = alice.compute_shared_secret(
        eve_to_alice.public_key
    )

    # Eve computes the same secret as Alice.
    eve_alice_secret = eve_to_alice.compute_shared_secret(
        alice.public_key
    )

    # Bob receives Eve's public value instead of Alice's.
    bob_secret = bob.compute_shared_secret(
        eve_to_bob.public_key
    )

    # Eve computes the same secret as Bob.
    eve_bob_secret = eve_to_bob.compute_shared_secret(
        bob.public_key
    )

    return {
        "attack": "Unauthenticated MITM",
        "eve_matches_alice": alice_secret == eve_alice_secret,
        "eve_matches_bob": bob_secret == eve_bob_secret,
        "attack_successful": (
            alice_secret == eve_alice_secret
            and bob_secret == eve_bob_secret
        ),
    }


def demonstrate_authenticated_mitm(bits=16):
    """
    Demonstrate that modifying Alice's signed
    Diffie-Hellman public value invalidates her signature.
    """

    p = generate_prime(bits)
    g = find_generator(p)

    alice = Participant("Alice", p, g)
    eve = Participant("Bob", p, g)

    # Bob already trusts Alice's authentic Ed25519 public key.
    alice_private, alice_public = generate_identity_keypair()

    message = {
        "type": "init",
        "sender": "Alice",
        "receiver": "Bob",
        "p": p,
        "g": g,
        "A": alice.public_key,
    }

    signed_message = create_signed_message(
        alice_private,
        message
    )

    # Eve replaces Alice's DH public value.
    signed_message["message"]["A"] = eve.public_key

    try:
        verify_signed_message(
            alice_public,
            signed_message
        )
    except ValueError:
        return {
            "attack": "Authenticated MITM",
            "attack_rejected": True,
            "reason": "Signature verification failed",
        }

    return {
        "attack": "Authenticated MITM",
        "attack_rejected": False,
        "reason": "Modified message was accepted",
    }
