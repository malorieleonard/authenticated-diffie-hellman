import json
import secrets


def generate_nonce():
    """
    Generate a fresh 32-byte random nonce.
    """
    return secrets.token_bytes(32)


def encode_message(message):
    """
    Convert a dictionary into deterministic JSON bytes.
    """

    if type(message) is not dict:
        raise TypeError("Message must be a dictionary.")

    return json.dumps(
        message,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True
    ).encode("utf-8")


def decode_message(data):
    """
    Decode JSON bytes and reject duplicate keys.
    """

    if type(data) is not bytes:
        raise TypeError("Encoded message must be bytes.")

    if len(data) > 4096:
        raise ValueError("Message exceeds 4096 bytes.")

    def reject_duplicates(pairs):
        result = {}

        for key, value in pairs:
            if key in result:
                raise ValueError("Duplicate JSON field.")
            result[key] = value

        return result

    try:
        message = json.loads(
            data.decode("utf-8"),
            object_pairs_hook=reject_duplicates,
            parse_constant=lambda value: (
                _reject_json_constant(value)
            )
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("Invalid JSON message.") from exc

    if type(message) is not dict:
        raise ValueError("Message must be a JSON object.")

    return message


def _reject_json_constant(value):
    raise ValueError(f"Invalid JSON constant: {value}")


def validate_fields(message, required_fields):
    """
    Ensure a message contains exactly the expected fields.
    """

    if type(message) is not dict:
        raise TypeError("Message must be a dictionary.")

    if type(required_fields) not in (list, tuple, set):
        raise TypeError("Required fields must be a collection.")

    if set(message.keys()) != set(required_fields):
        raise ValueError("Missing or unexpected message fields.")

    return True


def validate_nonce(nonce):
    """
    Validate a nonce represented as a hexadecimal string.
    """

    if type(nonce) is not str:
        raise TypeError("Nonce must be a hexadecimal string.")

    if len(nonce) != 64:
        raise ValueError("Nonce must represent exactly 32 bytes.")

    try:
        bytes.fromhex(nonce)
    except ValueError as exc:
        raise ValueError("Invalid hexadecimal nonce.") from exc

    return True