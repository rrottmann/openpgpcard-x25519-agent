"""Card utilities."""

from base64 import b64encode
from getpass import getpass
from logging import getLogger

from OpenPGPpy import (
    ConnectionException,
    DataException,
    OpenPGPcard,
    PGPCardException,
    PinException,
)
from smartcard.System import readers

SIGNATURE_SLOT = 1
ENCRYPTION_SLOT = 2
AUTHENTICATION_SLOT = 3

SIGNATURE_PIN = 1
ENCRYPTION_PIN = 2
ADMIN_PIN = 3

KEY_CRTS = {
    (SIGNATURE_SLOT): "B600",
    (ENCRYPTION_SLOT): "B800",
    (AUTHENTICATION_SLOT): "A400",
}

CURVE_25519_DO_PREFIX = bytes.fromhex("7F49 22 86 20")
CURVE_25519_CIPHER_DO_PREFIX = bytes.fromhex("A6 25") + CURVE_25519_DO_PREFIX

ECC_KEY_TYPES = {
    "2A8648CE3D030107": "nistp256",
    "2B2403030208010107": "brainpoolP256r1",
    "2B240303020801010B": "brainpoolP384r1",
    "2B240303020801010D": "brainpoolP512r1",
    "2B8104000A": "secp256k1",
    "2B81040022": "nistp384",
    "2B81040023": "nistp521",
    "2B060104019755010501": "x25519",
    "2B06010401DA470F01": "ed25519",
    "2B656F": "x448",
    "2B6571": "ed448",
}

STATUS_CODES = {
    0x6285: "in termination state",
    0x640E: "out of memory",
    0x6581: "memory failure",
    0x6600: "security-related issues",
    0x6700: "wrong length",
    0x6881: "logical channel not supported",
    0x6882: "secure messaging not supported",
    0x6883: "last command of chain expected",
    0x6884: "command chaing not supported",
    0x6982: "security status not satisfied",
    0x6983: "authentication method blocked",
    0x6985: "condition of use not satisfied",
    0x6987: "expected secure messaging data objects missing",
    0x6988: "secure messaging data objects incorrect",
    0x6A80: "incorrect parameters in the command",
    0x6A82: "file not found",
    0x6A88: "data object not found",
    0x6B00: "wrong parameters",
    0x6D00: "instruction code not supported",
    0x6E00: "class not supported",
    0x6F00: "no precise diagnosis",
    0x9000: "command correct",
}


def count_all_cards():
    """Number of cards.

    Returns:
        int: Count of cards.
    """
    return len(readers())


def list_all_cards():
    """List of cards, or empty.

    Returns:
        list: List of cards.
    """
    cards = []
    for i in range(0, count_all_cards()):
        card = get_card_by_index_or_none(i)
        if card:
            cards.append(card)
    return cards


def get_card_by_index(index):
    """Card at the specified index, or raises.

    Arguments:
        index (int): Card index.

    Returns:
        OpenPGPcard: Card at index.

    Propagates:
        ConnectionException: If no card at index.
    """
    card = OpenPGPcard(reader_index=index)
    card.index = index
    return card


def get_card_by_index_or_none(index):
    """Card at the specified index, or None.

    Arguments:
        index (int): Card index.

    Returns:
        OpenPGPcard: Card at index.
    """
    try:
        return get_card_by_index(index)
    except Exception:
        getLogger(__name__).debug(
            "error accessing card by index %x", index, exc_info=True
        )
        return None


def get_card_by_id(card_id):
    """Card with the specified ID, or raises.

    Arguments:
        card_id: Card serial number or index (eg 0x3f or "3f").

    Returns:
        OpenPGPcard: Card with ID.

    Raises:
        ConnectionException: If no card with ID.
    """
    serial = card_id if isinstance(card_id, int) else int(str(card_id), 16)
    count = count_all_cards()
    if serial < count:
        return get_card_by_index(serial)

    for i in range(0, count):
        card = get_card_by_index_or_none(i)
        if card and card.serial == serial:
            return card

    raise ConnectionException(f"no card with id {serial:#x}")


def get_default_card():
    """First available card, or raises.

    Returns:
        OpenPGPcard: First available card.

    Raises:
        ConnectionException: If no available cards.
    """
    for i in range(0, count_all_cards()):
        card = get_card_by_index_or_none(i)
        if card:
            return card

    raise ConnectionException("no available cards")


def send_simple_command(
    card, class_byte, instruction, parameter_1=0, parameter_2=0, data=None
):
    """Submits the specified command to the specified card.

    If the command succeeds, returns the command's output data.
    If the command fails, will raise a `PGPCardException` with the status bytes.

    Note this only works for certain commands with short input and output data.

    Arguments:
        card (OpenPGPcard): Card.
        class_byte (int): Command class byte.
        instruction (int): Instruction byte.
        parameter_1 (int): Parameter 1 byte.
        parameter_2 (int): Parameter 2 byte.
        data (bytearray): Command input data.

    Returns:
        bytearray: Command output data.

    Raises:
        PGPCardException: If the command fails.
    """
    length = len(data) if data else 0
    command = [class_byte, instruction, parameter_1, parameter_2, length]
    if data:
        command[6:] = data

    result, status_1, status_2 = _send_command_and_zero(card, command)
    while status_1 == 0x61 and status_2 != 0x00:
        result, status_1, status_2 = _append_get_response(
            card, class_byte, result, status_2
        )

    if status_1 not in (0x61, 0x90) or status_2 != 0x00:
        result[:] = bytearray(len(result))
        raise PGPCardException(status_1, status_2)

    return result


def _log_command(cla, ins, p1, p2, lc):  # noqa: SC200
    s = "sending command to card: %x %x %x %x + %x bytes"
    getLogger(__name__).debug(s, cla, ins, p1, p2, lc)  # noqa: SC200


def _log_response(sw1, sw2, length):  # noqa: SC200
    s = "received response from card: %x %x + %x bytes"
    getLogger(__name__).debug(s, sw1, sw2, length)  # noqa: SC200


def _send_command_and_zero(card, command):
    try:
        _log_command(*command[:5])
        result, status_1, status_2 = card.connection.transmit(command)
        _log_response(status_1, status_2, len(result))
        return result, status_1, status_2
    finally:
        command[:] = [0] * len(command)


def _append_get_response(card, class_byte, previous_result, expected_length):
    command = [class_byte, 0xC0, 0x00, 0x00, expected_length]
    result, status_1, status_2 = _send_command_and_zero(card, command)

    previous_result_length = len(previous_result)
    if previous_result_length == 0:
        return result, status_1, status_2

    result_length = len(result)
    if result_length == 0:
        return previous_result, status_1, status_2

    full_result = previous_result + result
    previous_result[:] = bytearray(previous_result_length)
    result[:] = bytearray(result_length)
    return full_result, status_1, status_2


def verify_pin(card, pin, slot=ENCRYPTION_PIN):
    """Submits the specified pin to the specified card for verification.

    If the PIN is valid, succeeds. If the PIN is invalid (or blocked),
    will raise a `PinException` with the number of retries left for the PIN.

    Arguments:
        card (OpenPGPcard): Card.
        pin (bytearray): PIN to verify.
        slot (int): PIN type (defaults to encryption PIN).

    Raises:
        PinException: If the PIN is incorrect or blocked.
        PGPCardException: If the operation fails for some other reason.
    """
    try:
        send_simple_command(card, 0, 0x20, 0, 0x80 + slot, pin)
    except PGPCardException as e:
        if e.sw_code & 0xFFF0 == 0x63C0:
            raise PinException(e.sw_code - 0x63C0)
        raise e


def calculate_x25519_shared_secret(card, public_key):
    """Performs ECDH with the specified card.

    Assumes this operation has already been authorized by verifying the PIN
    (or by other means). If not authorized, will raise a `PGPCardException'.

    Assumes the desired key slot to use for ECDH has already been set
    via the card's Manage Security Environment (MSE) command. If not set,
    the card defaults to using the encryption key slot.

    Arguments:
        card (OpenPGPcard): Card.
        public_key (bytearray): Other party's public key.

    Returns:
        bytearray: Shared secret.

    Propagates:
        PGPCardException: If the PIN needs to be verified before this operation
            is allowed, or if the operation fails for some other reason.
    """
    data = CURVE_25519_CIPHER_DO_PREFIX + public_key
    return send_simple_command(card, 0, 0x2A, 0x80, 0x86, data)


def calculate_shared_secret(card, public_key, pin=None):
    """Performs ECDH with the specified card.

    Assumes the desired key slot to use for ECDH has already been set
    via the card's Manage Security Environment (MSE) command. If not set,
    the card defaults to using the encryption key slot.

    Arguments:
        card (OpenPGPcard): Card.
        public_key (bytearray): Other party's public key.
        pin (bytearray): PIN to verify before performing this operation.

    Returns:
        bytearray: Shared secret.

    Raises:
        PGPCardException: If this operation fails.

    Propagates:
        PinException: If the PIN is incorrect or blocked.
    """
    try:
        return calculate_x25519_shared_secret(card, public_key)
    except PGPCardException as e:
        if e.sw_code != 0x6982 or not pin:
            raise e
        verify_pin(card, pin)
        return calculate_x25519_shared_secret(card, public_key)


def test_card(card_id=None):
    """Attempts a test X25519 operation with the specified card.

    Prints card info and prompts for PIN.
    If successful, does nothing. If fails, raises an exception.

    Arguments:
        card_id: Card serial number or index (eg 0x3f or "3f").

    Propagates:
        PinException: If the PIN is incorrect or blocked.
        PGPCardException: If the ECDH command fails.
        ConnectionException: If the specified card is unavailable.
    """
    card = get_card_by_id(card_id) if card_id else get_default_card()

    # print info to stdout
    print(format_card_info(card))  # noqa: T201
    print("Enter card user PIN: ")  # noqa: T201
    pin = getpass("").encode()

    calculate_shared_secret(card, bytearray(b"\xff" * 32), pin)


def get_key_type(card, slot=ENCRYPTION_SLOT):
    """Type of key in the specified slot of the specified card.

    Arguments:
        card (OpenPGPcard): Card.
        slot (int): Key slot (defaults to encryption slot).

    Returns:
        str: Key type (eg 'x25519' or 'nistp256' or 'rsa2048').
    """
    app_data = card.get_application_data()
    return get_key_type_from_app_data(app_data, slot)


def get_key_type_from_app_data(app_data, slot=ENCRYPTION_SLOT):
    """Type of key in the specified slot of the specified card app data.

    Arguments:
        app_data: Application-related data object (6E) queried from card.
        slot (int): Key slot (defaults to encryption slot).

    Returns:
        str: Key type (eg 'x25519' or 'nistp256' or 'rsa2048').
    """
    attributes = app_data.get("73", {}).get(f"C{slot}")
    return get_key_type_from_algorithm_attributes(attributes)


def get_key_type_from_algorithm_attributes(attributes):
    """Type of key for the specified algorithm attributes.

    Arguments:
        attributes (str): Algorithm-attributes string (C1, C2, or C3).

    Returns:
        str: Key type (eg 'x25519' or 'nistp256' or 'rsa2048').
    """
    if not attributes or len(attributes) < 6:
        return attributes
    if attributes[:2] == "01":
        return f"rsa{int(attributes[2:6], 16)}"
    return ECC_KEY_TYPES.get(attributes[2:]) or attributes


def get_curve25519_key(card, slot=ENCRYPTION_SLOT):
    """Extracts public key in the specified slot from the specified card.

    Arguments:
        card (OpenPGPcard): Card.
        slot (int): Key slot (defaults to encryption slot).

    Returns:
        bytes: Raw key byte string (32 bytes).

    Raises:
        DataException: If slot is empty or contains wrong type of key.
    """
    key = card.get_public_key(KEY_CRTS[slot])
    if not key:
        raise DataException("no key")
    if len(key) != 37 or key[:5] != CURVE_25519_DO_PREFIX:
        raise DataException(f"invalid curve25519 key: {key.hex()}")
    return key[-32:]


def format_curve25519_key(card, slot=ENCRYPTION_SLOT):
    """Formats public key in the specified slot from the specified card.

    Arguments:
        card (OpenPGPcard): Card.
        slot (int): Key slot (defaults to encryption slot).

    Returns:
        str: Base64-encoded key, or error message.
    """
    try:
        key = get_curve25519_key(card, slot)
        return b64encode(key).decode("utf-8") if key else ""
    except PGPCardException as e:
        return STATUS_CODES.get(e.sw_code) or "card error"
    except Exception:
        getLogger(__name__).warning(
            "error accessing key for card %x", card.index, exc_info=True
        )
        return "error"


def format_pin_status(card):
    """Formats user PIN status of the specified card.

    Arguments:
        card (OpenPGPcard): Card.

    Returns:
        str: Status message (eg "unlocked" or "3 tries remaining").
    """
    pin = card.get_pin_status(1)
    return "unlocked" if pin == 0x9000 else f"{pin} tries remaining"


def format_card_info(card):
    """Formats card info for the specified card.

    Arguments:
        card (OpenPGPcard): Card.

    Returns:
        str: Multi-line card info.
    """
    app_data = card.get_application_data()

    signature_type = get_key_type_from_app_data(app_data, SIGNATURE_SLOT)
    encryption_type = get_key_type_from_app_data(app_data, ENCRYPTION_SLOT)
    auth_type = get_key_type_from_app_data(app_data, AUTHENTICATION_SLOT)

    encryption_key = encryption_type
    if encryption_type == "x25519":
        encryption_key = f"{encryption_type} ({format_curve25519_key(card)})"

    pin = format_pin_status(card)

    return f"""
Card Index: {card.index:#x}
Card Name: {card.name}
Serial Number: {card.serial:#x}
Manufacturer: {card.manufacturer_id} ({card.manufacturer})
OpenPGP Version: {card.pgpverstr}
Signature Key: {signature_type}
Encryption Key: {encryption_key}
Authentication Key: {auth_type}
PIN Status: {pin}
    """.strip()


def format_cards_info(cards):
    """Formats card info for the specified list of cards.

    Arguments:
        cards (list): List of cards.

    Returns:
        str: Multi-line cards info.
    """
    if cards:
        return "\n----------\n".join([format_card_info(x) for x in cards])
    return "no cards"
