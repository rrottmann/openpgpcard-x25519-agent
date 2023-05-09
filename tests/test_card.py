"""Unit tests for card utilities."""

from logging import DEBUG
from unittest.mock import MagicMock

import pytest
from OpenPGPpy import ConnectionException, DataException, PGPCardException, PinException

from openpgpcard_x25519_agent.card import (
    _send_command_and_zero,
    calculate_shared_secret,
    calculate_x25519_shared_secret,
    count_all_cards,
    format_card_info,
    format_cards_info,
    format_curve25519_key,
    format_pin_status,
    get_card_by_id,
    get_card_by_index,
    get_card_by_index_or_none,
    get_curve25519_key,
    get_default_card,
    get_key_type,
    get_key_type_from_algorithm_attributes,
    get_key_type_from_app_data,
    list_all_cards,
    send_simple_command,
)
from openpgpcard_x25519_agent.card import test_card as cli_test_card
from openpgpcard_x25519_agent.card import verify_pin

EXAMPLE_KEY_HEX = "C53201039ADBA14BE71F886DA1D8DBE9EEBDED08CB111B75340078999AA9F038"
EXAMPLE_KEY_64 = "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg="

DECIPHER_KEY_COMMAND_PREFIX = "002A8086 27 A6 25 7F49 22 86 20"
DECIPHER_EXAMPLE_KEY_COMMAND = list(
    bytes.fromhex(f"{DECIPHER_KEY_COMMAND_PREFIX} {EXAMPLE_KEY_HEX}")
)
DECIPHER_TEST_CARD_COMMAND = list(bytes.fromhex(DECIPHER_KEY_COMMAND_PREFIX)) + (
    [0xFF] * 32
)


def test_count_all_cards_when_none(all_cards_mock):
    assert count_all_cards() == 0


def test_count_all_cards_when_multiple(five_cards_mock):
    assert count_all_cards() == 5


def test_list_all_cards_when_none(all_cards_mock):
    assert list_all_cards() == []


def test_list_all_cards_when_multiple(five_cards_mock):
    cards = list_all_cards()
    assert cards[0].index == 1
    assert cards[1].index == 3
    assert len(cards) == 2


def test_get_card_by_index_when_found(card_mock):
    assert get_card_by_index(63).index == 63


def test_get_card_by_index_or_none_when_found(card_mock):
    assert get_card_by_index_or_none(63).index == 63


def test_get_card_by_index_or_none_when_not_found(card_mock):
    card_mock.side_effect = ConnectionException("test")
    assert not get_card_by_index_or_none(63)


def test_get_card_by_id_when_not_found(all_cards_mock):
    with pytest.raises(ConnectionException):
        get_card_by_id("0x3f")


def test_get_card_by_id_when_found_by_index(all_cards_mock, card_mock):
    all_cards_mock.return_value = range(5)
    card_mock.return_value = MagicMock()

    assert get_card_by_id(3).index == 3


def test_get_card_by_id_when_found_by_serial(five_cards_mock):
    five_cards_mock[3].serial = 0x3F
    assert get_card_by_id("3f").index == 3


def test_get_default_card_when_none(all_cards_mock):
    with pytest.raises(ConnectionException):
        get_default_card()


def test_get_default_card_when_multiple(five_cards_mock):
    assert get_default_card().index == 1


def test_send_simple_command_when_success():
    card, sent = mock_card_and_command(b"bar")
    assert send_simple_command(card, 1, 2, 3, 4, b"foo") == b"bar"
    assert sent == [[1, 2, 3, 4, 3, 0x66, 0x6F, 0x6F]]


def test_send_simple_command_when_failure():
    card, sent = mock_card_and_command([], 0x12, 0x34)
    with pytest.raises(PGPCardException) as e:
        send_simple_command(card, 1, 2, 3, 4, b"foo")
    assert e.value.sw_code == 0x1234


def test_send_simple_command_when_get_response_empty():
    card = MagicMock()
    sent = mock_card_commands(
        card,
        (bytearray(b"bar"), 0x61, 0x03),
        (bytearray(0), 0x61, 0x00),
    )

    assert send_simple_command(card, 1, 2, 3, 4, b"foo") == b"bar"

    assert sent == [
        [1, 2, 3, 4, 3, 0x66, 0x6F, 0x6F],
        [1, 0xC0, 0, 0, 3],
    ]


def test_send_simple_command_when_get_response_once():
    card = MagicMock()
    sent = mock_card_commands(
        card,
        (bytearray(0), 0x61, 0x03),
        (bytearray(b"bar"), 0x90, 0x00),
    )

    assert send_simple_command(card, 1, 2, 3, 4, b"foo") == b"bar"

    assert sent == [
        [1, 2, 3, 4, 3, 0x66, 0x6F, 0x6F],
        [1, 0xC0, 0, 0, 3],
    ]


def test_send_simple_command_when_get_response_multiple():
    card = MagicMock()
    foo = bytearray(b"foo")
    bar = bytearray(b"bar")
    baz = bytearray(b"baz")
    sent = mock_card_commands(
        card,
        (foo, 0x61, 0x06),
        (bar, 0x61, 0x03),
        (baz, 0x90, 0x00),
    )

    assert send_simple_command(card, 1, 2, 3, 4, b"foo") == b"foobarbaz"

    assert sent == [
        [1, 2, 3, 4, 3, 0x66, 0x6F, 0x6F],
        [1, 0xC0, 0, 0, 6],
        [1, 0xC0, 0, 0, 3],
    ]
    assert foo == b"\0\0\0"
    assert bar == b"\0\0\0"
    assert baz == b"\0\0\0"


def test_send_command_and_zero_when_success(caplog):
    card, sent = mock_card_and_command([6, 7, 8], 9, 0)
    command = [1, 2, 3, 4, 5, 11, 12, 13, 14, 15]

    with caplog.at_level(DEBUG):
        assert _send_command_and_zero(card, command) == ([6, 7, 8], 9, 0)

    assert sent == [[1, 2, 3, 4, 5, 11, 12, 13, 14, 15]]
    assert command == [0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    assert caplog.text.find("sending command to card: 1 2 3 4 + 5 bytes") >= 0
    assert caplog.text.find("received response from card: 9 0 + 3 bytes") >= 0


def test_send_command_and_zero_when_failure():
    card = MagicMock()
    card.connection.transmit.side_effect = ConnectionException("test")
    command = [1, 2, 3, 4, 5, 11, 12, 13, 14, 15]

    with pytest.raises(ConnectionException):
        _send_command_and_zero(card, command)

    assert command == [0, 0, 0, 0, 0, 0, 0, 0, 0, 0]


def test_verify_pin_when_success():
    card, sent = mock_card_and_command([])
    verify_pin(card, bytearray(b"foo"))
    assert sent == [[0, 0x20, 0, 0x82, 3, 0x66, 0x6F, 0x6F]]


def test_verify_pin_when_pin_failure():
    card, sent = mock_card_and_command([], 0x63, 0xC1)
    with pytest.raises(PinException, match="1 try left"):
        verify_pin(card, bytearray(b"foo"))


def test_verify_pin_when_other_failure():
    card, sent = mock_card_and_command([], 0x65, 0x81)
    with pytest.raises(PGPCardException):
        verify_pin(card, bytearray(b"foo"))


def test_calculate_x25519_shared_secret_when_success():
    public_key = bytearray.fromhex(EXAMPLE_KEY_HEX)
    card, sent = mock_card_and_command(b"test")

    assert calculate_x25519_shared_secret(card, public_key) == b"test"

    assert sent == [DECIPHER_EXAMPLE_KEY_COMMAND]


def test_calculate_x25519_shared_secret_when_pin_required():
    card, sent = mock_card_and_command([], 0x69, 0x82)
    with pytest.raises(PGPCardException):
        calculate_x25519_shared_secret(card, bytearray.fromhex(EXAMPLE_KEY_HEX))


def test_calculate_shared_secret_when_pin_required():
    public_key = bytearray.fromhex(EXAMPLE_KEY_HEX)
    card, sent = mock_card_and_commands(
        ([], 0x69, 0x82),
        ([], 0x90, 0x00),
        (b"test", 0x90, 0x00),
    )

    assert calculate_shared_secret(card, public_key, bytearray(b"foo")) == b"test"

    assert sent == [
        DECIPHER_EXAMPLE_KEY_COMMAND,
        [0, 0x20, 0, 0x82, 3, 0x66, 0x6F, 0x6F],
        DECIPHER_EXAMPLE_KEY_COMMAND,
    ]


def test_calculate_shared_secret_when_pin_failure():
    public_key = bytearray.fromhex(EXAMPLE_KEY_HEX)
    card, sent = mock_card_and_commands(
        ([], 0x69, 0x82),
        ([], 0x63, 0xC1),
    )

    with pytest.raises(PinException, match="1 try left"):
        calculate_shared_secret(card, public_key, bytearray(b"foo"))


def test_calculate_shared_secret_when_other_failure():
    public_key = bytearray.fromhex(EXAMPLE_KEY_HEX)
    card, sent = mock_card_and_command([], 0x65, 0x81)

    with pytest.raises(PGPCardException):
        calculate_shared_secret(card, public_key, bytearray(b"foo"))


def test_cli_test_card_when_success(five_cards_mock, mocker):
    card = five_cards_mock[1]
    mocker.patch("openpgpcard_x25519_agent.card.getpass", return_value="foo")
    mocker.patch("openpgpcard_x25519_agent.card.format_card_info", return_value="test")

    sent = mock_card_commands(
        card,
        ([], 0x69, 0x82),
        ([], 0x90, 0x00),
        (b"test", 0x90, 0x00),
    )

    cli_test_card()

    assert sent == [
        DECIPHER_TEST_CARD_COMMAND,
        [0, 0x20, 0, 0x82, 3, 0x66, 0x6F, 0x6F],
        DECIPHER_TEST_CARD_COMMAND,
    ]


def test_get_key_type_when_app_data_missing():
    card = MagicMock()
    card.get_application_data.return_value = {}

    assert not get_key_type(card)


def test_get_key_type_when_known_curve():
    card = MagicMock()
    card.get_application_data.return_value = {"73": {"C2": "122B656F"}}

    assert get_key_type(card) == "x448"


def test_get_key_type_from_app_data_when_missing():
    assert not get_key_type_from_app_data({})


def test_get_key_type_from_app_data_when_known_curve():
    assert get_key_type_from_app_data({"73": {"C2": "122B656F"}}) == "x448"


def test_get_key_type_from_algorithm_attributes_when_none_or_too_short():
    assert not get_key_type_from_algorithm_attributes(None)
    assert get_key_type_from_algorithm_attributes("") == ""
    assert get_key_type_from_algorithm_attributes("01") == "01"


def test_get_key_type_from_algorithm_attributes_when_unknown():
    assert get_key_type_from_algorithm_attributes("12345678") == "12345678"


def test_get_key_type_from_algorithm_attributes_when_rsa():
    assert get_key_type_from_algorithm_attributes("010800001100") == "rsa2048"
    assert get_key_type_from_algorithm_attributes("010C00001100") == "rsa3072"
    assert get_key_type_from_algorithm_attributes("011000001100") == "rsa4096"


def test_get_key_type_from_algorithm_attributes_when_known_curve():
    assert get_key_type_from_algorithm_attributes("122B060104019755010501") == "x25519"
    assert get_key_type_from_algorithm_attributes("162B06010401DA470F01") == "ed25519"
    assert get_key_type_from_algorithm_attributes("132A8648CE3D030107") == "nistp256"


def test_get_curve25519_key_when_key_missing():
    card = MagicMock()
    card.get_public_key.return_value = b""

    with pytest.raises(DataException):
        get_curve25519_key(card)


def test_get_curve25519_key_when_key_invalid():
    card = MagicMock()
    card.get_public_key.return_value = b"1234578"

    with pytest.raises(DataException):
        get_curve25519_key(card)


def test_get_curve25519_key_when_key_good():
    card = MagicMock()
    card.get_public_key.return_value = bytes.fromhex(f"7F49 22 86 20 {EXAMPLE_KEY_HEX}")

    assert get_curve25519_key(card) == bytes.fromhex(EXAMPLE_KEY_HEX)

    card.get_public_key.assert_called_with("B800")


def test_format_curve25519_key_when_key_missing():
    card = MagicMock()
    card.get_public_key.return_value = b""

    assert format_curve25519_key(card) == "error"


def test_format_curve25519_key_when_unknown_card_exception():
    card = MagicMock()
    card.get_public_key.side_effect = PGPCardException(0, 0)

    assert format_curve25519_key(card) == "card error"


def test_format_curve25519_key_when_known_card_exception():
    card = MagicMock()
    card.get_public_key.side_effect = PGPCardException(0x65, 0x81)

    assert format_curve25519_key(card) == "memory failure"


def test_format_curve25519_key_when_key_good():
    card = MagicMock()
    card.get_public_key.return_value = bytes.fromhex(f"7F49 22 86 20 {EXAMPLE_KEY_HEX}")

    assert format_curve25519_key(card) == "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg="

    card.get_public_key.assert_called_with("B800")


def test_format_pin_status_when_blocked():
    card = MagicMock()
    card.get_pin_status.return_value = 0

    assert format_pin_status(card) == "0 tries remaining"


def test_format_pin_status_when_unlocked():
    card = MagicMock()
    card.get_pin_status.return_value = 0x9000

    assert format_pin_status(card) == "unlocked"

    card.get_pin_status.assert_called_with(1)


def test_format_card_info():
    card = MagicMock()
    card.get_application_data.return_value = {
        "73": {
            "C1": "162B06010401DA470F01",
            "C2": "122B060104019755010501",
            "C3": "010800001100",
        },
    }
    card.get_pin_status.return_value = 3
    card.get_public_key.return_value = bytes.fromhex(f"7F49 22 86 20 {EXAMPLE_KEY_HEX}")

    card.index = 2
    card.name = "foo"
    card.serial = 63
    card.manufacturer_id = "0x0042"
    card.manufacturer = "GnuPG"
    card.pgpverstr = "3.4"

    assert (
        format_card_info(card)
        == f"""
Card Index: 0x2
Card Name: foo
Serial Number: 0x3f
Manufacturer: 0x0042 (GnuPG)
OpenPGP Version: 3.4
Signature Key: ed25519
Encryption Key: x25519 ({EXAMPLE_KEY_64})
Authentication Key: rsa2048
PIN Status: 3 tries remaining
    """.strip()
    )


def test_format_cards_info_when_none(mocker):
    mocker.patch("openpgpcard_x25519_agent.card.format_card_info", return_value="test")
    assert format_cards_info([]) == "no cards"


def test_format_cards_info_when_multiple(mocker):
    mocker.patch("openpgpcard_x25519_agent.card.format_card_info", return_value="test")

    assert (
        format_cards_info([object(), object(), object()])
        == """
test
----------
test
----------
test
    """.strip()
    )


def mock_card_commands(card, *results):
    """Mocks the connection.transmit() method of the specified card for multiple calls.

    Arguments:
        card (Mock): Card.
        results (list): List of (data, status_1, status_2) result tuples.

    Returns:
        list: List to be populated with data sent by each command call.
    """
    commands = []
    results = list(results)
    card.connection.transmit.side_effect = (
        lambda command: _mock_card_commands_side_effect(results, commands, command)
    )
    return commands


def _mock_card_commands_side_effect(results, commands, command):
    commands.append(command.copy())
    if not results:
        return ([], 0, 0)
    return results.pop(0)


def mock_card_and_commands(*results):
    """Mocks the connection.transmit() method of the specified card for multiple calls.

    Arguments:
        results (list): List of (data, status_1, status_2) result tuples.

    Returns:
        Mock: Card mock.
        list: List to be populated with data sent by each command call.
    """
    card = MagicMock()
    return card, mock_card_commands(card, *results)


def mock_card_command(card, output, status_1=0x90, status_2=0x00):
    """Mocks the connection.transmit() method of the specified card for one call.

    Arguments:
        card (Mock): Card.
        output (list): Output data to return from call.
        status_1 (int): Status byte 1 to return from call.
        status_2 (int): Status byte 2 to return from call.

    Returns:
        list: List to be populated with data sent by the command call.
    """
    return mock_card_commands(card, (output, status_1, status_2))


def mock_card_and_command(output, status_1=0x90, status_2=0x00):
    """Mocks a card and the connection.transmit() method for it for one call.

    Arguments:
        output (list): Output data to return from call.
        status_1 (int): Status byte 1 to return from call.
        status_2 (int): Status byte 2 to return from call.

    Returns:
        Mock: Card mock.
        list: List to be populated with data sent by the command call.
    """
    card = MagicMock()
    return card, mock_card_command(card, output, status_1, status_2)
