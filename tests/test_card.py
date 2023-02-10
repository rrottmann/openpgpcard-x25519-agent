"""Unit tests for card utilities."""

from unittest.mock import MagicMock

import pytest
from OpenPGPpy import ConnectionException, DataException, PGPCardException

from openpgpcard_x25519_agent.card import (
    count_all_cards,
    format_card_info,
    format_cards_info,
    format_curve25519_key,
    format_pin_status,
    get_card_by_id,
    get_card_by_index,
    get_card_by_index_or_none,
    get_curve25519_key,
    get_key_type,
    get_key_type_from_algorithm_attributes,
    get_key_type_from_app_data,
    list_all_cards,
)

EXAMPLE_KEY_HEX = "C53201039ADBA14BE71F886DA1D8DBE9EEBDED08CB111B75340078999AA9F038"
EXAMPLE_KEY_64 = "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg="


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
