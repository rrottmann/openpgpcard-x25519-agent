"""Pytest configuration file."""

from unittest.mock import MagicMock

import pytest
from OpenPGPpy import ConnectionException


@pytest.fixture()
def card_mock(mocker):
    """Mocks OpenPGPcard for openpgpcard_x25519_agent.card package.

    Arguments:
        mocker: Pytest fixture.

    Returns:
        MagicMock: OpenPGPcard mock.
    """
    return mocker.patch("openpgpcard_x25519_agent.card.OpenPGPcard")


@pytest.fixture()
def all_cards_mock(mocker):
    """Mocks readers for openpgpcard_x25519_agent.card package.

    Arguments:
        mocker: Pytest fixture.

    Returns:
        MagicMock: readers mock.
    """
    return mocker.patch("openpgpcard_x25519_agent.card.readers", return_value=[])


@pytest.fixture()
def five_cards_mock(all_cards_mock, card_mock):
    """Mocks OpenPGPcard and readers with 5 mocks for card package.

    Arguments:
        all_cards_mock: Pytest fixture.
        card_mock: Pytest fixture.

    Returns:
        list: List of 5 "cards", (3 of which are exceptions).
    """
    source_cards = [
        ConnectionException("test 0"),
        MagicMock(),
        ConnectionException("test 2"),
        MagicMock(),
        ConnectionException("test 4"),
    ]
    all_cards_mock.return_value = list(source_cards)
    card_mock.side_effect = list(source_cards)
    return source_cards
