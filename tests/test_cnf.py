"""Unit tests for configuration utilities."""

from openpgpcard_x25519_agent.cnf import (
    DEFAULT_LOG_FORMAT,
    DEFAULT_LOG_LEVEL,
    DEFAULT_SOCKET,
    get_server_socket_file_descriptor,
    get_socket_path,
    init_log,
)


def test_init_log_with_no_defaults(mocker, monkeypatch):
    monkeypatch.setenv("OPENPGPCARD_X25519_AGENT_LOG_FORMAT", "")
    monkeypatch.setenv("OPENPGPCARD_X25519_AGENT_LOG_LEVEL", "")
    basic_config = mocker.patch("logging.basicConfig")

    init_log()

    basic_config.assert_called_once_with(
        format=DEFAULT_LOG_FORMAT, level=DEFAULT_LOG_LEVEL
    )


def test_init_log_with_env_defaults(mocker, monkeypatch):
    monkeypatch.setenv("OPENPGPCARD_X25519_AGENT_LOG_FORMAT", "%(asctime)s %(message)s")
    monkeypatch.setenv("OPENPGPCARD_X25519_AGENT_LOG_LEVEL", "info")
    basic_config = mocker.patch("logging.basicConfig")

    init_log()

    basic_config.assert_called_once_with(format="%(asctime)s %(message)s", level="INFO")


def test_init_log_with_root_level_and_env_defaults(mocker, monkeypatch):
    monkeypatch.setenv("OPENPGPCARD_X25519_AGENT_LOG_FORMAT", "%(asctime)s %(message)s")
    monkeypatch.setenv("OPENPGPCARD_X25519_AGENT_LOG_LEVEL", "INFO")
    basic_config = mocker.patch("logging.basicConfig")

    init_log("error")

    basic_config.assert_called_once_with(format="%(asctime)s %(message)s", level="INFO")


def test_init_log_with_root_level(mocker, monkeypatch):
    monkeypatch.setenv("OPENPGPCARD_X25519_AGENT_LOG_FORMAT", "")
    monkeypatch.setenv("OPENPGPCARD_X25519_AGENT_LOG_LEVEL", "")
    basic_config = mocker.patch("logging.basicConfig")

    init_log("error")

    basic_config.assert_called_once_with(format=DEFAULT_LOG_FORMAT, level="ERROR")


def test_init_log_with_info_verbosity(mocker, monkeypatch):
    monkeypatch.setenv("OPENPGPCARD_X25519_AGENT_LOG_FORMAT", "")
    monkeypatch.setenv("OPENPGPCARD_X25519_AGENT_LOG_LEVEL", "")
    basic_config = mocker.patch("logging.basicConfig")

    init_log(1)

    basic_config.assert_called_once_with(format=DEFAULT_LOG_FORMAT, level="INFO")


def test_init_log_with_debug_verbosity(mocker, monkeypatch):
    monkeypatch.setenv("OPENPGPCARD_X25519_AGENT_LOG_FORMAT", "")
    monkeypatch.setenv("OPENPGPCARD_X25519_AGENT_LOG_LEVEL", "")
    basic_config = mocker.patch("logging.basicConfig")

    init_log(2)

    basic_config.assert_called_once_with(format=DEFAULT_LOG_FORMAT, level="DEBUG")


def test_get_server_socket_file_descriptor_when_no_env_default_and_no_default():
    assert not get_server_socket_file_descriptor()


def test_get_server_socket_file_descriptor_when_no_env_default_and_path_default():
    assert not get_server_socket_file_descriptor("test.sock")


def test_get_server_socket_file_descriptor_when_no_env_default_and_descriptor_default():
    assert get_server_socket_file_descriptor("10") == 10


def test_get_server_socket_file_descriptor_when_env_default(monkeypatch):
    monkeypatch.setenv("LISTEN_FDS", "1")
    assert get_server_socket_file_descriptor("10") == 3


def test_get_socket_path_when_no_default():
    assert get_socket_path() == DEFAULT_SOCKET


def test_get_socket_path_when_default():
    assert get_socket_path("test.sock") == "test.sock"
