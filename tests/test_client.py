"""Unit tests for client utilities."""

from io import BytesIO
from socket import AF_UNIX, SOCK_STREAM, socket
from unittest.mock import MagicMock

import pytest

from openpgpcard_x25519_agent.client import (
    clear_pin,
    derive_shared_secret,
    format_reader_id,
    get_public_key,
    input_pin,
    parse_duration_as_seconds,
    print_and_zero_bytearray,
    print_bytearray,
    print_public_key,
    print_shared_secret,
    read_bytearray,
    read_line,
    read_pin,
    read_public_key,
    readinto_bytearray,
    send_to_agent,
    set_pin,
)
from openpgpcard_x25519_agent.msg import (
    ADD_SMARTCARD_KEY,
    DERIVE_SHARED_SECRET,
    FAILURE_MESSAGE,
    REMOVE_SMARTCARD_KEY,
    REQUEST_EXTENSION,
    REQUEST_PUBLIC_KEY,
    SUCCESS_MESSAGE,
    Message,
)

EXAMPLE_KEY_HEX = "C53201039ADBA14BE71F886DA1D8DBE9EEBDED08CB111B75340078999AA9F038"
EXAMPLE_KEY_64 = "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg="


@pytest.fixture()
def server(tmp_path):
    """Starts a listening server socket.

    Arguments:
        tmp_path: Pytest fixture.

    Yields:
        socket: Listening socket.
    """
    sock = socket(AF_UNIX, SOCK_STREAM)
    sock.bind(str(tmp_path / "test.sock"))
    sock.listen()
    try:
        yield sock
    finally:
        sock.close()


def test_set_pin_when_no_options(mocker):
    send_mock = mocker.patch(
        "openpgpcard_x25519_agent.client.send_to_agent", return_value=SUCCESS_MESSAGE
    )

    assert set_pin(bytearray(b"foo"))

    request = send_mock.call_args.args[0]
    assert request.message_type == ADD_SMARTCARD_KEY
    assert request.pin == b"foo"
    assert request.constrain_lifetime == 0
    assert not send_mock.call_args.args[1]
    assert not send_mock.call_args.args[2]


def test_input_pin_when_no_options(mocker):
    send_mock = mocker.patch(
        "openpgpcard_x25519_agent.client.send_to_agent", return_value=FAILURE_MESSAGE
    )
    source = BytesIO(b"test")

    assert not input_pin(source, "foo", "bar", False, "30m")

    request = send_mock.call_args.args[0]
    assert request.message_type == ADD_SMARTCARD_KEY
    assert request.pin == b"test"
    assert request.constrain_lifetime == 1800
    assert send_mock.call_args.args[1] == "foo"
    assert send_mock.call_args.args[2] == "bar"


def test_clear_pin_when_no_options(mocker):
    send_mock = mocker.patch(
        "openpgpcard_x25519_agent.client.send_to_agent", return_value=SUCCESS_MESSAGE
    )

    assert clear_pin()

    request = send_mock.call_args.args[0]
    assert request.message_type == REMOVE_SMARTCARD_KEY
    assert request.pin == b""
    assert not send_mock.call_args.args[1]
    assert not send_mock.call_args.args[2]


def test_clear_pin_when_all_options(mocker):
    send_mock = mocker.patch(
        "openpgpcard_x25519_agent.client.send_to_agent", return_value=FAILURE_MESSAGE
    )

    assert not clear_pin("foo", "bar")

    request = send_mock.call_args.args[0]
    assert request.message_type == REMOVE_SMARTCARD_KEY
    assert request.pin == b""
    assert send_mock.call_args.args[1] == "foo"
    assert send_mock.call_args.args[2] == "bar"


def test_get_public_key_when_no_options(mocker):
    response = Message()
    response.public_key = bytearray(b"foo")
    send_mock = mocker.patch(
        "openpgpcard_x25519_agent.client.send_to_agent", return_value=response
    )

    assert get_public_key() == b"foo"

    request = send_mock.call_args.args[0]
    assert request.message_type == REQUEST_EXTENSION
    assert request.extension_type == REQUEST_PUBLIC_KEY
    assert not send_mock.call_args.args[1]
    assert not send_mock.call_args.args[2]


def test_print_public_key_when_all_options(mocker):
    response = Message()
    response.public_key = bytearray(b"\0\0\1")
    send_mock = mocker.patch(
        "openpgpcard_x25519_agent.client.send_to_agent", return_value=response
    )
    output = BytesIO()

    assert print_public_key("foo", "bar", output)

    request = send_mock.call_args.args[0]
    assert request.message_type == REQUEST_EXTENSION
    assert request.extension_type == REQUEST_PUBLIC_KEY
    assert send_mock.call_args.args[1] == "foo"
    assert send_mock.call_args.args[2] == "bar"
    assert output.getvalue() == b"AAAB\n"


def test_derive_shared_secret_when_no_options(mocker):
    response = Message()
    shared_secret = bytearray(b"foo")
    response.shared_secret = shared_secret
    send_mock = mocker.patch(
        "openpgpcard_x25519_agent.client.send_to_agent", return_value=response
    )

    assert derive_shared_secret(b"bar") == b"foo"

    request = send_mock.call_args.args[0]
    assert request.message_type == REQUEST_EXTENSION
    assert request.extension_type == DERIVE_SHARED_SECRET
    assert request.public_key == b"bar"
    assert not send_mock.call_args.args[1]
    assert not send_mock.call_args.args[2]

    assert shared_secret == b"\0\0\0"
    assert response.shared_secret == b""


def test_print_shared_secret_when_all_options(mocker):
    response = Message()
    shared_secret = bytearray(b"\0\0\1")
    response.shared_secret = shared_secret
    send_mock = mocker.patch(
        "openpgpcard_x25519_agent.client.send_to_agent", return_value=response
    )
    source = BytesIO(f"{EXAMPLE_KEY_64}\n".encode())
    output = BytesIO()

    assert print_shared_secret(source, "foo", "bar", False, output)

    request = send_mock.call_args.args[0]
    assert request.message_type == REQUEST_EXTENSION
    assert request.extension_type == DERIVE_SHARED_SECRET
    assert request.public_key == bytearray.fromhex(EXAMPLE_KEY_HEX)
    assert send_mock.call_args.args[1] == "foo"
    assert send_mock.call_args.args[2] == "bar"
    assert output.getvalue() == b"AAAB\n"

    assert shared_secret == b"\0\0\0"
    assert response.shared_secret == b""


@pytest.mark.parametrize(
    "seat, reader_id",
    [
        (None, "0"),
        ("", "0"),
        (0, "0"),
        ("0", "0"),
        (1, "1"),
        ("1", "1"),
        (10, "a"),
        ("10", "a"),
    ],
)
def test_format_reader_id_when_parsable(seat, reader_id):
    assert format_reader_id(seat) == reader_id


def test_format_reader_id_when_garbage():
    with pytest.raises(ValueError, match="invalid literal"):
        assert format_reader_id("foo")


def test_format_reader_id_when_blank():
    assert format_reader_id("") == "0"


def test_format_reader_id_when_zero():
    assert format_reader_id("") == "0"


@pytest.mark.parametrize(
    "duration, seconds",
    [
        (None, 0),
        ("", 0),
        ("0", 0),
        (0, 0),
        (10, 10),
        ("10", 10),
        ("10s", 10),
        ("10S", 10),
        ("10 sec", 10),
        (2.5, 2),
        ("2.5s", 2),
        ("10m", 600),
        ("10M", 600),
        ("10 min", 600),
        ("2.5m", 150),
        ("10h", 36_000),
        ("10H", 36_000),
        ("10 hr", 36_000),
        ("2.5h", 9_000),
        ("10d", 864_000),
        ("10D", 864_000),
        ("10 days", 864_000),
        ("2.5d", 216_000),
    ],
)
def test_parse_lifetime_when_parsable(duration, seconds):
    assert parse_duration_as_seconds(duration) == seconds


@pytest.mark.parametrize("duration", ["foo", "-1", "h1", "1x"])
def test_parse_lifetime_when_garbage(duration):
    with pytest.raises(ValueError, match="invalid duration"):
        assert parse_duration_as_seconds(duration)


def test_read_pin_when_prompt(mocker):
    mocker.patch("openpgpcard_x25519_agent.client.getpass", return_value="foo")
    assert read_pin(prompt=True) == b"foo"


def test_read_pin_when_no_prompt():
    assert read_pin(BytesIO(b"foo\n")) == b"foo"


def test_read_public_key_when_prompt(capsys, mocker):
    stdin = mocker.patch("sys.stdin")
    stdin.buffer = BytesIO(f"{EXAMPLE_KEY_64}\n".encode())
    public_key = bytearray.fromhex(EXAMPLE_KEY_HEX)
    assert read_public_key(BytesIO(b"foo"), True) == public_key

    out, err = capsys.readouterr()
    assert out == "Public key: "


def test_read_public_key_when_no_prompt():
    public_key = bytearray.fromhex(EXAMPLE_KEY_HEX)
    assert read_public_key(BytesIO(f"{EXAMPLE_KEY_64}\n".encode())) == public_key


def test_read_public_key_when_no_prompt_and_not_base64_encoded():
    with pytest.raises(ValueError, match="Incorrect padding"):
        assert read_public_key(BytesIO(b"foo\nbar\nbaz"))


def test_read_public_key_when_no_prompt_and_wrong_key_length():
    with pytest.raises(ValueError, match="not a 32-byte"):
        assert read_public_key(BytesIO(b"AAAB\n"))


def test_read_bytearray_when_source_buffer_is_empty():
    assert read_bytearray(BytesIO()) == b""


def test_read_bytearray_when_source_buffer_is_short():
    assert read_bytearray(BytesIO(b"foo\nbar")) == b"foo\nbar"


def test_read_bytearray_when_source_buffer_is_long():
    assert read_bytearray(BytesIO(b"foo\nbar"), 3) == b"foo"


def test_read_bytearray_when_source_buffer_has_trailing_newline():
    assert read_bytearray(BytesIO(b"foo\n")) == b"foo"


def test_read_bytearray_when_source_buffer_is_only_newlines():
    assert read_bytearray(BytesIO(b"\n\n\n")) == b""


def test_readinto_bytearray_when_source_buffer_is_empty():
    buffer = bytearray(3)
    assert readinto_bytearray(buffer, BytesIO()) == 0
    assert buffer == b"\0\0\0"


def test_readinto_bytearray_when_source_buffer_is_short():
    buffer = bytearray(10)
    assert readinto_bytearray(buffer, BytesIO(b"foo\nbar")) == 7
    assert buffer == b"foo\nbar\0\0\0"


def test_readinto_bytearray_when_source_buffer_is_long():
    buffer = bytearray(3)
    assert readinto_bytearray(buffer, BytesIO(b"foo\nbar")) == 3
    assert buffer == b"foo"


def test_readinto_bytearray_when_source_file_is_empty(tmp_path):
    buffer = bytearray(3)
    source = tmp_path / "test.txt"
    source.write_text("")

    assert readinto_bytearray(buffer, source) == 0

    assert buffer == b"\0\0\0"


def test_readinto_bytearray_when_source_file_is_short(tmp_path):
    buffer = bytearray(10)
    source = tmp_path / "test.txt"
    source.write_text("foo\nbar")

    assert readinto_bytearray(buffer, source) == 7

    assert buffer == b"foo\nbar\0\0\0"


def test_readinto_bytearray_when_source_file_is_long(tmp_path):
    buffer = bytearray(3)
    source = tmp_path / "test.txt"
    source.write_text("foo\nbar")

    assert readinto_bytearray(buffer, source) == 3

    assert buffer == b"foo"


def test_readinto_bytearray_when_string_source(tmp_path):
    buffer = bytearray(10)
    source = tmp_path / "test.txt"
    source.write_text("foo\nbar")

    assert readinto_bytearray(buffer, str(source)) == 7

    assert buffer == b"foo\nbar\0\0\0"


def test_readinto_bytearray_when_default_source(mocker):
    stdin = mocker.patch("sys.stdin")
    stdin.buffer = BytesIO(b"foo\nbar")
    buffer = bytearray(10)

    assert readinto_bytearray(buffer) == 7

    assert buffer == b"foo\nbar\0\0\0"


def test_readinto_bytearray_when_dash_source(mocker):
    stdin = mocker.patch("sys.stdin")
    stdin.buffer = BytesIO(b"foo\nbar")
    buffer = bytearray(10)

    assert readinto_bytearray(buffer, "-") == 7

    assert buffer == b"foo\nbar\0\0\0"


def test_read_line_when_buffer_empty():
    assert not read_line(BytesIO())


def test_read_line_when_buffer_contains_short_first_line():
    assert read_line(BytesIO(b"foo\nbar\nbaz")) == "foo"


def test_read_line_when_buffer_contains_long_first_line():
    assert read_line(BytesIO(b"foobarbaz\nqux"), 6) == "foobar"


def test_read_line_when_buffer_surrounded_by_whitespace():
    assert read_line(BytesIO(b"  foo  ")) == "  foo  "


def test_read_line_when_file_empty(tmp_path):
    source = tmp_path / "test.txt"
    source.write_text("")
    assert not read_line(source)


def test_read_line_when_file_contains_short_first_line(tmp_path):
    source = tmp_path / "test.txt"
    source.write_text("foo\nbar\nbaz")
    assert read_line(source) == "foo"


def test_read_line_when_file_contains_long_first_line(tmp_path):
    source = tmp_path / "test.txt"
    source.write_text("foobarbaz\nqux")
    assert read_line(source, 6) == "foobar"


def test_read_line_when_file_surrounded_by_whitespace(tmp_path):
    source = tmp_path / "test.txt"
    source.write_text("  foo  ")
    assert read_line(source) == "  foo  "


def test_read_line_when_file_string_source(tmp_path):
    source = tmp_path / "test.txt"
    source.write_text("foo\nbar\nbaz")
    assert read_line(str(source)) == "foo"


def test_read_line_when_dash_source(mocker):
    stdin = mocker.patch("sys.stdin")
    stdin.buffer = BytesIO(b"foo\nbar\nbaz")
    assert read_line("-") == "foo"


def test_read_line_when_default_source(mocker):
    stdin = mocker.patch("sys.stdin")
    stdin.buffer = BytesIO(b"foo\nbar\nbaz")
    assert read_line() == "foo"


def test_print_and_zero_bytearray_when_empty():
    source = bytearray(0)
    output = BytesIO()

    assert not print_and_zero_bytearray(source, output)

    assert source == bytearray(0)
    assert not output.getvalue()


def test_print_and_zero_bytearray_when_not_empty():
    source = bytearray(b"\0\0\1")
    output = BytesIO()

    assert print_and_zero_bytearray(source, output)

    assert source == bytearray(b"\0\0\0")
    assert output.getvalue() == b"AAAB\n"


def test_print_bytearray_when_empty():
    output = BytesIO()
    print_bytearray(bytearray(0), output)
    assert not output.getvalue()


def test_print_bytearray_when_not_empty():
    output = BytesIO()
    print_bytearray(bytearray(b"\0\0\1"), output)
    assert output.getvalue() == b"AAAB\n"


def test_print_bytearray_when_default_output(capsys):
    print_bytearray(bytearray(b"\0\0\1"))
    out, err = capsys.readouterr()
    assert out == "AAAB\n"


def test_send_to_agent_when_successful(mocker, server):
    request = MagicMock()
    mocker.patch("openpgpcard_x25519_agent.client.Message")

    response = send_to_agent(request, server.getsockname())

    assert request.reader_id == "0"
    request.send.assert_called_once()
    request.zero.assert_called_once()
    response.receive.assert_called_once()
    response.zero.assert_not_called()
    assert not isinstance(response.extension_type, str)


def test_send_to_agent_when_request_extension(mocker, server):
    request = MagicMock()
    request.message_type = REQUEST_EXTENSION
    request.extension_type = REQUEST_PUBLIC_KEY
    mocker.patch("openpgpcard_x25519_agent.client.Message")

    response = send_to_agent(request, server.getsockname())

    assert request.reader_id == "0"
    request.send.assert_called_once()
    request.zero.assert_called_once()
    response.receive.assert_called_once()
    response.zero.assert_not_called()
    assert response.extension_type == REQUEST_PUBLIC_KEY


def test_send_to_agent_when_seat_is_garbage(mocker, server):
    request = MagicMock()
    response = MagicMock()
    mocker.patch("openpgpcard_x25519_agent.client.Message", return_value=response)

    with pytest.raises(ValueError, match="invalid literal"):
        send_to_agent(request, server.getsockname(), "foo")

    request.send.assert_not_called()
    request.zero.assert_called_once()
    response.receive.assert_not_called()
    response.zero.assert_not_called()


def test_send_to_agent_when_connect_fails(mocker, tmp_path):
    request = MagicMock()
    response = MagicMock()
    mocker.patch("openpgpcard_x25519_agent.client.Message", return_value=response)

    with pytest.raises(FileNotFoundError):
        send_to_agent(request, tmp_path / "test.sock")

    request.send.assert_not_called()
    request.zero.assert_called_once()
    response.receive.assert_not_called()
    response.zero.assert_not_called()


def test_send_to_agent_when_send_fails(mocker):
    request = MagicMock()
    response = MagicMock()
    request.send.side_effect = ConnectionError("test")
    mocker.patch("openpgpcard_x25519_agent.client.Message", return_value=response)

    connection = MagicMock()
    open_connection = mocker.patch("openpgpcard_x25519_agent.client._open_connection")
    open_connection.return_value = connection

    with pytest.raises(ConnectionError):
        send_to_agent(request)

    open_connection.assert_called_once()
    connection.close.assert_called_once()
    request.send.assert_called_once()
    request.zero.assert_called_once()
    response.receive.assert_not_called()
    response.zero.assert_not_called()


def test_send_to_agent_when_receive_fails(mocker):
    request = MagicMock()
    response = MagicMock()
    response.receive.side_effect = ConnectionError("test")
    mocker.patch("openpgpcard_x25519_agent.client.Message", return_value=response)

    connection = MagicMock()
    open_connection = mocker.patch("openpgpcard_x25519_agent.client._open_connection")
    open_connection.return_value = connection

    with pytest.raises(ConnectionError):
        send_to_agent(request)

    open_connection.assert_called_once()
    connection.close.assert_called_once()
    request.send.assert_called_once()
    request.zero.assert_called_once()
    response.receive.assert_called_once()
    response.zero.assert_called_once()


def test_send_to_agent_when_close_fails(mocker):
    request = MagicMock()
    mocker.patch("openpgpcard_x25519_agent.client.Message")

    connection = MagicMock()
    open_connection = mocker.patch("openpgpcard_x25519_agent.client._open_connection")
    open_connection.return_value = connection
    connection.close.side_effect = ConnectionError("test")

    response = send_to_agent(request)

    open_connection.assert_called_once()
    connection.close.assert_called_once()
    request.send.assert_called_once()
    request.zero.assert_called_once()
    response.receive.assert_called_once()
    response.zero.assert_not_called()
