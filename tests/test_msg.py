"""Unit tests for message utilities."""

from unittest.mock import MagicMock

import pytest

from openpgpcard_x25519_agent.msg import (
    ADD_SMARTCARD_KEY,
    ADD_SMARTCARD_KEY_CONSTRAINED,
    DERIVE_SHARED_SECRET,
    EXTENSION_FAILURE,
    EXTENSION_FAILURE_MESSAGE,
    FAILURE,
    FAILURE_MESSAGE,
    REMOVE_SMARTCARD_KEY,
    REQUEST_EXTENSION,
    REQUEST_PUBLIC_KEY,
    SUCCESS,
    SUCCESS_MESSAGE,
    Message,
    MessageError,
)

EXAMPLE_KEY_HEX = "C53201039ADBA14BE71F886DA1D8DBE9EEBDED08CB111B75340078999AA9F038"


def test_send():
    socket = MagicMock()
    SUCCESS_MESSAGE.send(socket)
    assert socket.send.called_with(bytearray.fromhex("00000001"))
    assert socket.sendall.called_with(bytearray.fromhex("06"))


def test_receive():
    socket = mock_receiving_socket(["00000001"], ["06"])
    msg = Message()
    msg.receive(socket)
    assert msg.buffer == b"\x06"
    assert msg.message_type == SUCCESS


def test_send_from_buffer_when_empty_buffer():
    socket = MagicMock()
    Message().send_from_buffer(socket)
    assert socket.send.called_with(bytearray.fromhex("00000000"))
    assert socket.sendall.called_with(bytearray(0))


def test_send_from_buffer_when_too_long_buffer():
    socket = MagicMock()
    Message(100000).send_from_buffer(socket)
    assert socket.send.called_with(bytearray.fromhex("00000001"))
    assert socket.sendall.called_with(bytearray.fromhex("05"))


def test_send_from_buffer_when_extension_response_too_long_buffer():
    socket = MagicMock()
    Message(100000, extension_type="foo").send_from_buffer(socket)
    assert socket.send.called_with(bytearray.fromhex("00000001"))
    assert socket.sendall.called_with(bytearray.fromhex("1C"))


def test_receive_into_buffer_when_multiple_recv_into_calls():
    socket = mock_receiving_socket(["00000025"], ["06", "00000020", EXAMPLE_KEY_HEX])
    msg = Message()
    msg.extension_type = REQUEST_PUBLIC_KEY
    msg.receive_into_buffer(socket)
    assert msg.buffer == bytearray.fromhex(f"06 00000020 {EXAMPLE_KEY_HEX}")


def test_receive_into_buffer_when_length_too_long():
    socket = mock_receiving_socket(["0001 0000"], [])
    with pytest.raises(MessageError, match="too long: 65536"):
        Message().receive_into_buffer(socket)


def test_receive_into_buffer_when_length_field_too_short():
    socket = mock_receiving_socket(["0001"], [])
    with pytest.raises(MessageError, match="invalid message length"):
        Message().receive_into_buffer(socket)


def test_parse_empty_message():
    with pytest.raises(MessageError, match="empty message"):
        Message().parse_from_buffer()


def test_format_unimplemented_message_type():
    with pytest.raises(MessageError, match="unimplemented message type"):
        Message().format_into_buffer()


def test_parse_unimplemented_message_type():
    with pytest.raises(MessageError, match="unimplemented message type"):
        Message(b"\0").parse_from_buffer()


def test_format_unimplemented_extension_type():
    with pytest.raises(MessageError, match="unimplemented extension type"):
        Message(message_type=REQUEST_EXTENSION).format_into_buffer()


def test_parse_unimplemented_extension_type():
    with pytest.raises(MessageError, match="unimplemented extension type"):
        Message("1B 00000000").parse_from_buffer()


def test_parse_extension_type_length_too_short():
    with pytest.raises(MessageError, match="message too short"):
        Message("1B 0001").parse_from_buffer()


def test_parse_extension_type_too_short():
    with pytest.raises(MessageError, match="message too short"):
        Message("1B 00000003 00").parse_from_buffer()


def test_format_unimplemented_extension_response():
    with pytest.raises(MessageError, match="unimplemented extension type"):
        Message(message_type=SUCCESS, extension_type="foo").format_into_buffer()


def test_parse_unimplemented_extension_response():
    with pytest.raises(MessageError, match="unimplemented extension type"):
        Message("06", extension_type="foo").parse_from_buffer()


def test_format_success():
    msg = SUCCESS_MESSAGE
    msg.zero()
    msg.format_into_buffer()
    assert msg.buffer == b"\x06"
    # ensure success message can be sent again and again, even after zeroing
    msg.zero()
    assert msg.buffer == b""
    msg.format_into_buffer()
    assert msg.buffer == b"\x06"
    msg.format_into_buffer()
    assert msg.buffer == b"\x06"


def test_parse_success():
    msg = Message(b"\x06")
    msg.parse_from_buffer()
    assert msg.message_type == SUCCESS
    assert not msg.extension_type


def test_format_failure():
    msg = FAILURE_MESSAGE
    msg.zero()
    msg.format_into_buffer()
    assert msg.buffer == b"\x05"


def test_parse_failure():
    msg = Message(b"\x05")
    msg.parse_from_buffer()
    assert msg.message_type == FAILURE
    assert not msg.extension_type


def test_format_extension_failure():
    msg = EXTENSION_FAILURE_MESSAGE
    msg.zero()
    msg.format_into_buffer()
    assert msg.buffer == b"\x1C"


def test_parse_extension_failure():
    msg = Message(b"\x1C")
    msg.parse_from_buffer()
    assert msg.message_type == EXTENSION_FAILURE
    assert not msg.extension_type


def test_format_respond_with_public_key():
    msg = Message()
    msg.message_type = SUCCESS
    msg.extension_type = REQUEST_PUBLIC_KEY
    msg.public_key = bytearray.fromhex(EXAMPLE_KEY_HEX)
    msg.format_into_buffer()
    assert msg.buffer == bytearray.fromhex(f"06 00000020 {EXAMPLE_KEY_HEX}")


def test_parse_respond_with_public_key():
    msg = Message(f"06 00000020 {EXAMPLE_KEY_HEX}")
    msg.extension_type = REQUEST_PUBLIC_KEY
    msg.parse_from_buffer()
    assert msg.message_type == SUCCESS
    assert msg.public_key == bytearray.fromhex(EXAMPLE_KEY_HEX)


def test_parse_respond_with_public_key_when_too_short():
    msg = Message("06 00000020 00")
    msg.extension_type = REQUEST_PUBLIC_KEY
    with pytest.raises(MessageError, match="wrong length"):
        msg.parse_from_buffer()


def test_parse_respond_with_public_key_when_field_length_indicates_too_short():
    msg = Message(f"06 0000001F {EXAMPLE_KEY_HEX}")
    msg.extension_type = REQUEST_PUBLIC_KEY
    with pytest.raises(MessageError, match="wrong length"):
        msg.parse_from_buffer()


def test_parse_respond_with_public_key_when_too_long():
    msg = Message(f"06 00000020 {EXAMPLE_KEY_HEX} 00")
    msg.extension_type = REQUEST_PUBLIC_KEY
    with pytest.raises(MessageError, match="wrong length"):
        msg.parse_from_buffer()


def test_format_respond_with_shared_secret():
    msg = Message()
    msg.message_type = SUCCESS
    msg.extension_type = DERIVE_SHARED_SECRET
    msg.shared_secret = bytearray.fromhex(EXAMPLE_KEY_HEX)
    msg.format_into_buffer()
    assert msg.buffer == bytearray.fromhex(f"06 00000020 {EXAMPLE_KEY_HEX}")


def test_parse_respond_with_shared_secret():
    msg = Message(f"06 00000020 {EXAMPLE_KEY_HEX}")
    msg.extension_type = DERIVE_SHARED_SECRET
    msg.parse_from_buffer()
    assert msg.message_type == SUCCESS
    assert msg.shared_secret == bytearray.fromhex(EXAMPLE_KEY_HEX)


def test_parse_respond_with_shared_secret_when_too_short():
    msg = Message("06 00000020 00")
    msg.extension_type = DERIVE_SHARED_SECRET
    with pytest.raises(MessageError, match="wrong length"):
        msg.parse_from_buffer()


def test_parse_respond_with_shared_secret_when_field_length_indicates_too_short():
    msg = Message(f"06 0000001F {EXAMPLE_KEY_HEX}")
    msg.extension_type = DERIVE_SHARED_SECRET
    with pytest.raises(MessageError, match="wrong length"):
        msg.parse_from_buffer()


def test_parse_respond_with_shared_secret_when_too_long():
    msg = Message(f"06 00000020 {EXAMPLE_KEY_HEX} 00")
    msg.extension_type = DERIVE_SHARED_SECRET
    with pytest.raises(MessageError, match="wrong length"):
        msg.parse_from_buffer()


def test_format_request_public_key():
    msg = Message()
    msg.message_type = REQUEST_EXTENSION
    msg.extension_type = REQUEST_PUBLIC_KEY
    msg.reader_id = "3"
    msg.format_into_buffer()
    assert msg.buffer == bytearray.fromhex(
        "1B 0000000A 7832353531392F707562 00000001 33"
    )


def test_parse_request_public_key():
    msg = Message("1B 0000000A 7832353531392F707562 00000001 33")
    msg.parse_from_buffer()
    assert msg.message_type == REQUEST_EXTENSION
    assert msg.extension_type == REQUEST_PUBLIC_KEY
    assert msg.reader_id == "3"


def test_parse_request_public_key_when_too_short():
    msg = Message("1B 0000000A 7832353531392F707562")
    with pytest.raises(MessageError, match="expected at least 19, but was: 15"):
        msg.parse_from_buffer()


def test_parse_request_public_key_when_too_long():
    msg = Message("1B 0000000A 7832353531392F707562 00000001 33 00")
    with pytest.raises(MessageError, match="expected 20, but was: 21"):
        msg.parse_from_buffer()


def test_format_derive_shared_secret():
    msg = Message()
    msg.message_type = REQUEST_EXTENSION
    msg.extension_type = DERIVE_SHARED_SECRET
    msg.reader_id = "3"
    msg.public_key = bytearray.fromhex(EXAMPLE_KEY_HEX)
    msg.format_into_buffer()
    assert msg.buffer == bytearray.fromhex(
        f"1B 00000009 7832353531392F6468 00000001 33 00000020 {EXAMPLE_KEY_HEX}"
    )


def test_parse_derive_shared_secret():
    msg = Message(
        f"1B 00000009 7832353531392F6468 00000001 33 00000020 {EXAMPLE_KEY_HEX}"
    )
    msg.parse_from_buffer()
    assert msg.message_type == REQUEST_EXTENSION
    assert msg.extension_type == DERIVE_SHARED_SECRET
    assert msg.reader_id == "3"
    assert msg.public_key == bytearray.fromhex(EXAMPLE_KEY_HEX)


def test_parse_derive_shared_secret_when_no_reader_id():
    msg = Message("1B 00000009 7832353531392F6468")
    with pytest.raises(MessageError, match="expected at least 18, but was: 14"):
        msg.parse_from_buffer()


def test_parse_derive_shared_secret_when_reader_id_length_field_too_short():
    msg = Message("1B 00000009 7832353531392F6468 0033")
    with pytest.raises(MessageError, match="expected at least 18, but was: 16"):
        msg.parse_from_buffer()


def test_parse_derive_shared_secret_when_reader_id_length_field_indicates_too_long():
    msg = Message("1B 00000009 7832353531392F6468 00000002 33")
    with pytest.raises(MessageError, match="expected at least 20, but was: 19"):
        msg.parse_from_buffer()


def test_parse_derive_shared_secret_when_public_key_length_field_too_short():
    msg = Message("1B 00000009 7832353531392F6468 00000001 33 0020")
    with pytest.raises(MessageError, match="expected at least 23, but was: 21"):
        msg.parse_from_buffer()


def test_parse_derive_shared_secret_when_public_key_length_field_indicates_too_short():
    msg = Message(
        f"1B 00000009 7832353531392F6468 00000001 33 0000001F {EXAMPLE_KEY_HEX}"
    )
    with pytest.raises(MessageError, match="expected 54, but was: 55"):
        msg.parse_from_buffer()


def test_parse_derive_shared_secret_when_public_key_length_field_indicates_too_long():
    msg = Message(
        f"1B 00000009 7832353531392F6468 00000001 33 00000021 {EXAMPLE_KEY_HEX}"
    )
    with pytest.raises(MessageError, match="expected at least 56, but was: 55"):
        msg.parse_from_buffer()


def test_parse_derive_shared_secret_when_public_key_length_too_short():
    msg = Message("1B 00000009 7832353531392F6468 00000001 33 00000020 00")
    with pytest.raises(MessageError, match="expected at least 55, but was: 24"):
        msg.parse_from_buffer()


def test_parse_derive_shared_secret_when_public_key_length_too_long():
    msg = Message(
        f"1B 00000009 7832353531392F6468 00000001 33 00000020 {EXAMPLE_KEY_HEX} 00"
    )
    with pytest.raises(MessageError, match="expected 55, but was: 56"):
        msg.parse_from_buffer()


def test_format_remove_smartcard_key():
    msg = Message()
    msg.message_type = REMOVE_SMARTCARD_KEY
    msg.reader_id = "3"
    msg.pin = bytearray(b"foo")
    msg.format_into_buffer()
    assert msg.buffer == bytearray.fromhex("15 00000001 33 00000003 666F6F")


def test_parse_remove_smartcard_key():
    msg = Message("15 00000001 33 00000003 666F6F")
    msg.parse_from_buffer()
    assert msg.message_type == REMOVE_SMARTCARD_KEY
    assert not msg.extension_type
    assert msg.reader_id == "3"
    assert msg.pin == b"foo"


def test_parse_remove_smartcard_key_when_no_reader_id():
    msg = Message("15")
    with pytest.raises(MessageError, match="expected at least 5, but was: 1"):
        msg.parse_from_buffer()


def test_parse_remove_smartcard_key_when_no_pin():
    msg = Message("15 00000001 33")
    with pytest.raises(MessageError, match="expected at least 10, but was: 6"):
        msg.parse_from_buffer()


def test_parse_remove_smartcard_key_when_too_long():
    msg = Message("15 00000001 33 00000003 666F6F 00")
    with pytest.raises(MessageError, match="expected 13, but was: 14"):
        msg.parse_from_buffer()


def test_format_add_smartcard_key_when_no_constraints():
    msg = Message()
    msg.message_type = ADD_SMARTCARD_KEY
    msg.reader_id = "3"
    msg.pin = bytearray(b"foo")
    msg.format_into_buffer()
    assert msg.buffer == bytearray.fromhex("14 00000001 33 00000003 666F6F")


def test_format_add_smartcard_key_when_empty_constraints():
    msg = Message()
    msg.message_type = ADD_SMARTCARD_KEY_CONSTRAINED
    msg.reader_id = "3"
    msg.pin = bytearray(b"foo")
    msg.constrain_lifetime = 0
    msg.constrain_confirm = False
    msg.format_into_buffer()
    assert msg.buffer == bytearray.fromhex("14 00000001 33 00000003 666F6F")


def test_format_add_smartcard_key_when_constrain_lifetime():
    msg = Message()
    msg.message_type = ADD_SMARTCARD_KEY
    msg.reader_id = "3"
    msg.pin = bytearray(b"foo")
    msg.constrain_lifetime = 3600
    msg.format_into_buffer()
    assert msg.buffer == bytearray.fromhex("1A 00000001 33 00000003 666F6F 01 00000e10")


def test_format_add_smartcard_key_when_constrain_confirm():
    msg = Message()
    msg.message_type = ADD_SMARTCARD_KEY_CONSTRAINED
    msg.reader_id = "3"
    msg.pin = bytearray(b"foo")
    msg.constrain_confirm = True
    msg.format_into_buffer()
    assert msg.buffer == bytearray.fromhex("1A 00000001 33 00000003 666F6F 02")


def test_parse_add_smartcard_key_when_no_constraints():
    msg = Message("14 00000001 33 00000003 666F6F")
    msg.parse_from_buffer()
    assert msg.message_type == ADD_SMARTCARD_KEY
    assert not msg.extension_type
    assert msg.reader_id == "3"
    assert msg.pin == b"foo"
    assert not hasattr(msg, "constrain_lifetime")
    assert not hasattr(msg, "constrain_confirm")


def test_parse_add_smartcard_key_constrained_when_constrain_lifetime():
    msg = Message("1A 00000001 33 00000003 666F6F 01 00000E10")
    msg.parse_from_buffer()
    assert msg.message_type == ADD_SMARTCARD_KEY_CONSTRAINED
    assert not msg.extension_type
    assert msg.reader_id == "3"
    assert msg.pin == b"foo"
    assert msg.constrain_lifetime == 3600
    assert not hasattr(msg, "constrain_confirm")


def test_parse_add_smartcard_key_constrained_when_constrain_confirm():
    msg = Message("1A 00000001 33 00000003 666F6F 02")
    msg.parse_from_buffer()
    assert msg.message_type == ADD_SMARTCARD_KEY_CONSTRAINED
    assert not msg.extension_type
    assert msg.reader_id == "3"
    assert msg.pin == b"foo"
    assert not hasattr(msg, "constrain_lifetime")
    assert msg.constrain_confirm


def test_parse_add_smartcard_key_constrained_when_constrain_lifetime_and_confirm():
    msg = Message("1A 00000001 33 00000003 666F6F 01 00000E10 02")
    msg.parse_from_buffer()
    assert msg.message_type == ADD_SMARTCARD_KEY_CONSTRAINED
    assert not msg.extension_type
    assert msg.reader_id == "3"
    assert msg.pin == b"foo"
    assert msg.constrain_lifetime == 3600
    assert msg.constrain_confirm


def test_parse_add_smartcard_key_constrained_when_constrain_confirm_and_lifetime():
    msg = Message("1A 00000001 33 00000003 666F6F 02 01 00000E10")
    msg.parse_from_buffer()
    assert msg.message_type == ADD_SMARTCARD_KEY_CONSTRAINED
    assert not msg.extension_type
    assert msg.reader_id == "3"
    assert msg.pin == b"foo"
    assert msg.constrain_lifetime == 3600
    assert msg.constrain_confirm


def test_parse_add_smartcard_key_when_no_reader_id():
    msg = Message("14")
    with pytest.raises(MessageError, match="expected at least 5, but was: 1"):
        msg.parse_from_buffer()


def test_parse_add_smartcard_key_when_no_pin():
    msg = Message("14 00000001 33")
    with pytest.raises(MessageError, match="expected at least 10, but was: 6"):
        msg.parse_from_buffer()


def test_parse_add_smartcard_key_when_constrain_confirm():
    msg = Message("14 00000001 33 00000003 666F6F 02")
    with pytest.raises(MessageError, match="expected 13, but was: 14"):
        msg.parse_from_buffer()


def test_parse_add_smartcard_key_constrained_when_no_reader_id():
    msg = Message("1A")
    with pytest.raises(MessageError, match="expected at least 5, but was: 1"):
        msg.parse_from_buffer()


def test_parse_add_smartcard_key_constrained_when_no_pin():
    msg = Message("1A 00000001 33")
    with pytest.raises(MessageError, match="expected at least 10, but was: 6"):
        msg.parse_from_buffer()


def test_parse_add_smartcard_key_constrained_when_lifetime_too_short():
    msg = Message("1A 00000001 33 00000003 666F6F 01 0E10")
    with pytest.raises(MessageError, match="expected at least 18, but was: 16"):
        msg.parse_from_buffer()


def test_parse_add_smartcard_key_constrained_when_unimplemented_constraint():
    msg = Message("1A 00000001 33 00000003 666F6F 03")
    with pytest.raises(MessageError, match="unimplemented constraint type"):
        msg.parse_from_buffer()


def test_parse_add_smartcard_key_constrained_when_unimplemented_constraint_extension():
    msg = Message("1A 00000001 33 00000003 666F6F FF 00000003 626172")
    with pytest.raises(MessageError, match="unimplemented constraint extension"):
        msg.parse_from_buffer()


def test_insert_string_when_buffer_too_short_for_length():
    with pytest.raises(MessageError, match="buffer too short for string"):
        Message(6).insert_string("", 3)


def test_insert_string_when_buffer_too_short_for_string():
    with pytest.raises(MessageError, match="buffer too short for insert"):
        Message(8).insert_string("foo", 3)


def test_insert_string_when_source_too_short_for_length():
    with pytest.raises(MessageError, match="source too short for insert"):
        Message(20).insert_string("foo", 3, 6)


def test_insert_string_when_source_too_short_for_offset():
    with pytest.raises(MessageError, match="source too short for insert"):
        Message(20).insert_string("foo", 3, 3, 6)


def test_insert_string_with_string_object():
    buffer = bytearray.fromhex("FF FFFFFFFF FFFFFF FF")
    msg = Message(buffer)
    msg.insert_string("foo", 1)
    assert buffer == bytearray.fromhex("FF 00000003 666F6F FF")


def test_insert_string_with_bytes_object():
    buffer = bytearray.fromhex("FF FFFFFFFF FFFFFF FF")
    msg = Message(buffer)
    msg.insert_string(b"foo", 1)
    assert buffer == bytearray.fromhex("FF 00000003 666F6F FF")


def test_insert_string_with_bytearray_object():
    buffer = bytearray.fromhex("FF FFFFFFFF FFFFFF FF")
    msg = Message(buffer)
    msg.insert_string(bytearray(b"foo"), 1)
    assert buffer == bytearray.fromhex("FF 00000003 666F6F FF")


def test_insert_string_with_exact_size():
    buffer = bytearray(7)
    msg = Message(buffer)
    msg.insert_string("foo", 0)
    assert buffer == bytearray.fromhex("00000003 666F6F")


def test_insert_string_with_sub_string():
    buffer = bytearray.fromhex("FF FFFFFFFF FFFFFF FF")
    msg = Message(buffer)
    msg.insert_string("foobar", 1, 3, 1)
    assert buffer == bytearray.fromhex("FF 00000003 6F6F62 FF")


def test_insert_string_with_start_of_sub_string():
    buffer = bytearray.fromhex("FF FFFFFFFF FFFFFF FF")
    msg = Message(buffer)
    msg.insert_string("foobar", 1, 3)
    assert buffer == bytearray.fromhex("FF 00000003 666F6F FF")


def test_insert_string_with_end_of_sub_string():
    buffer = bytearray.fromhex("FF FFFFFFFF FFFFFF FF")
    msg = Message(buffer)
    msg.insert_string("foobar", 1, 3, 3)
    assert buffer == bytearray.fromhex("FF 00000003 626172 FF")


def test_insert_string_with_empty_string_into_exact_size():
    buffer = bytearray(4)
    msg = Message(buffer)
    msg.insert_string("", 0)
    assert buffer == bytearray.fromhex("00000000")


def test_insert_string_with_empty_string():
    buffer = bytearray.fromhex("FF FFFFFFFF FF")
    msg = Message(buffer)
    msg.insert_string("", 1)
    assert buffer == bytearray.fromhex("FF 00000000 FF")


def test_extract_string_with_exact_size():
    msg = Message("00000003 666F6F")
    assert msg.extract_string(0) == b"foo"


def test_extract_string_from_surrounding_buffer():
    msg = Message("FF 00000003 666F6F FF")
    assert msg.extract_string(1) == b"foo"


def test_extract_string_with_empty_string_of_exact_size():
    msg = Message("00000000")
    assert msg.extract_string(0) == b""


def test_extract_string_with_empty_string_from_surrounding_buffer():
    msg = Message("FF 00000000 FF")
    assert msg.extract_string(1) == b""


def test_zero():
    buffer = bytearray(b"foo")
    msg = Message(buffer)

    msg.zero()

    assert buffer == b"\0\0\0"
    assert msg.buffer == b""


def test_zero_when_sensitive_fields():
    buffer = bytearray(b"foo")
    msg = Message(buffer)
    pin = bytearray(b"bar")
    msg.pin = pin
    shared_secret = bytearray(b"baz")
    msg.shared_secret = shared_secret

    msg.zero()

    assert buffer == b"\0\0\0"
    assert msg.buffer == b""
    assert pin == b"\0\0\0"
    assert msg.pin == b""
    assert shared_secret == b"\0\0\0"
    assert msg.shared_secret == b""


def test_initialize_buffer_with_none():
    assert Message().buffer == bytearray(0)


def test_initialize_buffer_with_zero():
    assert Message(0).buffer == bytearray(0)


def test_initialize_buffer_with_empty_bytes():
    assert Message(b"").buffer == bytearray(0)


def test_initialize_buffer_with_empty_list():
    assert Message([]).buffer == bytearray(0)


def test_initialize_buffer_with_integer():
    assert Message(3).buffer == bytearray(b"\0\0\0")


def test_initialize_buffer_with_bytearray():
    assert Message(bytearray(b"foo")).buffer == bytearray.fromhex("66 6F 6F")


def test_initialize_buffer_with_bytes():
    assert Message(b"foo").buffer == bytearray.fromhex("66 6F 6F")


def test_initialize_buffer_with_list_of_bytes():
    assert Message([0x66, 0x6F, 0x6F]).buffer == bytearray.fromhex("66 6F 6F")


def test_initialize_buffer_with_tuple_of_bytes():
    assert Message((0x66, 0x6F, 0x6F)).buffer == bytearray.fromhex("66 6F 6F")


def test_initialize_buffer_with_hex_string():
    assert Message("66 6F 6F").buffer == bytearray.fromhex("66 6F 6F")


def mock_receiving_socket(recv, recv_into):
    """Mocks the receiving methods of a socket to return the specified content.

    Arguments:
        recv (list): Queue of bytes to return for `recv()`.
        recv_into (list): Queue of bytes to return for `recv_into()`.

    Returns:
        Mock: Socket mock.
    """
    recv = [bytearray.fromhex(x) if isinstance(x, str) else x for x in recv]
    recv_into = [bytearray.fromhex(x) if isinstance(x, str) else x for x in recv_into]

    socket = MagicMock()
    socket.recv.side_effect = recv
    socket.recv_into.side_effect = lambda buffer, _: _mock_socket_recv_into(
        recv_into, buffer
    )
    return socket


def _mock_socket_recv_into(queue, buffer):
    chunk = queue.pop(0)
    length = len(chunk)
    buffer[:length] = chunk
    return length
