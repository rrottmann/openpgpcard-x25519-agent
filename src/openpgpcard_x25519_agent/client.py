"""Client utilities."""

import base64
import sys
from getpass import getpass
from io import BytesIO
from logging import getLogger
from re import fullmatch
from socket import AF_UNIX, SOCK_STREAM, socket

from openpgpcard_x25519_agent.cnf import get_socket_path
from openpgpcard_x25519_agent.msg import (
    ADD_SMARTCARD_KEY,
    DERIVE_SHARED_SECRET,
    REMOVE_SMARTCARD_KEY,
    REQUEST_EXTENSION,
    REQUEST_PUBLIC_KEY,
    SUCCESS,
    Message,
)


def set_pin(pin, lifetime=0, socket_path=None, seat=None):
    """Sets the PIN for the specified seat.

    Arguments:
        pin (bytearray): PIN (zeros after sending).
        lifetime (int): Seconds to cache PIN; 0 for infinite (default: 0).
        socket_path (str): Path to socket file.
        seat (int): Card seat number (default: 0).

    Returns:
        bool: True if successful.
    """
    request = Message(message_type=ADD_SMARTCARD_KEY)
    request.constrain_lifetime = lifetime
    request.pin = pin
    response = send_to_agent(request, socket_path, seat)
    return response.message_type == SUCCESS


def input_pin(source=None, socket_path=None, seat=None, prompt=None, lifetime=None):
    """Reads in a PIN, and sets it for the specified seat.

    Arguments:
        source: File path to read for PIN; blank or '-' for stdin.
        socket_path (str): Path to socket file.
        seat (int): Card seat number (default: 0).
        prompt (bool): True to prompt instead of read input.
        lifetime (int): Seconds to cache PIN; 0 for infinite (default: 0).

    Returns:
        bool: True if successful.
    """
    return set_pin(
        read_pin(source, prompt),
        parse_duration_as_seconds(lifetime),
        socket_path,
        seat,
    )


def clear_pin(socket_path=None, seat=None):
    """Clears the PIN for the specified seat.

    Arguments:
        socket_path (str): Path to socket file.
        seat (int): Card seat number (default: 0).

    Returns:
        bool: True if successful.
    """
    request = Message(message_type=REMOVE_SMARTCARD_KEY)
    request.pin = bytearray(0)
    response = send_to_agent(request, socket_path, seat)
    return response.message_type == SUCCESS


def get_public_key(socket_path=None, seat=None):
    """Retreives the public key for the specified seat.

    Arguments:
        socket_path (str): Path to socket file.
        seat (int): Card seat number (default: 0).

    Returns:
        bytearray: 32-byte public key.
    """
    request = Message(message_type=REQUEST_EXTENSION)
    request.extension_type = REQUEST_PUBLIC_KEY
    response = send_to_agent(request, socket_path, seat)
    return getattr(response, "public_key", bytearray(0))


def print_public_key(socket_path=None, seat=None, output=None):
    """Prints the public key for the specified card seat.

    Arguments:
        socket_path (str): Agent socket path.
        seat (int): Card seat number (default: 0).
        output (IOBase): Output stream (default: stdout).

    Returns:
        bool: True if successful.
    """
    public_key = get_public_key(socket_path, seat)
    return print_and_zero_bytearray(public_key, output)


def derive_shared_secret(public_key, socket_path=None, seat=None):
    """Derives a shared secret with the public key for the specified seat.

    Arguments:
        public_key (bytearray): 32-byte public key (of the other party).
        socket_path (str): Path to socket file.
        seat (int): Card seat number (default: 0).

    Returns:
        bytearray: 32-byte shared secret (caller must zero after use).
    """
    request = Message(message_type=REQUEST_EXTENSION)
    request.extension_type = DERIVE_SHARED_SECRET
    request.public_key = public_key
    response = send_to_agent(request, socket_path, seat)

    shared_secret = getattr(response, "shared_secret", bytearray(0)).copy()
    response.zero()
    return shared_secret


def print_shared_secret(
    source=None, socket_path=None, seat=None, prompt=None, output=None
):
    """Reads a public key, and derives a shared secret with it for the specified seat.

    Arguments:
        source: File path to read for public key; blank or '-' for stdin.
        socket_path (str): Path to socket file.
        seat (int): Card seat number (default: 0).
        prompt (bool): True to prompt instead of read input.
        output (IOBase): Output stream (default: stdout).

    Returns:
        bool: True if successful.
    """
    shared_secret = derive_shared_secret(
        read_public_key(source, prompt),
        socket_path,
        seat,
    )
    return print_and_zero_bytearray(shared_secret, output)


def format_reader_id(seat):
    """Formats the specified seat as reader ID.

    Arguments:
        seat (int): Card seat number (default: 0).

    Returns:
        str: Formatted reader ID.
    """
    return f"{int(seat):x}" if seat else "0"


def parse_duration_as_seconds(duration):
    """Parses the specified duration as seconds.

    Arguments:
        duration (str): Duration (ex: '30m' or '2.5h').

    Returns:
        int: Duration as seconds.

    Raises:
        ValueError: If invalid duration format.
    """
    if not duration:
        return 0
    if isinstance(duration, int) or isinstance(duration, float):
        return int(duration)

    result = fullmatch(r"((?:\d*\.)?\d+)\s*(\w+)?", duration)
    if not result:
        raise ValueError(f"invalid duration: {duration}")

    return calculate_duration_as_seconds(float(result[1]), result[2])


def calculate_duration_as_seconds(value, units=None):
    """Calculates the seconds in the specified duration.

    Arguments:
        value (int): Duration value.
        units (str): Duration units (ex: 'm' or 'H' or 'days').

    Returns:
        int: Duration as seconds.

    Raises:
        ValueError: If invalid duration units.
    """
    if not units or units[0] in "sS":
        return int(value)
    elif units[0] in "mM":
        return int(value * 60)
    elif units[0] in "hH":
        return int(value * 60 * 60)
    elif units[0] in "dD":
        return int(value * 60 * 60 * 24)
    else:
        raise ValueError(f"invalid duration units: {units}")


def read_pin(source=None, prompt=False):
    """Reads in a PIN as a bytearray.

    Arguments:
        source: File path to read; blank or '-' for stdin (default: stdin).
        prompt (bool): True to prompt instead of read input.

    Returns:
        bytearray: PIN.
    """
    if prompt:
        return bytearray(getpass("PIN: ").encode())
    return read_bytearray(source)


def read_public_key(source=None, prompt=False, output=None):
    """Reads in base64-encoded public key as a bytearray.

    Arguments:
        source: File path to read; blank or '-' for stdin (default: stdin).
        prompt (bool): True to prompt instead of read input.
        output (IOBase): Prompt stream (default: stdout).

    Returns:
        bytearray: Decoded public-key bytes.

    Raises:
        ValueError: If content read is not a 32-byte base64-encoded public key.
    """
    if prompt:
        source = None
        output = output or sys.stdout.buffer
        output.write(b"Public key: ")
        output.flush()

    decoded = base64.b64decode(read_line(source), validate=True)
    if len(decoded) != 32:
        raise ValueError("input not a 32-byte base64-encoded public key")

    return bytearray(decoded)


def read_bytearray(source=None, max_length=None):
    """Reads in content as a bytearray.

    Arguments:
        source: File path to read; blank or '-' for stdin (default: stdin).
        max_length (int): Max bytes to read (default: 100).

    Returns:
        bytearray: Content.
    """
    buffer = bytearray(max_length or 100)
    length = readinto_bytearray(buffer, source)

    # strip trailing line endings
    while length > 0 and buffer[length - 1] in b"\r\n":
        length -= 1

    return memoryview(buffer)[:length]


def readinto_bytearray(buffer, source=None):
    """Reads in content to an existing bytearray.

    Arguments:
        buffer (bytearray): Buffer to read into.
        source: File path to read; blank or '-' for stdin (default: stdin).

    Returns:
        int: Bytes read.
    """
    if not source or source == "-":
        source = sys.stdin.buffer

    if hasattr(source, "readinto"):
        return source.readinto(buffer)

    with open(source, "rb") as f:
        return f.readinto(buffer)


def read_line(source=None, max_length=100):
    """Reads a single line as a string.

    Arguments:
        source: File path to read; blank or '-' for stdin (default: stdin).
        max_length (int): Max bytes to read (default: 100).

    Returns:
        str: Line.
    """
    if not source or source == "-":
        source = sys.stdin.buffer

    if hasattr(source, "readline"):
        return source.readline(max_length or 100).decode().rstrip("\r\n")

    with open(source) as f:
        return f.readline(max_length or 100).rstrip("\r\n")


def print_and_zero_bytearray(buffer, output=None):
    """Base64-encodes and prints the specified bytearray, then zeros it.

    Arguments:
        buffer (bytearray): Bytearray to print.
        output (IOBase): Output stream (default: stdout).

    Returns:
        bool: If not blank.
    """
    if buffer:
        print_bytearray(buffer, output)
        buffer[:] = bytearray(len(buffer))
        return True
    return False


def print_bytearray(buffer, output=None):
    """Base64-encodes and prints the specified bytearray.

    Arguments:
        buffer (bytearray): Bytearray to print.
        output (IOBase): Output stream (default: stdout).
    """
    output = output or sys.stdout.buffer
    with BytesIO(buffer) as b:
        base64.encode(b, output)


def send_to_agent(request, socket_path=None, seat=None):
    """Sends the specified message to the specified socket.

    Arguments:
        request (Message): Request to send.
        socket_path (str): Path to socket file.
        seat (int): Card seat number (default: 0).

    Returns:
        Message: Response received.

    Raises:
        Exception: If error opening or using socket.
    """
    response = Message()
    if request.message_type == REQUEST_EXTENSION:
        response.extension_type = request.extension_type

    try:
        request.reader_id = format_reader_id(seat)
        connection = _open_connection(socket_path)
    except Exception as e:
        request.zero()
        raise e

    try:
        request.send(connection)
    except Exception as e:
        _close_connection(connection)
        raise e
    finally:
        request.zero()

    try:
        response.receive(connection)
    except Exception as e:
        response.zero()
        raise e
    finally:
        _close_connection(connection)

    return response


def _open_connection(socket_path):
    socket_path = get_socket_path(socket_path)
    getLogger(__name__).debug("connecting to %s", socket_path)
    connection = socket(AF_UNIX, SOCK_STREAM)
    connection.connect(str(socket_path))
    connection.settimeout(5.0)
    return connection


def _close_connection(connection):
    try:
        connection.close()
    except Exception:
        getLogger(__name__).warning("error closing connection", exc_info=True)
