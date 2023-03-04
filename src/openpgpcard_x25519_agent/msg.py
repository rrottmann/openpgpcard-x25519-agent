"""Message utilities."""

from logging import getLogger
from struct import pack, pack_into, unpack, unpack_from

# request message types
ADD_SMARTCARD_KEY = 20
ADD_SMARTCARD_KEY_CONSTRAINED = 26
REMOVE_SMARTCARD_KEY = 21
REQUEST_EXTENSION = 27

# response message types
SUCCESS = 6
FAILURE = 5
EXTENSION_FAILURE = 28

# constraint types
CONSTRAIN_LIFETIME = 1
CONSTRAIN_CONFIRM = 2
CONSTRAIN_EXTENSION = 255

# extension types
REQUEST_PUBLIC_KEY = "x25519/pub"  # noqa: S105
DERIVE_SHARED_SECRET = "x25519/dh"  # noqa: S105


class MessageError(Exception):
    """Signals an invalid message."""

    pass


class Message:
    """Agent request or response message.

    Attributes:
        buffer (bytearray): Temporary buffer for reading or writing to socket.
        message_type (int): SSH agent message-type code.
        extension_type (str): SSH agent extension-type string.

    Add Smartcard Key
    -----------------

    Client request attributes::

        message_type = 20
        reader_id = "0"
        pin = bytearray(b"123456")

    Add Smartcard Key With Constraints
    ----------------------------------

    Client request attributes::

        message_type = 26
        reader_id = "0"
        pin = bytearray(b"123456")
        constrain_lifetime = 3600
        constrain_confirm = False

    Remove Smartcard Key
    --------------------

    Client request attributes::

        message_type = 21
        reader_id = "0"
        pin = bytearray(b"")

    Request Public Key
    ------------------

    Client request attributes::

        message_type = 27
        extension_type = "x25519/pub"
        reader_id = "0"

    Server response attributes::

        message_type = 6
        extension_type = "x25519/pub"
        public_key = bytearray(b"(32-byte public-key data)")

    Derive Shared Secret
    --------------------

    Client request attributes (note that ``public_key`` in this case is the
    *other party's* public key)::

        message_type = 27
        extension_type = "x25519/dh"
        reader_id = "0"
        public_key = bytearray(b"(32-byte public-key data)")

    Server response attributes::

        message_type = 6
        extension_type = "x25519/dh"
        shared_secret = bytearray(b"(32-byte shared-secret data)")
    """

    def __init__(self, buffer=None, message_type=0, extension_type=""):
        """Creates a new message.

        Arguments:
            buffer: If bytes or bytearray, content for buffer.
                If a string, hex content for buffer.
                If an integer, buffer initialized with specified size.
                If None, buffer initialized to empty.
            message_type (int): Message type (eg 6 for success response).
            extension_type (str): Extension name (eg "x25519/dh").
        """
        self.buffer = bytearray(0)
        self.initialize_buffer(buffer)
        self.message_type = message_type
        self.extension_type = extension_type

    def send(self, socket):
        """Formats and writes message to the specified socket.

        Arguments:
            socket (Socket): Socket to write.

        Propagates:
            MessageError: If invalid message format.
        """
        self.format_into_buffer()
        self.send_from_buffer(socket)

    def receive(self, socket):
        """Reads and parses message from the specified socket.

        Arguments:
            socket (Socket): Socket to read.

        Propagates:
            MessageError: If invalid message format.
        """
        self.receive_into_buffer(socket)
        self.parse_from_buffer()

    def send_from_buffer(self, socket):
        """Writes all content from the buffer to the specified socket.

        Arguments:
            socket (Socket): Socket to write.

        Propagates:
            MessageError: If invalid message format.
        """
        length = len(self.buffer)
        # limit message sizes to 64 KB, even though they could be as long as 4 MB
        if length > 65535:
            self.log().error("sending failure, message too long: %s", length)
            if self.extension_type:
                EXTENSION_FAILURE_MESSAGE.send(socket)
            else:
                FAILURE_MESSAGE.send(socket)
            return

        socket.send(pack(">I", length))
        socket.sendall(self.buffer)

    def receive_into_buffer(self, socket):
        """Reads expected message length from the specified socket to the buffer.

        Arguments:
            socket (Socket): Socket to read.

        Raises:
            MessageError: If invalid message format.
        """
        self.zero()

        length_bytes = socket.recv(4)
        if len(length_bytes) != 4:
            raise MessageError(f"received invalid message length: {length_bytes.hex()}")

        length = unpack(">I", length_bytes)[0]
        # limit message sizes to 64 KB, even though they could be as long as 4 MB
        if length == 0 or length > 65535:
            raise MessageError(f"received message too long: {length}")

        self.initialize_buffer(length)
        view = memoryview(self.buffer)
        remaining = length

        while remaining:
            received = socket.recv_into(view, remaining)
            view = view[received:]
            remaining -= received

    # keep message-type switch statement together,
    # even if it makes cognitive complexity too high
    def format_into_buffer(self):  # noqa: CCR001
        """Replaces old buffer, formatting it with the configured message type.

        Attributes used:
            message_type (int): Message type.
            extension_type (str): Extension name.

        Raises:
            MessageError: If unimplemented extension type.
        """
        if self.message_type == SUCCESS and self.extension_type:
            self.format_extension_success()
        elif self.message_type == EXTENSION_FAILURE:
            self.format_extension_failure()
        elif self.message_type == REQUEST_EXTENSION:
            self.format_request_extension()
        elif self.message_type == SUCCESS:
            self.format_success()
        elif self.message_type == FAILURE:
            self.format_failure()
        elif self.message_type == ADD_SMARTCARD_KEY:
            self.format_add_smartcard_key()
        elif self.message_type == ADD_SMARTCARD_KEY_CONSTRAINED:
            self.format_add_smartcard_key()
        elif self.message_type == REMOVE_SMARTCARD_KEY:
            self.format_remove_smartcard_key()
        else:
            raise MessageError(
                f"sending unimplemented message type: {self.message_type}"
            )

    # keep message-type switch statement together,
    # even if it makes cognitive complexity too high
    def parse_from_buffer(self):  # noqa: CCR001
        """Parses full message from buffer.

        Attributes set:
            message_type (int): Message type.

        Attributes used:
            extension_type (str): Expected extension name.

        Raises:
            MessageError: If unimplemented message type.
        """
        if not self.buffer:
            raise MessageError("received empty message")

        self.message_type = int(self.buffer[0])

        if self.message_type == SUCCESS and self.extension_type:
            self.parse_extension_success()
        elif self.message_type == EXTENSION_FAILURE:
            self.log().info("parsing response with extension failure")
        elif self.message_type == REQUEST_EXTENSION:
            self.parse_request_extension()
        elif self.message_type == SUCCESS:
            self.log().info("parsing response with success")
        elif self.message_type == FAILURE:
            self.log().info("parsing response with failure")
        elif self.message_type == ADD_SMARTCARD_KEY:
            self.parse_add_smartcard_key()
        elif self.message_type == ADD_SMARTCARD_KEY_CONSTRAINED:
            self.parse_add_smartcard_key()
        elif self.message_type == REMOVE_SMARTCARD_KEY:
            self.parse_remove_smartcard_key()
        else:
            raise MessageError(
                f"received unimplemented message type: {self.message_type}"
            )

    def format_success(self):
        """Replaces old buffer, formatting it with a generic success message."""
        self.log().info("formatting response with success")
        self.initialize_buffer((SUCCESS,))

    def format_failure(self):
        """Replaces old buffer, formatting it with a generic failure message."""
        self.log().info("formatting response with failure")
        self.initialize_buffer((FAILURE,))

    def format_extension_failure(self):
        """Replaces old buffer, formatting it with an extension failure message."""
        self.log().info("formatting response with extension failure")
        self.initialize_buffer((EXTENSION_FAILURE,))

    def format_extension_success(self):
        """Replaces old buffer, formatting it with an extension response message.

        Attributes used:
            extension_type (str): Extension name.

        Raises:
            MessageError: If unimplemented extension type.
        """
        if self.extension_type == REQUEST_PUBLIC_KEY:
            self.format_respond_with_public_key()
        elif self.extension_type == DERIVE_SHARED_SECRET:
            self.format_respond_with_shared_secret()
        else:
            raise MessageError(
                "sending response to unimplemented extension type: "
                f"{self.extension_type}"
            )

    def parse_extension_success(self):
        """Parses extension response message from buffer.

        Attributes used:
            extension_type (str): Expected extension name.

        Raises:
            MessageError: If unimplemented extension type.
        """
        if self.extension_type == REQUEST_PUBLIC_KEY:
            self.parse_respond_with_public_key()
        elif self.extension_type == DERIVE_SHARED_SECRET:
            self.parse_respond_with_shared_secret()
        else:
            raise MessageError(
                "receiving response to unimplemented extension type: "
                f"{self.extension_type}"
            )

    def format_respond_with_public_key(self):
        """Replaces old buffer, formatting it with "request public key" response.

        Attributes used:
            public_key (bytearray): 32-byte public key.
        """
        self.log().info("formatting response with public key")
        self.initialize_buffer(1 + 4 + len(self.public_key))
        self.buffer[0] = SUCCESS
        self.insert_string(self.public_key, 1)

    def parse_respond_with_public_key(self):
        """Parses "request public key" response message from buffer.

        Attributes set:
            public_key (bytearray): 32-byte public key.

        Raises:
            MessageError: If buffer formatted incorrectly.
        """
        self.log().info("parsing response with public key")
        if len(self.buffer) != 37:
            raise MessageError(
                f"wrong length response to request public key: {len(self.buffer)}"
            )

        self.public_key = self.extract_string(1)
        if len(self.public_key) != 32:
            raise MessageError(f"wrong length for public key: {len(self.public_key)}")

    def format_respond_with_shared_secret(self):
        """Replaces old buffer, formatting it with "derive shared secret" response.

        Attributes used:
            shared_secret (bytearray): 32-byte shared secret.
        """
        self.log().info("formatting response with shared secret")
        self.initialize_buffer(1 + 4 + len(self.shared_secret))
        self.buffer[0] = SUCCESS
        self.insert_string(self.shared_secret, 1)

    def parse_respond_with_shared_secret(self):
        """Parses "derive shared secret" response message from buffer.

        Attributes set:
            shared_secret (bytearray): 32-byte shared secret.

        Raises:
            MessageError: If buffer formatted incorrectly.
        """
        self.log().info("parsing response with shared secret")
        if len(self.buffer) != 37:
            raise MessageError(
                f"wrong length response to derive shared secret: {len(self.buffer)}"
            )

        self.shared_secret = self.extract_string(1)
        if len(self.shared_secret) != 32:
            raise MessageError(
                f"wrong length for shared secret: {len(self.shared_secret)}"
            )

    def format_request_extension(self):
        """Replaces old buffer, formatting it with an extension request message.

        Attributes used:
            extension_type (str): Extension name.

        Raises:
            MessageError: If unimplemented extension type.
        """
        if self.extension_type == REQUEST_PUBLIC_KEY:
            self.format_request_public_key()
        elif self.extension_type == DERIVE_SHARED_SECRET:
            self.format_derive_shared_secret()
        else:
            raise MessageError(
                f"sending unimplemented extension type: {self.extension_type}"
            )

    def parse_request_extension(self):
        """Parses extension request message from buffer.

        Attributes set:
            extension_type (str): Extension name.

        Raises:
            MessageError: If unimplemented extension type.
        """
        self.extension_type = self.extract_string(1).decode()

        if self.extension_type == REQUEST_PUBLIC_KEY:
            self.parse_request_public_key()
        elif self.extension_type == DERIVE_SHARED_SECRET:
            self.parse_derive_shared_secret()
        else:
            raise MessageError(
                f"received unimplemented extension type: {self.extension_type}"
            )

    def format_request_public_key(self):
        """Replaces old buffer, formatting it with "request public key" request.

        Attributes used:
            reader_id (str): Reader ID.
        """
        self.log().info("formatting request for public key")
        extension_type_size = 4 + len(REQUEST_PUBLIC_KEY)
        reader_bytes = self.reader_id.encode()
        reader_id_size = 4 + len(reader_bytes)
        self.initialize_buffer(1 + extension_type_size + reader_id_size)

        offset = 0
        self.buffer[offset] = REQUEST_EXTENSION
        offset += 1
        self.insert_string(REQUEST_PUBLIC_KEY, offset)
        offset += extension_type_size
        self.insert_string(reader_bytes, offset)

    def parse_request_public_key(self):
        """Parses "request public key" request message from buffer.

        Attributes set:
            reader_id (str): Reader ID.

        Propagates:
            MessageError: If buffer formatted incorrectly.
        """
        self.log().info("parsing request for public key")
        extension_type_size = 4 + len(REQUEST_PUBLIC_KEY)
        offset = 1 + extension_type_size

        reader_bytes = self.extract_string(offset)
        self.reader_id = reader_bytes.decode()
        reader_id_size = 4 + len(reader_bytes)
        offset += reader_id_size

        self._assert_expected_buffer_size(offset, "request_public_key")

    def format_derive_shared_secret(self):
        """Replaces old buffer, formatting it with "derive shared secret" request.

        Attributes used:
            reader_id (str): Reader ID.
            public_key (bytearray): 32-byte public key.
        """
        self.log().info("formatting request to derive shared secret")
        extension_type_size = 4 + len(DERIVE_SHARED_SECRET)
        reader_bytes = self.reader_id.encode()
        reader_id_size = 4 + len(reader_bytes)
        public_key_size = 4 + len(self.public_key)
        self.initialize_buffer(
            1 + extension_type_size + reader_id_size + public_key_size
        )

        offset = 0
        self.buffer[offset] = REQUEST_EXTENSION
        offset += 1
        self.insert_string(DERIVE_SHARED_SECRET, offset)
        offset += extension_type_size
        self.insert_string(reader_bytes, offset)
        offset += reader_id_size
        self.insert_string(self.public_key, offset)

    def parse_derive_shared_secret(self):
        """Parses "derive shared secret" request message from buffer.

        Attributes set:
            reader_id (str): Reader ID.
            public_key (bytearray): 32-byte public key.

        Propagates:
            MessageError: If buffer formatted incorrectly.
        """
        self.log().info("parsing request to derive shared secret")
        extension_type_size = 4 + len(DERIVE_SHARED_SECRET)
        offset = 1 + extension_type_size

        reader_bytes = self.extract_string(offset)
        self.reader_id = reader_bytes.decode()
        reader_id_size = 4 + len(reader_bytes)
        offset += reader_id_size

        self.public_key = self.extract_string(offset)
        public_key_size = 4 + len(self.public_key)
        offset += public_key_size

        self._assert_expected_buffer_size(offset, "derive shared secret")

    def format_add_smartcard_key(self):
        """Replaces old buffer, formatting it with "add smartcard key" request.

        Attributes used:
            reader_id (str): Reader ID.
            pin (bytearray): PIN bytes.
            constrain_lifetime (int): Optional TTL in seconds.
            constrain_confirm (bool): Optionally true to require confirmations.
        """
        self.log().info("formatting request to add smartcard key")
        self.message_type = ADD_SMARTCARD_KEY
        reader_bytes = self.reader_id.encode()
        reader_id_size = 4 + len(reader_bytes)
        pin_size = 4 + len(self.pin)

        lifetime_size = 0
        lifetime = getattr(self, "constrain_lifetime", 0)
        if lifetime:
            lifetime_size = 5
            self.message_type = ADD_SMARTCARD_KEY_CONSTRAINED

        confirm_size = 0
        confirm = getattr(self, "constrain_confirm", False)
        if confirm:
            confirm_size = 1
            self.message_type = ADD_SMARTCARD_KEY_CONSTRAINED

        self.initialize_buffer(
            1 + reader_id_size + pin_size + lifetime_size + confirm_size
        )

        offset = 0
        self.buffer[offset] = self.message_type
        offset += 1
        self.insert_string(reader_bytes, offset)
        offset += reader_id_size
        self.insert_string(self.pin, offset)
        offset += pin_size
        if lifetime:
            pack_into(">BI", self.buffer, offset, CONSTRAIN_LIFETIME, lifetime)
            offset += lifetime_size
        if confirm:
            pack_into(">B", self.buffer, offset, CONSTRAIN_CONFIRM)

    def parse_add_smartcard_key(self):
        """Parses "add smartcard key" request message from buffer.

        Attributes set:
            reader_id (str): Reader ID.
            pin (bytearray): PIN bytes.
            constrain_lifetime (int): Optional TTL in seconds.
            constrain_confirm (bool): Optionally true to require confirmations.

        Propagates:
            MessageError: If buffer formatted incorrectly.
        """
        self.log().info("parsing request to add smartcard key")
        offset = 1

        reader_bytes = self.extract_string(offset)
        self.reader_id = reader_bytes.decode()
        reader_id_size = 4 + len(reader_bytes)
        offset += reader_id_size

        self.pin = self.extract_string(offset)
        pin_size = 4 + len(self.pin)
        offset += pin_size

        if self.message_type == ADD_SMARTCARD_KEY_CONSTRAINED:
            while offset < len(self.buffer):
                offset = self.parse_add_smartcard_key_constraint(offset)
        else:
            self._assert_expected_buffer_size(offset, "add smartcard key")

    def parse_add_smartcard_key_constraint(self, offset):
        """Parses a constraint from the buffer at the specified offset.

        Arguments:
            offset (int): Starting offset of this constraint.

        Returns:
            offset: Offset of next constraint.

        Raises:
            MessageError: If unimplemented constraint type.
        """
        constraint_type = self.buffer[offset]
        offset += 1

        if constraint_type == CONSTRAIN_LIFETIME:
            if len(self.buffer) < offset + 4:
                raise MessageError(
                    "message too short for seconds value; expected at least "
                    f"{offset + 4}, but was: {len(self.buffer)}"
                )
            self.constrain_lifetime = unpack_from(">I", self.buffer, offset)[0]
            return offset + 4
        elif constraint_type == CONSTRAIN_CONFIRM:
            self.constrain_confirm = True
            return offset
        elif constraint_type == CONSTRAIN_EXTENSION:
            extension_name = self.extract_string(offset)
            raise MessageError(
                f"received unimplemented constraint extension: {extension_name}"
            )
        else:
            raise MessageError(
                f"received unimplemented constraint type: {constraint_type}"
            )

    def format_remove_smartcard_key(self):
        """Replaces old buffer, formatting it with "remove smartcard key" request.

        Attributes used:
            reader_id (str): Reader ID.
            pin (bytearray): PIN bytes.
        """
        self.log().info("formatting request to remove smartcard key")
        reader_bytes = self.reader_id.encode()
        reader_id_size = 4 + len(reader_bytes)
        pin_size = 4 + len(self.pin)
        self.initialize_buffer(1 + reader_id_size + pin_size)

        offset = 0
        self.buffer[offset] = REMOVE_SMARTCARD_KEY
        offset += 1
        self.insert_string(reader_bytes, offset)
        offset += reader_id_size
        self.insert_string(self.pin, offset)

    def parse_remove_smartcard_key(self):
        """Parses "remove smartcard key" request message from buffer.

        Attributes set:
            reader_id (str): Reader ID.
            pin (bytearray): PIN bytes.

        Propagates:
            MessageError: If buffer formatted incorrectly.
        """
        self.log().info("parsing request to remove smartcard key")
        offset = 1

        reader_bytes = self.extract_string(offset)
        self.reader_id = reader_bytes.decode()
        reader_id_size = 4 + len(reader_bytes)
        offset += reader_id_size

        self.pin = self.extract_string(offset)
        pin_size = 4 + len(self.pin)
        offset += pin_size

        self._assert_expected_buffer_size(offset, "remove smartcard key")

    def insert(self, source, at_offset, source_length=0, source_offset=0):
        """Overwrites the buffer with the specified source bytes.

        Arguments:
            source (bytearray): Source of bytes.
            at_offset (int): Destination byte offset in buffer.
            source_length (int): Number of bytes to insert (default: source length).
            source_offset (int): Source byte offset (default: 0).

        Raises:
            MessageError: If buffer too short or source too short.
        """
        length = source_length or (len(source) - source_offset)
        if not length:
            return

        if len(self.buffer) < at_offset + length:
            raise MessageError(
                "buffer too short for insert; expected at least "
                f"{at_offset + length}, but was: {len(self.buffer)}"
            )
        if len(source) < source_offset + length:
            raise MessageError(
                "source too short for insert; expected at least "
                f"{source_offset + length}, but was: {len(source)}"
            )

        view = source
        if source_offset or len(source) != length:
            view = memoryview(source)[source_offset : (source_offset + length)]

        self.buffer[at_offset : (at_offset + length)] = view

    def insert_string(self, source, at_offset, source_length=0, source_offset=0):
        """Overwrites the buffer with the specified source bytes, prefixed by length.

        The first 4 bytes at the specified offset (as an unsigned 32-bit integer)
        will be filled with the length of the source bytes,
        and then the source bytes themselves will be written.

        Arguments:
            source (bytearray): Source of bytes.
            at_offset (int): Destination byte offset in buffer.
            source_length (int): Number of bytes to insert (default: source length).
            source_offset (int): Source byte offset (default: 0).

        Raises:
            MessageError: If buffer too short or source too short.
        """
        if type(source) == str:
            source = source.encode()

        if len(self.buffer) < at_offset + 4:
            raise MessageError(
                "buffer too short for string; expected at least "
                f"{at_offset + 4}, but was: {len(self.buffer)}"
            )

        length = source_length or (len(source) - source_offset)
        pack_into(">I", self.buffer, at_offset, length)
        self.insert(source, at_offset + 4, length, source_offset)

    def extract(self, offset, length):
        """Extracts the specified bytes from the buffer.

        Arguments:
            offset (int): Starting byte offset.
            length (int): Number of bytes to extract.

        Returns:
            bytearray: Copy of extracted bytes.

        Raises:
            MessageError: If buffer too short.
        """
        if len(self.buffer) < offset + length:
            raise MessageError(
                "message too short; expected at least "
                f"{offset + length}, but was: {len(self.buffer)}"
            )
        return self.buffer[offset : (offset + length)]

    def extract_string(self, offset):
        """Extracts the specified bytes from the buffer.

        The first 4 bytes at the specified offset (as an unsigned 32-bit integer)
        specify the length of the bytes to extract (following those 4 bytes).

        Arguments:
            offset (int): Starting byte offset.

        Returns:
            bytearray: Copy of extracted bytes.

        Raises:
            MessageError: If buffer too short.
        """
        if len(self.buffer) < offset + 4:
            raise MessageError(
                "message too short for string; expected at least "
                f"{offset + 4}, but was: {len(self.buffer)}"
            )
        length = unpack_from(">I", self.buffer, offset)[0]
        return self.extract(offset + 4, length)

    def zero(self):
        """Zeros the buffer and other sensitive fields of this class."""
        self.initialize_buffer()

        pin = getattr(self, "pin", None)
        if pin:
            pin[:] = bytearray(len(pin))
            self.pin = bytearray(0)

        shared_secret = getattr(self, "shared_secret", None)
        if shared_secret:
            shared_secret[:] = bytearray(len(shared_secret))
            self.shared_secret = bytearray(0)

    def initialize_buffer(self, buffer=None):
        """Zeros current buffer, and replaces it with the specified content.

        Arguments:
            buffer: If bytes or bytearray, content with which to replace buffer.
                If a string, buffer is replaced with hex content of string.
                If an integer, buffer is replaced with zeroed buffer of specified size.
                If None, buffer is replaced with empty buffer of size 0.

        """
        if self.buffer:
            self.buffer[:] = bytearray(len(self.buffer))
        elif not buffer:
            # do nothing if both current buffer and new buffer are empty
            return

        if isinstance(buffer, bytearray):
            self.buffer = buffer
        elif isinstance(buffer, str):
            self.buffer = bytearray.fromhex(buffer)
        elif buffer:
            self.buffer = bytearray(buffer)
        else:
            self.buffer = bytearray(0)

    def log(self):
        """Logger for this class.

        Returns:
            Logger instance.
        """
        return getLogger(f"{__name__}.{self.__class__.__name__}")

    def __del__(self):
        """Zeros the buffer and other sensitive fields of this class."""
        self.zero()

    def _assert_expected_buffer_size(self, expected, action):
        actual = len(self.buffer)
        if expected != actual:
            raise MessageError(
                f"wrong length for {action}; expected {expected}, but was: {actual}"
            )


SUCCESS_MESSAGE = Message(message_type=SUCCESS)
FAILURE_MESSAGE = Message(message_type=FAILURE)
EXTENSION_FAILURE_MESSAGE = Message(message_type=EXTENSION_FAILURE)
