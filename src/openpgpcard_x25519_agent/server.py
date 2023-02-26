"""Server utilities."""

from datetime import datetime
from logging import getLogger
from pathlib import Path
from selectors import EVENT_READ, DefaultSelector
from signal import SIGINT, SIGTERM, signal
from socket import AF_UNIX, SOCK_STREAM, socket, socketpair

from openpgpcard_x25519_agent.card import (
    calculate_shared_secret,
    get_card_by_id,
    get_curve25519_key,
    get_default_card,
)
from openpgpcard_x25519_agent.cnf import (
    get_server_socket_file_descriptor,
    get_socket_path,
)
from openpgpcard_x25519_agent.msg import (
    ADD_SMARTCARD_KEY,
    ADD_SMARTCARD_KEY_CONSTRAINED,
    DERIVE_SHARED_SECRET,
    FAILURE,
    FAILURE_MESSAGE,
    REMOVE_SMARTCARD_KEY,
    REQUEST_EXTENSION,
    REQUEST_PUBLIC_KEY,
    SUCCESS,
    Message,
)


def run_server(socket=None, card_id=None):
    """Runs a new server in this thread, listening on the specified socket path.

    Arguments:
        socket: Path to socket file or file descriptor number.
        card_id (str): Card to serve (as seat 0).
    """
    seats = [Seat(card_id)]

    fileno = get_server_socket_file_descriptor(socket)
    if fileno:
        server = Server(fileno=fileno, seats=seats)
    else:
        server = Server(get_socket_path(socket), seats)

    signal(SIGINT, lambda number, frame: server.stop())
    signal(SIGTERM, lambda number, frame: server.stop())
    server.start()


class Server:
    """SSH-agent server for X25519 from an OpenPGP card.

    Handles SSH-agent client requests that reference a smartcard reader ID
    by converting the ID into a hex number, and using that number as the index
    into the server's `seats` list.

    Attributes:
        listening (bool): True if running.
        path (Path): Path to socket file.
        fileno (int): Socket file-descriptor number.
        seats (list): List of available card seats.
        socket (socket): Listening SSH-agent server socket.
        interrupt_sender (socket): Client side of interrupt socket pair.
        interrupt_receiver (socket): Listening side of interrupt socket pair.
    """

    def __init__(self, socket_path=None, seats=None, fileno=None):
        """Creates a new server to listen on the specified socket path.

        Arguments:
            socket_path (str): Path to socket file.
            seats (list): List of available card seats.
            fileno (int): File descriptor number.
        """
        self.listening = False
        self.path = Path(socket_path) if socket_path else None
        self.fileno = fileno
        self.seats = seats or []
        self.socket = None
        self.interrupt_sender = None
        self.interrupt_receiver = None

    def start(self, selector=None):
        """Starts the server in this thread.

        Arguments:
            selector (BaseSelector): Selector to use for server.
        """
        selector = selector if selector else DefaultSelector()
        self._bind_interrupt(selector)
        self._bind(selector)
        self._listen(selector)
        self._unbind(selector)
        self._unbind_interrupt(selector)

    def stop(self):
        """Notifies the server to stop."""
        if self.interrupt_sender:
            self.log().debug("stopping...")
            self.interrupt_sender.send(b"\0")
        else:
            self.log().debug("not started")

    # keep connection-handling logic together,
    # even if it makes cognitive complexity too high
    def handle_connection(self, connection):  # noqa: CCR001
        """Handles the specified connection.

        Arguments:
            connection (socket): Connection to handle.
        """
        self.log().debug("new connection")
        request = Message()
        response = Message()

        try:
            connection.settimeout(5.0)
            request.receive(connection)
        except Exception:
            self.log().error("error receiving request", exc_info=True)
            request.message_type = 0

        if request.message_type:
            try:
                self.handle_request(request, response)
            except Exception:
                self.log().error("error handling request", exc_info=True)
                response.message_type = 0

        try:
            if response.message_type:
                response.send(connection)
            else:
                FAILURE_MESSAGE.send(connection)
        except Exception:
            self.log().error("error sending response", exc_info=True)

        request.zero()
        response.zero()

        try:
            connection.close()
        except Exception:
            self.log().warning("error closing connection", exc_info=True)

    def handle_request(self, request, response):
        """Handles the specified request by populated the specified response.

        Arguments:
            request (Message): Request message.
            response (Message): Response message.
        """
        if request.message_type == REQUEST_EXTENSION:
            self.request_extension(request, response)
        elif request.message_type == ADD_SMARTCARD_KEY:
            self.add_smartcard_key(request, response)
        elif request.message_type == ADD_SMARTCARD_KEY_CONSTRAINED:
            self.add_smartcard_key(request, response)
        elif request.message_type == REMOVE_SMARTCARD_KEY:
            self.remove_smartcard_key(request, response)

    def request_extension(self, request, response):
        """Handles the specified extension request by populated the specified response.

        Arguments:
            request (Message): Request message.
            response (Message): Response message.
        """
        if request.extension_type == REQUEST_PUBLIC_KEY:
            self.request_public_key(request, response)
        elif request.extension_type == DERIVE_SHARED_SECRET:
            self.derive_shared_secret(request, response)

    def request_public_key(self, request, response):
        """Populates the specified response message with the requested public key.

        Arguments:
            request (Message): Request message.
            response (Message): Response message.
        """
        seat = self.get_seat(request.reader_id)
        response.public_key = get_curve25519_key(seat.get_card())
        response.extension_type = REQUEST_PUBLIC_KEY
        response.message_type = SUCCESS

    def derive_shared_secret(self, request, response):
        """Populates the specified response message with the derived shared secret.

        Arguments:
            request (Message): Request message.
            response (Message): Response message.
        """
        seat = self.get_seat(request.reader_id)
        response.shared_secret = calculate_shared_secret(
            seat.get_card(), request.public_key, seat.get_pin()
        )
        response.extension_type = DERIVE_SHARED_SECRET
        response.message_type = SUCCESS

    def add_smartcard_key(self, request, response):
        """Caches the specified PIN code for specified smartcard key.

        Arguments:
            request (Message): Request message.
            response (Message): Response message.
        """
        if getattr(request, "constrain_confirm", False):
            response.message_type = FAILURE
            return

        lifetime = getattr(request, "constrain_lifetime", 0)
        expires = None
        if lifetime:
            expires = datetime.fromtimestamp(_now().timestamp() + lifetime)

        seat = self.get_seat(request.reader_id)
        seat.set_pin(request.pin.copy(), expires)
        response.message_type = SUCCESS

    def remove_smartcard_key(self, request, response):
        """Clears the cached PIN code for specified smartcard key.

        Arguments:
            request (Message): Request message.
            response (Message): Response message.
        """
        seat = self.get_seat(request.reader_id)
        seat.clear_pin()
        response.message_type = SUCCESS

    def get_seat(self, reader_id):
        """Finds registered seat for the specified reader ID.

        Arguments:
            reader_id (str): Reader ID.

        Returns:
            Seat: Registered seat for ID.

        Raises:
            ValueError: If seat not found.
        """
        try:
            return self.seats[int(reader_id, 16)]
        except Exception:
            raise ValueError(f"server does not have requested seat: {reader_id}")

    def log(self):
        """Logger for this class.

        Returns:
            Logger instance.
        """
        return getLogger(f"{__name__}.{self.__class__.__name__}")

    def __del__(self):
        """Stops the server."""
        self.stop()

    def _bind_interrupt(self, selector):
        if self.interrupt_receiver:
            self.log().warning("interrupt already bound")
        else:
            self.log().debug("binding interrupt")
            reader, writer = socketpair()
            self.interrupt_receiver = reader
            self.interrupt_sender = writer
            selector.register(self.interrupt_receiver, EVENT_READ, "interrupt")

    def _bind(self, selector):
        if self.socket:
            self.log().warning("already bound to %s", self.path)
        else:
            self.log().info("binding to %s", self.fileno or self.path)
            self.listening = True
            if self.path:
                self.path.unlink(missing_ok=True)
                self.path.parent.mkdir(parents=True, exist_ok=True)
                self.socket = socket(AF_UNIX, SOCK_STREAM)
                self.socket.bind(str(self.path))
            else:
                self.socket = socket(fileno=self.fileno)
            self.socket.listen()
            self.socket.setblocking(False)
            selector.register(self.socket, EVENT_READ, "accept")

    # keep selector-listening logic together,
    # even if it makes cognitive complexity too high
    def _listen(self, selector):  # noqa: CCR001
        while self.listening:
            for key, _ in selector.select():
                if key.data == "interrupt":
                    self.listening = False
                elif key.data == "accept":
                    connection, address = self.socket.accept()
                    self.handle_connection(connection)

    def _unbind(self, selector):
        if self.socket:
            self.log().info("unbinding to %s", self.fileno or self.path)
            selector.unregister(self.socket)
            self.socket.close()
            self.socket = None
            if self.path:
                self.path.unlink(missing_ok=True)
            self.listening = False
        else:
            self.log().warning("not bound to %s", self.path)

    def _unbind_interrupt(self, selector):
        if self.interrupt_receiver:
            self.log().debug("unbinding interrupt")
            selector.unregister(self.interrupt_receiver)
            self.interrupt_receiver.close()
            self.interrupt_receiver = None
            self.interrupt_sender.close()
            self.interrupt_sender = None
        else:
            self.log().warning("interrupt not bound")


class Seat:
    """Card seat for X25519 from an OpenPGP card.

    Caches the PIN for the card seat.

    Attributes:
        id (str): Card ID.
        pin (bytearray): PIN.
        expires (datetime): PIN expiration.
    """

    def __init__(self, card_id=None, pin=None, expires=None):
        """Creates a new card seat.

        Arguments:
            card_id (str): Card ID.
            pin (bytearray): PIN.
            expires (datetime): PIN expiration.
        """
        self.id = card_id
        self.pin = pin or bytearray(0)
        self.expires = expires

    def get_card(self):
        """Finds the card that corresponds to the registered ID for this seat.

        Returns:
            OpenPGPcard: Card object.

        Propagates:
            ConnectionException: If card not found.
        """
        return get_card_by_id(self.id) if self.id else get_default_card()

    def get_pin(self):
        """Gets the PIN for this seat, clearing if expired.

        Returns:
            bytearray: PIN.
        """
        if self.expired():
            self.clear_pin()
        return self.pin

    def set_pin(self, pin, expires=None):
        """Sets the PIN for this seat.

        Arguments:
            pin (bytearray): PIN.
            expires (datetime): PIN expiration.
        """
        self.clear_pin()
        self.pin = pin
        self.expires = expires

    def clear_pin(self):
        """Zeros the PIN."""
        if self.pin:
            self.pin[:] = bytearray(len(self.pin))
            self.pin = bytearray(0)
        self.expires = None

    def expired(self):
        """Checks if PIN lifetime has expired.

        Returns:
            bool: True if expired.
        """
        return self.expires and self.expires < _now()

    def __del__(self):
        """Zeros the PIN."""
        self.clear_pin()


def _now():
    return datetime.now()
