"""OpenPGP Card X25519 Agent.

Socket interface to Curve25519 ECDH from an OpenPGP card.

Usage:
  openpgpcard-x25519-agent [--card=ID] [-v | -vv | --verbosity=LEVEL]
  openpgpcard-x25519-agent --listen=SOCKET [--card=ID]
                           [-v | -vv | --verbosity=LEVEL]
  openpgpcard-x25519-agent --help
  openpgpcard-x25519-agent --version

Options:
  -h --help             Show this help
  --version             Show agent version
  -c --card=ID          Card to use (default: first found)
  -l --listen=SOCKET    Listen on socket path (default: /run/wg/agent1)
  --verbosity=LEVEL     Log level (ERROR, WARNING, INFO, DEBUG)
  -v                    INFO verbosity
  -vv                   DEBUG verbosity
"""
from sys import exit

from docopt import docopt

from openpgpcard_x25519_agent import __version__
from openpgpcard_x25519_agent.card import (
    format_card_info,
    format_cards_info,
    get_card_by_id,
    list_all_cards,
)
from openpgpcard_x25519_agent.cnf import init_log


def main():
    """CLI Entry point."""
    args = docopt(__doc__)
    init_log(args["--verbosity"] or args["-v"])

    if args["--version"]:
        version()
    elif args["--listen"]:
        listen(args["--listen"], args["--card"])
    elif args["--card"]:
        show(args["--card"])
    else:
        show_all()


def show_all():
    """List all cards."""
    # print list to stdout
    print(format_cards_info(list_all_cards()))  # noqa: T201


def show(card):
    """Show card info.

    Arguments:
        card: Card ID.
    """
    # print info to stdout
    print(format_card_info(get_card_by_id(card)))  # noqa: T201


def listen(socket, card):
    """Listen for socket connections.

    Arguments:
        socket: Socket path.
        card: Card ID.
    """
    # to implement
    print("listen")  # noqa: T201
    exit(1)


def version():
    """Show version."""
    # print version to stdout
    print("openpgpcard-x25519-agent " + __version__)  # noqa: T201


if __name__ == "__main__":
    main()
