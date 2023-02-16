"""OpenPGP Card X25519 Agent.

Socket interface to Curve25519 ECDH from an OpenPGP card.

Usage:
  openpgpcard-x25519-agent [--card=ID] [-v | -vv | --verbosity=LEVEL]
  openpgpcard-x25519-agent --listen [--socket=SOCKET] [--card=ID]
                           [-v | -vv | --verbosity=LEVEL]
  openpgpcard-x25519-agent --test [--card=ID] [-v | -vv | --verbosity=LEVEL]
  openpgpcard-x25519-agent --help
  openpgpcard-x25519-agent --version

Options:
  -h --help             Show this help
  --version             Show agent version
  -c --card=ID          Card to use (default: first found)
  -l --listen           Listen on socket
  -s --socket=SOCKET    Socket path (default: /var/run/wireguard/agent0)
  --test                Prompt for PIN and attempt a test X25519 operation.
  --verbosity=LEVEL     Log level (ERROR, WARNING, INFO, DEBUG)
  -v                    INFO verbosity
  -vv                   DEBUG verbosity
"""
from docopt import docopt

from openpgpcard_x25519_agent import __version__
from openpgpcard_x25519_agent.card import (
    format_card_info,
    format_cards_info,
    get_card_by_id,
    list_all_cards,
    test_card,
)
from openpgpcard_x25519_agent.cnf import init_log
from openpgpcard_x25519_agent.server import run_server


def main():
    """CLI Entry point."""
    args = docopt(__doc__)
    init_log(args["--verbosity"] or args["-v"])

    if args["--version"]:
        version()
    elif args["--listen"]:
        listen(args["--socket"], args["--card"])
    elif args["--test"]:
        test(args["--card"])
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
    run_server(socket, card)


def test(card=None):
    """Attempt test X25519 operation.

    Arguments:
        card: Card ID.
    """
    test_card(card)
    # print result to stdout
    print("X25519 SUCCESS")  # noqa: T201


def version():
    """Show version."""
    # print version to stdout
    print("openpgpcard-x25519-agent " + __version__)  # noqa: T201


if __name__ == "__main__":
    main()
