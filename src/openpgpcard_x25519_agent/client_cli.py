"""OpenPGP Card X25519 Agent Client.

Client interface to OpenPGP Card X25519 Agent.

Usage:
  openpgpcard-x25519-client --set-pin [--prompt] [--lifetime=DURATION]
                            [--seat=SEAT] [--socket=SOCKET]
                            [-v | -vv | --verbosity=LEVEL]
                            [- | FILE]
  openpgpcard-x25519-client --clear-pin
                            [--seat=SEAT] [--socket=SOCKET]
                            [-v | -vv | --verbosity=LEVEL]
  openpgpcard-x25519-client --public-key
                            [--seat=SEAT] [--socket=SOCKET]
                            [-v | -vv | --verbosity=LEVEL]
  openpgpcard-x25519-client --shared-secret [--prompt]
                            [--seat=SEAT] [--socket=SOCKET]
                            [-v | -vv | --verbosity=LEVEL]
                            [- | FILE]
  openpgpcard-x25519-client --help
  openpgpcard-x25519-client --version

Options:
  -h --help             Show this help
  --version             Show agent version
  -c --clear-pin        Clear PIN
  -k --public-key       Show public key
  -x --shared-secret    Derive X25519 shared secret
  -p --set-pin          Set PIN
  -l --lifetime=TTL     Expire PIN after duration (ex: 30m)
  -t --prompt           Prompt for input instead of reading from file
  -i --seat=ID          Card seat to use (default: 0)
  -s --socket=SOCKET    Socket path (default: /var/run/wireguard/agent0)
  --verbosity=LEVEL     Log level (ERROR, WARNING, INFO, DEBUG)
  -v                    INFO verbosity
  -vv                   DEBUG verbosity

Examples:
  Prompt to set the PIN for seat 0 via socket at /var/run/wireguard/agent0:

    openpgpcard-x25519-client --set-pin --prompt
    PIN:

  Prompt to set the PIN for seat 0 via socket at /var/run/wireguard/agent0,
  and expire after 30 minutes:

    openpgpcard-x25519-client --set-pin --prompt --lifetime=30m
    PIN:

  Prompt to set the PIN for seat 1 via socket at /wg.sock:

    openpgpcard-x25519-client --set-pin --prompt --seat=1 --socket=/wg.sock
    PIN:

  Pipe in PIN from `pass` for seat 0 via socket at /var/run/wireguard/agent0:

    pass smartcards/card1/pin | openpgpcard-x25519-client --set-pin

  Redirect in PIN from `echo` for seat 0 via socket at /var/run/wireguard/agent0:

    openpgpcard-x25519-client --set-pin <(echo 123456)

  Read in PIN from pin.txt for seat 1 via socket at /wg.sock,
  and expire after 2 and 1/2 hours:

    openpgpcard-x25519-client -p -i 1 -s /wg.sock -l 2.5h pin.txt

  Clear the PIN for seat 0 via socket at /var/run/wireguard/agent0:

    openpgpcard-x25519-client --clear-pin

  Clear the PIN for seat 1 via socket at /wg.sock:

    openpgpcard-x25519-client --clear-pin --seat=1 --socket=/wg.sock

  Print the public key for seat 0 via socket at /var/run/wireguard/agent0:

    openpgpcard-x25519-client --public-key
    /TOE4TKtAqVsePRVR+5AA43HkAK5DSntkOCO7nYq5xU=

  Print the public key for seat 1 via socket at /wg.sock:

    openpgpcard-x25519-client --public-key --seat=1 --socket=/wg.sock
    /TOE4TKtAqVsePRVR+5AA43HkAK5DSntkOCO7nYq5xU=

  Print the shared secret derived for seat 0 via socket at
  /var/run/wireguard/agent0, prompting for the other party's public key:

    openpgpcard-x25519-client --shared-secret --prompt
    Public key: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE=
    i3S/rPUXkdn+WmicQSHUpu/AKGrR5J8Wn+raUrGScE0=

  Print the shared secret derived for seat 1 via socket at /wg.sock,
  piping in the other party's public key:

    echo AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE= |
        openpgpcard-x25519-client -x -i 1 -s /wg.sock
    i3S/rPUXkdn+WmicQSHUpu/AKGrR5J8Wn+raUrGScE0=
"""
from sys import exit

from docopt import docopt

from openpgpcard_x25519_agent import __version__
from openpgpcard_x25519_agent.client import (
    clear_pin,
    input_pin,
    print_public_key,
    print_shared_secret,
)
from openpgpcard_x25519_agent.cnf import init_log


# keep entry-point logic together,
# even if it makes cognitive complexity too high
def main():  # noqa: CCR001
    """CLI Entry point."""
    args = docopt(__doc__)
    init_log(args["--verbosity"] or args["-v"])

    if args["--version"]:
        version()
    elif args["--clear-pin"]:
        clear_pin(args["--socket"], args["--seat"]) or exit(1)
    elif args["--set-pin"]:
        input_pin(
            args["FILE"],
            args["--socket"],
            args["--seat"],
            args["--prompt"],
            args["--lifetime"],
        ) or exit(1)
    elif args["--public-key"]:
        print_public_key(args["--socket"], args["--seat"]) or exit(1)
    elif args["--shared-secret"]:
        print_shared_secret(
            args["FILE"],
            args["--socket"],
            args["--seat"],
            args["--prompt"],
        ) or exit(1)


def version():
    """Show version."""
    # print version to stdout
    print("openpgpcard-x25519-client " + __version__)  # noqa: T201


if __name__ == "__main__":
    main()
