OpenPGP Card X25519 Agent
=========================

Socket interface to Curve25519 ECDH from an OpenPGP card, using the [SSH agent protocol](https://datatracker.ietf.org/doc/html/draft-miller-ssh-agent). It's intended to be used with the [OpenPGP Card WireGuard Go](https://git.sr.ht/~arx10/openpgpcard-wireguard-go) client, allowing a WireGuard private key to be stored on an OpenPGP card.

See the [OpenPGP Card WireGuard Guide](https://www.procustodibus.com/blog/2023/03/openpgpcard-wireguard-guide/) for a complete walkthrough of installation and usage of both agent and client.


Development
-----------

### Prerequisites

Requires Python 3.8 or newer, and the [pcsc-lite](https://pcsclite.apdu.fr/) daemon.

Install prerequisites on Debian with the following packages:
```
apt install gcc libpcsclite-dev make pcscd python3-dev python3-venv swig
```

Or on Fedora:
```
dnf install findutils gcc make pcsc-lite pcsc-lite-devel python3-devel swig
```

### Set up dev env

1. Create a virtualenv with [pyenv](https://github.com/pyenv/pyenv):
    ```
    pyenv virtualenv 3.8.16 openpgpcard-x25519-agent
    ```

2. Activate the virtualenv:
    ```
    pyenv local openpgpcard-x25519-agent
    ```

3. Install tox:
    ```
    pip install tox
    ```

4. Install pre-commit and pre-push hooks:
    ```
    tox exec -e lint -- pre-commit install
    ```

### Dev tasks

List all tox tasks you can run:
```
tox list
```

Run unit tests in watch mode:
```
tox -e watch
```

Run linting:
```
tox -e lint
```

### Dev usage

Run agent listening at `/var/run/wireguard/agent0`:
```
sudo mkdir -p /var/run/wireguard && sudo chown $USER /var/run/wireguard
tox -e agent -- -l -vv
```

Or run agent listening on test socket:
```
tox -e agent -- -l -s test.socket -vv
```

Prompt to cache PIN on agent:
```
tox -e client -- -p -t -vv
```

Clear PIN from agent listening on test socket:
```
tox -e client -- -c -s test.socket -vv
```


Beware
------

* Any client with access to the socket on which the agent is listening has full use of your OpenPGP card's decryption key when the agent has the card's PIN cached. An adversary with access to the socket can easily decrypt your WireGuard traffic, or impersonate your WireGuard identity; she also can decrypt regular OpenPGP messages encrypted for your card's decryption key.
* Use of the agent requires the OpenPGP card's PIN to be cached in memory. After the card's PIN has been cached, if an adversary is able to dump your computer's memory, she will be able to recover the PIN.
* Even after you clear the PIN or shut down the agent, there still may be copies of the PIN in memory that an adversary could recover.


Contributing
------------

* Ask questions or send patches to https://lists.sr.ht/~arx10/openpgpcard-x25519-agent
* File issues at https://todo.sr.ht/~arx10/openpgpcard-x25519-agent
* Sync the latest source code with https://git.sr.ht/~arx10/openpgpcard-x25519-agent
* Install the latest release from https://pypi.org/project/openpgpcard-x25519-agent/


License
-------

Copyright (c) 2023 Arcem Tene, Inc.

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>.
