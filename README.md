OpenPGP Card X25519 Agent
=========================

Socket interface to Curve25519 ECDH from an OpenPGP card.


Development
-----------

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


License
-------

Copyright (c) 2023 Arcem Tene, Inc.

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>.
