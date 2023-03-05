#!/bin/sh -eu
# Installs latest version from PyPi to /opt/venvs/openpgpcard-x25519-agent;
# then creates and starts systemd openpgp-x25519-agent.service.
# Run as your daily user. Doesn't handle prerequisites, upgrade, or uninstall.

venv_dir="${VENV_DIR:-/opt/venvs/openpgpcard-x25519-agent}"
unit_dir="${SERVICE_DIR:-/usr/local/lib/systemd/system}"
repo_url="${REPO_URL:-https://git.sr.ht/~arx10/openpgpcard-x25519-agent/tree/main/item}"

# create venv
sudo mkdir -p "$venv_dir"
sudo chown $USER:$(id -g) "$venv_dir"
umask 0002
python3 -m venv --upgrade-deps "$venv_dir"
ls -ld "$venv_dir"

# install agent
. "$venv_dir/bin/activate"
pip install openpgpcard-x25519-agent
deactivate
ls -l "$venv_dir/bin/openpgpcard*"

# create systemd socket group
sudo groupadd --system openpgpcard
sudo usermod --append --groups openpgpcard $USER
grep openpgpcard /etc/group

# create and start systemd unit
sudo mkdir -p "$unit_dir"
wget -O - "$repo_url/etc/openpgpcard-x25519-agent.service" |
    awk -v venv_dir="$venv_dir" '
        /^Exec/ { gsub("/opt/venvs/openpgp-x25519-agent", venv_dir) }
        { print }
    ' |
    sudo tee "$unit_dir/openpgpcard-x25519-agent.service" > /dev/null
wget -O - "$repo_url/etc/openpgpcard-x25519-agent.socket" |
    sudo tee "$unit_dir/openpgpcard-x25519-agent.socket" > /dev/null
sudo systemctl daemon-reload
sudo systemctl --now enable openpgpcard-x25519-agent
systemctl status openpgpcard-x25519-agent
