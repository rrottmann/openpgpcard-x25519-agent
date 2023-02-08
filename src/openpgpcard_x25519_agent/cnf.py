"""Configuration utilities."""

import logging
from os import environ

DEFAULT_LOG_FORMAT = "%(asctime)s %(name)s %(levelname)s: %(message)s"
DEFAULT_LOG_LEVEL = "WARNING"


def init_log(root_level=""):
    """Initializes python logging.

    Arguments:
        root_level (str): Root logging level. Defaults to 'WARNING'.
    """
    log_format = _get_log_format()
    log_level = _get_log_level(root_level)
    logging.basicConfig(format=log_format, level=log_level)
    logging.getLogger(__name__).debug("init logging at %s", log_level)


def _get_log_level(default=""):
    environment_variable = environ.get("OPENPGPCARD_X25519_AGENT_LOG_LEVEL")
    if environment_variable:
        return environment_variable.upper()

    if default == 1:
        return "INFO"
    if default == 2:
        return "DEBUG"
    if default:
        return default.upper()

    return DEFAULT_LOG_LEVEL


def _get_log_format(default=""):
    return (
        environ.get("OPENPGPCARD_X25519_AGENT_LOG_FORMAT")
        or default
        or DEFAULT_LOG_FORMAT
    )
