"""Setup file for openpgpcard-x25519-agent."""
from setuptools import setup

if __name__ == "__main__":
    try:
        setup()
    # catch everything, print help message, then re-raise
    except:  # noqa
        # print help message to stdout
        print(  # noqa: T201
            "\n\nAn error occurred while building the project, "
            "please ensure you have the most updated version of setuptools, "
            "setuptools_scm and wheel with:\n"
            "   pip install -U setuptools setuptools_scm wheel\n\n"
        )
        raise
