
import pytest

def pytest_addoption(parser):
    parser.addoption("--slow", action="store_true", default=False,
            help="Run tests known to take a long time")

