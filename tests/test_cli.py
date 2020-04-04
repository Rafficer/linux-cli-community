import pytest  # type: ignore
import os


@pytest.fixture()
def init():
    os.system('echo hello')


def test_(init):
    assert (os.system('protonvpn -v')) == 0