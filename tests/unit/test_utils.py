import pytest

from protonvpn_cli.utils import is_valid_ip


class TestIPValidation:
    good_ips = ('255.255.255.255', '127.0.0.1', '10.8.8.28/24', '122.122.54.54', '192.168.2.1/32')
    bad_ips = ('256.256.256.256', '127.0.0.-1', '127.0.0.1/467')

    @pytest.mark.parametrize('ip', good_ips)
    def test_correct_ip(self, ip):
        assert is_valid_ip(ip)

    @pytest.mark.parametrize('ip', bad_ips)
    def test_incorrect_ip(self, ip):
        assert not is_valid_ip(ip)
