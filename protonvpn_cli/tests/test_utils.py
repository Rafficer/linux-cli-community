from unittest import TestCase

from protonvpn_cli.country_codes import country_codes
from protonvpn_cli.utils import get_country_name


class TestUtils(TestCase):

    def test_get_country_name(self):
        country_code = "GS"
        country_name = get_country_name(country_code)
        self.assertEqual(country_name, country_codes[country_code])

    def test_get_country_name_not_exists(self):
        country_code = "TEST"
        self.assertIsNone(country_codes.get(country_code, None))

        country_name = get_country_name(country_code)
        self.assertEqual(country_name, country_code)
