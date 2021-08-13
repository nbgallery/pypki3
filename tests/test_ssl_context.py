# vim: expandtab tabstop=4 shiftwidth=4

from os import environ
from pathlib import Path

import unittest

from generate_certs import generate_certs, generate_unencrypted_pem_config

import pypki3

class SSLContextTests(unittest.TestCase):
    def setUp(self):
        self.working_path = Path.cwd()
        self.config_path = self.working_path.joinpath('config.ini')
        environ['PYPKI3_CONFIG'] = str(self.config_path)
        generate_certs(self.working_path)
        generate_unencrypted_pem_config(self.working_path)

    def tearDown(self):
        self.config_path.unlink()

        pems = self.working_path.glob('*.pem')
        p12s = self.working_path.glob('*.p12')

        for pem in pems:
            pem.unlink()

        for p12 in p12s:
            p12.unlink()

    def test_ssl_context_from_pem(self):
        ctx = pypki3.ssl_context()
        self.assertTrue(ctx is not None)
