# vim: expandtab tabstop=4 shiftwidth=4

from pathlib import Path

import unittest

from generate_certs import generate_certs, generate_unencrypted_pem_config

# this has to happen before we import pypki3
working_path = Path.cwd()
config_path = working_path.joinpath('config.ini')
generate_certs(working_path)
generate_unencrypted_pem_config(working_path)

import pypki3

class SSLContextTests(unittest.TestCase):
    def test_ssl_context_from_pem(self):
        ctx = pypki3.ssl_context()
        self.assertTrue(ctx is not None)
