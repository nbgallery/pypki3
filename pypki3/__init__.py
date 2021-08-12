# vim: expandtab tabstop=4 shiftwidth=4

from .config import Loader

loader = Loader()

prepare = loader.prepare
ssl_context = loader.ssl_context
