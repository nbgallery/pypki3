# vim: expandtab tabstop=4 shiftwidth=4

from typing import Optional

from .config import CreateNamedTemporaryKeyCertPathsContextManager
from .config import Loader

loader = Loader()

prepare = loader.prepare
ssl_context = loader.ssl_context
NamedTemporaryKeyCertPaths = CreateNamedTemporaryKeyCertPathsContextManager(loader)
pip = loader.pip
