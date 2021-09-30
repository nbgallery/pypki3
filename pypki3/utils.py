# vim: expandtab tabstop=4 shiftwidth=4

from os import environ

def in_nbgallery():
    if 'NBGALLERY_CLIENT_VERSION' in environ:
        return True

    return False

def in_ipython():
    try:
        from IPython import get_ipython  # pylint: disable=E0401

        if get_ipython() is not None:
            return True
        else:
            return False

    except ImportError:
        return False

    return False
