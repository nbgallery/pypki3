# pypki3

pypki3 is intended as a replacement for pypki2.
It is built around the `cryptography` package instead of `pyOpenSSL`, which is now deprecated.

Unlike pypki2, pypki3 does not try to do any auto-configuration, nor does it try to silently compensate when there's a configuration issue.  The mantra is, "Let it crash."

pypki3 also does not support any monkey-patching like pypki2 did.  There's just no need for that.

## Configuration

Since the user has to create their own configuration file now, the config file is much simpler, using a standard `config.ini` format, of the following form.

```
[global]
p12 = /path/to/your.p12
pem = /path/to/your.combined.pem
ca = /path/to/certificate_authorities.pem
```

At least one of `p12` or `pem` must be populated.  If both are populated, then `p12` is used.

The `pem` file must be a combined key-and-cert file of the following form, which is pretty normal in the Python world.

```
-----BEGIN RSA PRIVATE KEY-----
... (private key in base64 encoding) ...
-----END RSA PRIVATE KEY-----
-----BEGIN CERTIFICATE-----
... (certificate in base64 PEM encoding) ...
-----END CERTIFICATE-----
```

### Configuration file locations

pypki3 will first look at the location specified by the `PYPKI3_CONFIG` environment variable for a config file.  This can be helpful in corporate Windows environments where the "home directory" is not always in a standard location.  It can also be useful in test environments.

Next pypki3 will look in `~/.config/pypki3/config.ini`.

Next pypki3 will look in `/etc/pypki3/config.ini`.

Finally, for existing library support, if pypki3 is being used in an NBGallery Jupyter environment, then pypki3 will attempt to look for the older pypki2 `~/.mypki` file, or use NBGallery's Javascript certificate upload dialog.

## Usage

### Get an SSLContext
If you have your own code and you just want to pass along an SSLContext based on the .mypki config (eg. for `urlopen()`, or for the `requests` package), then all you have to do is the following:

```python
from urllib.request import urlopen
import pypki3
ctx = pypki3.ssl_context()
resp = urlopen(https_url, context=ctx)
...
```

If you have already configured your PKI info, you have the option of providing a certificate password to `ssl_context()` rather than using the interactive prompt.  This can be useful when the password is stored in a vault, or when the code needs to run in some non-interactive way.  Please be conscientious of the security implications of putting your password directly in your code though.

```python
from urllib.request import urlopen
import pypki3
ctx = pypki3.ssl_context(password='supersecret')
resp = urlopen(https_url, context=ctx)
...
```

### Prompting for a password early (optional)

Sometimes it can also be useful to force the certificate password prompt to appear before `ssl_context()` is called, by another library for example.  To do this, simply use `prepare()`.

```python
import pypki3
import another_library_that_uses_pypki3
pypki3.prepare()  # Prompts for password here

# A lot of other code/steps...

# Does not prompt for password way down here
another_library_that_uses_pypki3.does_something()
```

### Getting a decrypted key/cert context

pypki3 includes a context manager that ensures the decrypted key and cert are cleaned up.  This is useful when you want to make sure you don't leave your decrypted certs sitting around on disk.

```python
import pypki3

with NamedTemporaryKeyCertPaths() as key_cert_paths:
    key_path = key_cert_paths[0]  # key_path is a pathlib.Path object
    cert_path = key_cert_paths[1]  # cert_path is a pathlib.Path object
    # Do something awesome here

# Decrypted key and cert are cleaned up when you leave the `with` context.
```

### Using the pip wrapper
Some pip servers require PKI authentication.  To make this a bit easier, pypki3 includes a pip wrapper that takes care of filling in the `--client-cert` and `--cert` parameters based on the pypki3 configuration.  This also prevents pip from prompting for a password 8 million times when use password-protected (encrypted) certs.

```python
import pypki3
pypki3.pip(['install', 'amazing-internal-package'])
```
