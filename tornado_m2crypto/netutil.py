from M2Crypto import SSL

# These are the keyword arguments to ssl.wrap_socket that must be translated
# to their SSLContext equivalents (the other arguments are still passed
# to SSLContext.wrap_socket).
_SSL_CONTEXT_KEYWORDS = frozenset(['ssl_version', 'certfile', 'keyfile',
                                   'cert_reqs', 'ca_certs', 'ciphers'])


def ssl_options_to_m2_context(ssl_options):
    """Try to convert an ``ssl_options`` dictionary to an
    `~M2Crypto.SSL.Context` object.

    The ``ssl_options`` dictionary contains keywords to be passed to
    `ssl.wrap_socket`.  In Python 2.7.9+, `ssl.SSLContext` objects can
    be used instead.  This function converts the dict form to its
    `~ssl.SSLContext` equivalent, and may be used when a component which
    accepts both forms needs to upgrade to the `~ssl.SSLContext` version
    to use features like SNI or NPN.
    """
    if isinstance(ssl_options, SSL.Context):
        return ssl_options
    assert isinstance(ssl_options, dict)
    assert all(k in _SSL_CONTEXT_KEYWORDS for k in ssl_options), ssl_options
    # Can't use create_default_context since this interface doesn't
    # tell us client vs server.
    context = ssl.SSLContext(
        ssl_options.get('ssl_version', ssl.PROTOCOL_SSLv23))
    if 'certfile' in ssl_options:
        context.load_cert_chain(ssl_options['certfile'], ssl_options.get('keyfile', None))
    if 'cert_reqs' in ssl_options:
        context.verify_mode = ssl_options['cert_reqs']
    if 'ca_certs' in ssl_options:
        context.load_verify_locations(ssl_options['ca_certs'])
    if 'ciphers' in ssl_options:
        context.set_ciphers(ssl_options['ciphers'])
    if hasattr(ssl, 'OP_NO_COMPRESSION'):
        # Disable TLS compression to avoid CRIME and related attacks.
        # This constant depends on openssl version 1.0.
        # TODO: Do we need to do this ourselves or can we trust
        # the defaults?
        context.options |= ssl.OP_NO_COMPRESSION
    return context


def m2_wrap_socket(socket, ssl_options, server_hostname=None, **kwargs):
    """Returns an ``M2Crypto.SSL.Connection`` wrapping the given socket.

    ``ssl_options`` may be either an `SSL.Context` object or a
    dictionary (as accepted by `ssl_options_to_context`).  Additional
    keyword arguments are passed to ``wrap_socket`` (either the
    `~ssl.SSLContext` method or the `ssl` module function as
    appropriate).
    """
    context = ssl_options_to_context(ssl_options)
    if ssl.HAS_SNI:
        # In python 3.4, wrap_socket only accepts the server_hostname
        # argument if HAS_SNI is true.
        # TODO: add a unittest (python added server-side SNI support in 3.4)
        # In the meantime it can be manually tested with
        # python3 -m tornado.httpclient https://sni.velox.ch
        return context.wrap_socket(socket, server_hostname=server_hostname,
                                   **kwargs)
    else:
        return context.wrap_socket(socket, **kwargs)
