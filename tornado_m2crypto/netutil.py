from M2Crypto import SSL
from myDebug import printDebug

# These are the keyword arguments to ssl.wrap_socket that must be translated
# to their SSLContext equivalents (the other arguments are still passed
# to SSLContext.wrap_socket).
_SSL_CONTEXT_KEYWORDS = frozenset(['ssl_version', 'certfile', 'keyfile',
                                   'cert_reqs', 'verify_depth', 'ca_certs', 'ciphers'])

@printDebug
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

  # #   ############## BRUTE FORCE #######
  #   ctx = SSL.Context(weak_crypto=True)
  #   CERTFILE = '/home/chaen/dirac/tornadoM2Crypto/tornado/tornado/test/test.crt'
  #   KEYFILE = '/home/chaen/dirac/tornadoM2Crypto/tornado/tornado/test/test.key'
  #   ctx.load_cert(certfile=CERTFILE,keyfile = KEYFILE)
  #   #ctx.load_client_ca(CAFILE)
  #   #if ctx.load_verify_locations(CAFILE) != 1:
  # #      raise Exception('CA certificates not loaded')
  #   #ctx.set_verify(M2Crypto.SSL.verify_none,10)
  #   ctx.set_verify(SSL.verify_peer,10)
  #   ctx.set_allow_unknown_ca(1)
  #   # set a session name.. not sure ..
  #   ctx.set_session_id_ctx('m2_srv')
  #   # Log the SSL info
  #   ctx.set_info_callback()
  #   return ctx
  #   ##############################################

    ssl_options['ca_certs'] = ssl_options['certfile']

    assert isinstance(ssl_options, dict)
    assert all(k in _SSL_CONTEXT_KEYWORDS for k in ssl_options), ssl_options
    # Can't use create_default_context since this interface doesn't
    # tell us client vs server.
    context = SSL.Context( protocol = ssl_options.get('ssl_version', 'tls'), weak_crypto = True)
    # context = SSL.Context(protocol = 'tls', weak_crypto = False)

    # CHris debug

    context.set_allow_unknown_ca(1)
    # set a session name.. not sure ..
    context.set_session_id_ctx('m2_srv')
    # Log the SSL info
    context.set_info_callback()

    if 'certfile' in ssl_options:
        context.load_cert(certfile=ssl_options['certfile'],keyfile = ssl_options.get('keyfile', None))
    if ssl_options.get('cert_reqs'):
        #context.verify_mode = ssl_options['cert_reqs']
        #context.set_verify(M2Crypto.SSL.verify_peer,10)
        context.set_verify(ssl_options['cert_reqs'],ssl_options.get('verify_depth', 10))
    else:
      context.set_verify(SSL.verify_none, 10)
    if 'ca_certs' in ssl_options:
        print "CHRIS I load the CA"
        if not context.load_verify_locations(ssl_options['ca_certs']):
          raise Exception('CA certificates not loaded')
        print "ALL OK"
    if 'ciphers' in ssl_options:
        context.set_cipher_list(ssl_options['ciphers'])
    # if hasattr(ssl, 'OP_NO_COMPRESSION'):
    #     # Disable TLS compression to avoid CRIME and related attacks.
    #     # This constant depends on openssl version 1.0.
    #     # TODO: Do we need to do this ourselves or can we trust
    #     # the defaults?
    #     context.options |= ssl.OP_NO_COMPRESSION
    return context


@printDebug
def m2_wrap_socket(socket, ssl_options, server_hostname=None, **kwargs):
    """Returns an ``M2Crypto.SSL.Connection`` wrapping the given socket.

    ``ssl_options`` may be either an `SSL.Context` object or a
    dictionary (as accepted by `ssl_options_to_context`).  Additional
    keyword arguments are passed to ``wrap_socket`` (either the
    `~ssl.SSLContext` method or the `ssl` module function as
    appropriate).
    """
    context = ssl_options_to_m2_context(ssl_options)
    connection = SSL.Connection(ctx=context, sock=socket)

    # if server_hostname:
    #   connection.set_tlsext_host_name(server_hostname)

    return connection
