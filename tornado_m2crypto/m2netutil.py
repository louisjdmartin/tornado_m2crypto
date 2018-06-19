from M2Crypto import SSL, m2
from os.path import isdir


_SSL_CONTEXT_KEYWORDS = frozenset(['ssl_version', 'certfile', 'keyfile', 'dhparam',
                                   'cert_reqs', 'verify_depth', 'ca_certs', 'ciphers',
                                   'debugSSL'])

def ssl_options_to_m2_context(ssl_options):
    """Try to convert an ``ssl_options`` dictionary to an
    `~M2Crypto.SSL.Context` object.

    Allowed options in ssl_options are:
    * ssl_version: (default: tls) version of ssl. See `~M2Crypto.SSL.Context`
    * certfile: pem file to use as certificate
    * keyfile: pem file for the key
    * dhparam: Diffie-Helman parameters
    * cert_reqs: (default none) Requirements over the remote certificate
                  (verify_none, verify_peer, verify_fail_if_no_peer_cert or verify_client_once from `~M2Crypto.SSL`)
    * verify_depth: (default 10) recursion depth for certificate verification
    * ca_certs: path to the CA file or the CA folder
    * ciphers: cipher list (see `~M2Crypto.SSL.Context.set_cipher_list`)
    * sslDebug: if True, will printout the openssl debug info

    """

    if isinstance(ssl_options, SSL.Context):
        return ssl_options


    assert isinstance(ssl_options, dict)
    assert all(k in _SSL_CONTEXT_KEYWORDS for k in ssl_options), ssl_options
    # Can't use create_default_context since this interface doesn't
    # tell us client vs server.
    context = SSL.Context( protocol = ssl_options.get('ssl_version', 'tls'), weak_crypto = True)



    if 'certfile' in ssl_options:
        context.load_cert(certfile=ssl_options['certfile'],keyfile = ssl_options.get('keyfile', None))

    if ssl_options.get('cert_reqs'):
        context.set_verify(ssl_options['cert_reqs'],
                           ssl_options.get('verify_depth', 10))
    else:
      context.set_verify(SSL.verify_none, 10)

    if 'ca_certs' in ssl_options:
        if isdir(ssl_options['ca_certs']):
            load = context.load_verify_locations(capath=ssl_options['ca_certs'])
        else:
            load = context.load_verify_locations(cafile=ssl_options['ca_certs'])
        if not load:
          raise Exception('CA certificates not loaded')
    if 'ciphers' in ssl_options:
        context.set_cipher_list(ssl_options['ciphers'])
    if 'dhparam' in ssl_options:
        context.set_tmp_dh(ssl_options['dhparam'])


    # Log the SSL info
    if ssl_options.get('sslDebug'):
      context.set_info_callback()

    # Options potentially interesting for debuging:
    # context.set_allow_unknown_ca(1)
    # set a session name.. not sure ..
    # context.set_session_id_ctx('m2_srv')


    return context


def m2_wrap_socket(socket, ssl_options, server_hostname=None, **kwargs):
    """Returns an ``M2Crypto.SSL.Connection`` wrapping the given socket.

    ``ssl_options`` may be either an `~M2Crypto.SSL.Context` object or a
    dictionary (as accepted by `ssl_options_to_m2_context`).

    ``server_side``: Needed ! if True, initialize M2Crypto as a server
    """
    context = ssl_options_to_m2_context(ssl_options)
    connection = SSL.Connection(ctx=context, sock=socket)

    # TODO: maybe enable this ?
    # if server_hostname:
    #   connection.set_tlsext_host_name(server_hostname)

    # Add an extra attribute to the Connection so we can test on it later
    connection.server_side = kwargs.get('server_side', False)

    # Hum, why do I need that?
    connection.family = socket.family


    # Need this for writes that are larger than BIO pair buffers
    # the ssl module also sets it
    m2.ssl_set_mode(connection.ssl, m2.SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER)


    return connection
