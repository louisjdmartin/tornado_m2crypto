import socket

from tornado.iostream import SSLIOStream

from M2Crypto.SSL.Context import Context
from M2Crypto import m2


_client_m2_ssl_defaults = Context()
_client_m2_ssl_defaults.set_options(m2.X509_PURPOSE_SSL_CLIENT)

_server_m2_ssl_defaults = Context()
_server_m2_ssl_defaults.set_options(m2.X509_PURPOSE_SSL_SERVER)


class M2IOStream(SSLIOStream):
    """A utility class to write to and read from a non-blocking SSL socket using M2Crypto.


    If the socket passed to the constructor is already connected,
    it should be wrapped with::

        ssl.wrap_socket(sock, do_handshake_on_connect=False, **kwargs)

    before constructing the `SSLIOStream`.  Unconnected sockets will be
    wrapped when `IOStream.connect` is finished.
    """

    def __init__(self, *args, **kwargs):
      pass


    def initialize(self, *args, **kwargs):
        """The ``ssl_options`` keyword argument may either be an
        `SSL.SSLContext` object or a dictionary of keywords arguments
        for `ssl.wrap_socket`
        """
        self._ssl_options = kwargs.pop('ssl_options', _client_m2_ssl_defaults)
        super(SSLIOStream, self).__init__(*args, **kwargs)
        self._ssl_accepting = True
        self._handshake_reading = False
        self._handshake_writing = False
        self._ssl_connect_callback = None
        self._server_hostname = None

        # If the socket is already connected, attempt to start the handshake.
        try:
            self.socket.getpeername()
        except socket.error:
            pass
        else:
            # Indirectly start the handshake, which will run on the next
            # IOLoop iteration and then the real IO state will be set in
            # _handle_events.
            self._add_io_state(self.io_loop.WRITE)


    # CHRIS: NO NEED TO INHERIT
    # @classmethod
    # def configurable_base(cls):
    #     return SSLIOStream
    #
    # CHRIS: NO NEED TO INHERIT
    # @classmethod
    # def configurable_default(cls):
    #     return SSLIOStream
    #
    #
    # CHRIS: NO NEED TO INHERIT
    # def reading(self):
    #     return self._handshake_reading or super(SSLIOStream, self).reading()
    #
    # CHRIS: NO NEED TO INHERIT
    # def writing(self):
    #     return self._handshake_writing or super(SSLIOStream, self).writing()
    #

    # def _do_ssl_handshake(self):
    #     # Based on code from test_ssl.py in the python stdlib
    #     try:
    #         self._handshake_reading = False
    #         self._handshake_writing = False
    #         self.socket.do_handshake()
    #     except ssl.SSLError as err:
    #         if err.args[0] == ssl.SSL_ERROR_WANT_READ:
    #             self._handshake_reading = True
    #             return
    #         elif err.args[0] == ssl.SSL_ERROR_WANT_WRITE:
    #             self._handshake_writing = True
    #             return
    #         elif err.args[0] in (ssl.SSL_ERROR_EOF,
    #                              ssl.SSL_ERROR_ZERO_RETURN):
    #             return self.close(exc_info=err)
    #         elif err.args[0] == ssl.SSL_ERROR_SSL:
    #             try:
    #                 peer = self.socket.getpeername()
    #             except Exception:
    #                 peer = '(not connected)'
    #             gen_log.warning("SSL Error on %s %s: %s",
    #                             self.socket.fileno(), peer, err)
    #             return self.close(exc_info=err)
    #         raise
    #     except socket.error as err:
    #         # Some port scans (e.g. nmap in -sT mode) have been known
    #         # to cause do_handshake to raise EBADF and ENOTCONN, so make
    #         # those errors quiet as well.
    #         # https://groups.google.com/forum/?fromgroups#!topic/python-tornado/ApucKJat1_0
    #         if (self._is_connreset(err) or
    #                 err.args[0] in (errno.EBADF, errno.ENOTCONN)):
    #             return self.close(exc_info=err)
    #         raise
    #     except AttributeError as err:
    #         # On Linux, if the connection was reset before the call to
    #         # wrap_socket, do_handshake will fail with an
    #         # AttributeError.
    #         return self.close(exc_info=err)
    #     else:
    #         self._ssl_accepting = False
    #         if not self._verify_cert(self.socket.getpeercert()):
    #             self.close()
    #             return
    #         self._run_ssl_connect_callback()
    #
    # def _run_ssl_connect_callback(self):
    #     if self._ssl_connect_callback is not None:
    #         callback = self._ssl_connect_callback
    #         self._ssl_connect_callback = None
    #         self._run_callback(callback)
    #     if self._ssl_connect_future is not None:
    #         future = self._ssl_connect_future
    #         self._ssl_connect_future = None
    #         future.set_result(self)
    #
    # def _verify_cert(self, peercert):
    #     """Returns True if peercert is valid according to the configured
    #     validation mode and hostname.
    #
    #     The ssl handshake already tested the certificate for a valid
    #     CA signature; the only thing that remains is to check
    #     the hostname.
    #     """
    #     if isinstance(self._ssl_options, dict):
    #         verify_mode = self._ssl_options.get('cert_reqs', ssl.CERT_NONE)
    #     elif isinstance(self._ssl_options, ssl.SSLContext):
    #         verify_mode = self._ssl_options.verify_mode
    #     assert verify_mode in (ssl.CERT_NONE, ssl.CERT_REQUIRED, ssl.CERT_OPTIONAL)
    #     if verify_mode == ssl.CERT_NONE or self._server_hostname is None:
    #         return True
    #     cert = self.socket.getpeercert()
    #     if cert is None and verify_mode == ssl.CERT_REQUIRED:
    #         gen_log.warning("No SSL certificate given")
    #         return False
    #     try:
    #         ssl.match_hostname(peercert, self._server_hostname)
    #     except ssl.CertificateError as e:
    #         gen_log.warning("Invalid SSL certificate: %s" % e)
    #         return False
    #     else:
    #         return True
    #
    # def _handle_read(self):
    #     if self._ssl_accepting:
    #         self._do_ssl_handshake()
    #         return
    #     super(SSLIOStream, self)._handle_read()
    #
    # def _handle_write(self):
    #     if self._ssl_accepting:
    #         self._do_ssl_handshake()
    #         return
    #     super(SSLIOStream, self)._handle_write()
    #
    # def connect(self, address, callback=None, server_hostname=None):
    #     self._server_hostname = server_hostname
    #     # Ignore the result of connect(). If it fails,
    #     # wait_for_handshake will raise an error too. This is
    #     # necessary for the old semantics of the connect callback
    #     # (which takes no arguments). In 6.0 this can be refactored to
    #     # be a regular coroutine.
    #     fut = super(SSLIOStream, self).connect(address)
    #     fut.add_done_callback(lambda f: f.exception())
    #     return self.wait_for_handshake(callback)
    #
    def _handle_connect(self):
        # Call the superclass method to check for errors.
        super(SSLIOStream, self)._handle_connect()
        if self.closed():
            return
        # When the connection is complete, wrap the socket for SSL
        # traffic.  Note that we do this by overriding _handle_connect
        # instead of by passing a callback to super().connect because
        # user callbacks are enqueued asynchronously on the IOLoop,
        # but since _handle_events calls _handle_connect immediately
        # followed by _handle_write we need this to be synchronous.
        #
        # The IOLoop will get confused if we swap out self.socket while the
        # fd is registered, so remove it now and re-register after
        # wrap_socket().
        self.io_loop.remove_handler(self.socket)
        old_state = self._state
        self._state = None
        self.socket = ssl_wrap_socket(self.socket, self._ssl_options,
                                      server_hostname=self._server_hostname,
                                      do_handshake_on_connect=False)
        self._add_io_state(old_state)

    # def wait_for_handshake(self, callback=None):
    #     """Wait for the initial SSL handshake to complete.
    #
    #     If a ``callback`` is given, it will be called with no
    #     arguments once the handshake is complete; otherwise this
    #     method returns a `.Future` which will resolve to the
    #     stream itself after the handshake is complete.
    #
    #     Once the handshake is complete, information such as
    #     the peer's certificate and NPN/ALPN selections may be
    #     accessed on ``self.socket``.
    #
    #     This method is intended for use on server-side streams
    #     or after using `IOStream.start_tls`; it should not be used
    #     with `IOStream.connect` (which already waits for the
    #     handshake to complete). It may only be called once per stream.
    #
    #     .. versionadded:: 4.2
    #
    #     .. deprecated:: 5.1
    #
    #        The ``callback`` argument is deprecated and will be removed
    #        in Tornado 6.0. Use the returned `.Future` instead.
    #
    #     """
    #     if (self._ssl_connect_callback is not None or
    #             self._ssl_connect_future is not None):
    #         raise RuntimeError("Already waiting")
    #     if callback is not None:
    #         warnings.warn("callback argument is deprecated, use returned Future instead",
    #                       DeprecationWarning)
    #         self._ssl_connect_callback = stack_context.wrap(callback)
    #         future = None
    #     else:
    #         future = self._ssl_connect_future = Future()
    #     if not self._ssl_accepting:
    #         self._run_ssl_connect_callback()
    #     return future
    #
    # def write_to_fd(self, data):
    #     try:
    #         return self.socket.send(data)
    #     except ssl.SSLError as e:
    #         if e.args[0] == ssl.SSL_ERROR_WANT_WRITE:
    #             # In Python 3.5+, SSLSocket.send raises a WANT_WRITE error if
    #             # the socket is not writeable; we need to transform this into
    #             # an EWOULDBLOCK socket.error or a zero return value,
    #             # either of which will be recognized by the caller of this
    #             # method. Prior to Python 3.5, an unwriteable socket would
    #             # simply return 0 bytes written.
    #             return 0
    #         raise
    #     finally:
    #         # Avoid keeping to data, which can be a memoryview.
    #         # See https://github.com/tornadoweb/tornado/pull/2008
    #         del data
    #
    # def read_from_fd(self, buf):
    #     try:
    #         if self._ssl_accepting:
    #             # If the handshake hasn't finished yet, there can't be anything
    #             # to read (attempting to read may or may not raise an exception
    #             # depending on the SSL version)
    #             return None
    #         try:
    #             return self.socket.recv_into(buf)
    #         except ssl.SSLError as e:
    #             # SSLError is a subclass of socket.error, so this except
    #             # block must come first.
    #             if e.args[0] == ssl.SSL_ERROR_WANT_READ:
    #                 return None
    #             else:
    #                 raise
    #         except socket.error as e:
    #             if e.args[0] in _ERRNO_WOULDBLOCK:
    #                 return None
    #             else:
    #                 raise
    #     finally:
    #         buf = None
    #
    # def _is_connreset(self, e):
    #     if isinstance(e, ssl.SSLError) and e.args[0] == ssl.SSL_ERROR_EOF:
    #         return True
    #     return super(SSLIOStream, self)._is_connreset(e)
