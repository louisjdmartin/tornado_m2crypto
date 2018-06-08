import errno
import os
import socket
import warnings

from .netutil import m2_wrap_socket

from tornado import stack_context
from tornado.concurrent import Future
from tornado.iostream import SSLIOStream, _ERRNO_WOULDBLOCK,IOStream
from tornado.log import gen_log

from M2Crypto import m2, SSL, Err
from myDebug import printDebug




_client_m2_ssl_defaults = SSL.Context(weak_crypto = True)
# _client_m2_ssl_defaults.set_options(m2.X509_PURPOSE_SSL_CLIENT)

_server_m2_ssl_defaults = SSL.Context(weak_crypto = True)
# _server_m2_ssl_defaults.set_options(m2.X509_PURPOSE_SSL_SERVER)


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

    #@printDebug
    def initialize(self, *args, **kwargs):
        """The ``ssl_options`` keyword argument may either be an
        `SSL.SSLContext` object or a dictionary of keywords arguments
        for `ssl.wrap_socket`
        """
        self._ssl_options = kwargs.pop('ssl_options', _client_m2_ssl_defaults)
        IOStream.__init__(self, *args, **kwargs)
        self._done_setup = False
        self._ssl_accepting = True
        self._handshake_reading = False
        self._handshake_writing = False
        self._ssl_connect_callback = None
        self._server_hostname = None

        # If the socket is already connected, attempt to start the handshake.
        try:
            n = self.socket.getpeername()
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
    #         setup_ssl
    #         ret = self.socket.accept_ssl()
    #         if ret < 0:
    #           get_error
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


    # CHRIS missing a hell lot of error handling
    @printDebug
    def _do_ssl_handshake(self):
        # Based on code from test_ssl.py in the python stdlib
        #import traceback
        #print "CHRIS TRACEBACK"
        #for line in traceback.format_stack():
        #  print(line.strip())
        #print "====="
        print ">> SOCKET TYPE: %s" % type(self.socket)
        try:
            self._handshake_reading = False
            self._handshake_writing = False
            if not self._done_setup:
                self.socket.setup_ssl()
                if self.socket.server_side:
                    self.socket.set_accept_state()
                else:
                    self.socket.set_connect_state()
                self._done_setup = True
            # Actual accept/connect logic
            if self.socket.server_side:
              res = self.socket.accept_ssl()
            else:
              res = self.socket.connect_ssl()
            if res == 0:
                # TODO: We should somehow get SSL_WANT_READ/WRITE here
                #       and then set the correct flag, although it does
                #       work as long as one of them gets set
                self._handshake_reading = True
                #self._handshake_writing = True
                return
            if res < 0:
                err_num = self.socket.ssl_get_error(res)
                print "Err: %s" % err_num
                print "Err Str: %s" % Err.get_error_reason(err_num)
                return self.close()
        except SSL.SSLError as e:
            raise
        except socket.error as err:
            print "Socket error!"
            # Some port scans (e.g. nmap in -sT mode) have been known
            # to cause do_handshake to raise EBADF and ENOTCONN, so make
            # those errors quiet as well.
            # https://groups.google.com/forum/?fromgroups#!topic/python-tornado/ApucKJat1_0
            if (self._is_connreset(err) or
                    err.args[0] in (errno.EBADF, errno.ENOTCONN)):
                return self.close(exc_info=err)
            raise
        except AttributeError as err:
            # On Linux, if the connection was reset before the call to
            # wrap_socket, do_handshake will fail with an
            # AttributeError.
            return self.close(exc_info=err)
        else:
            self._ssl_accepting = False
            if not self._verify_cert(self.socket.get_peer_cert()):
                print "VALIDATION FAILED!"
                self.close()
                return
            print "Connect complete! (Sever: %s)!" % self.socket.server_side
            self._run_ssl_connect_callback()

    # CHRIS no need to change
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
    #@printDebug
    def _verify_cert(self, peercert):
        """Returns True if peercert is valid according to the configured
        validation mode and hostname.

        The ssl handshake already tested the certificate for a valid
        CA signature; the only thing that remains is to check
        the hostname.
        """
        return True
        checker = SSL.Checker.Checker()
        if not checker(self.socket.get_peer_cert(), self.socket.addr[0]):
            return False

    # CHRIS : no need
    # def _handle_read(self):
    #     if self._ssl_accepting:
    #         self._do_ssl_handshake()
    #         return
    #     super(SSLIOStream, self)._handle_read()
    #
    # CHRIS : no need
    # def _handle_write(self):
    #     if self._ssl_accepting:
    #         self._do_ssl_handshake()
    #         return
    #     super(SSLIOStream, self)._handle_write()
    #

    # CHRIS no need
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

    @printDebug
    def _handle_connect(self):
        # Call the superclass method to check for errors.
        self._handle_connect_super()
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
        self.socket = m2_wrap_socket(self.socket, self._ssl_options,
                                      server_hostname=self._server_hostname)
        self._add_io_state(old_state)

    # CHRIS: no need to inherit
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
    #@printDebug
    def write_to_fd(self, data):
        #if 'UU' in data:

        try:
            res = self.socket.send(data)
            # TODO: Hmm, -1 sometimes means try again,
            #       this is a case where working out how to use
            #       SSL_WANT_WRITE is going to be needed...
            if res < 0:

              err = self.socket.ssl_get_error( res)
              if err == SSL.m2.ssl_error_want_write:
                  return 0

              # Now this is is clearly not correct.
              # We get error "1 (ssl_error_ssl)" but the calling function (_handle_write)
              # is handling exception. So we might have to throw instead
              # of returning 0
              # print "CHRIS ALL ERRORS"
              # for e in dir(SSL.m2):
              #   if 'ssl_error' in e:
              #     print "%s -> %s"%(e, getattr(SSL.m2,e))
              # -1 means try again, so let's do it..
              if res == -1:
                #return 0
                raise socket.error(errno.EWOULDBLOCK, "Fix me please")
              raise Exception()

            #if res < 0:
            #    return 0
            return res
        finally:
            # Avoid keeping to data, which can be a memoryview.
            # See https://github.com/tornadoweb/tornado/pull/2008
            del data

    # @printDebug
    def read_from_fd(self, buf):
        try:
            if self._ssl_accepting:
                # If the handshake hasn't finished yet, there can't be anything
                # to read (attempting to read may or may not raise an exception
                # depending on the SSL version)
                return None
            try:
                print("CHRIS read_from_fd trying recv")
                retRcv =  self.socket.recv_into(buf)
                print("CHRIS read_from_fd retRcv %s"%retRcv)
                return retRcv
            except TypeError as e:
                # Bug in M2Crypto?
                # TODO: This shouldn't use an exception path
                #       Either Connection should be subclassed with a working
                #       implementation of recv_into, or work out why it
                #       sometimes gets a None returned anyway, it's probably
                #       a race between the handshake and the first read?
                print "Nothing to read? %s"%repr(e)

                return None
            except SSL.SSLError as e:
                print "CHRIS READ ERROR %s %s"%(type(e), repr(e))
                if e.args[0] == m2.ssl_error_want_read:
                    print("CHRIS read_from_fd want read")
                    return None
                else:
                    print("CHRIS read_from_fd raise")

                    raise
            except socket.error as e:
                print("CHRIS socker.error")
                if e.args[0] in _ERRNO_WOULDBLOCK:
                    print("CHRIS would block")
                    return None
                else:
                    print("CHRIS raise")
                    raise
        finally:
            print("CHRIS fd finally")
            buf = None
    #
    # Do inherit because there is no such error in M2Crpto
    #@printDebug
    def _is_connreset(self, e):
      return IOStream._is_connreset(self, e)

    def _handle_connect_super(self):
        # Work around a bug where M2Crypto passes None as last argument to
        # getsockopt, but an int is required.
        err = self.socket.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR, 0)
        if err != 0:
            self.error = socket.error(err, os.strerror(err))
            # IOLoop implementations may vary: some of them return
            # an error state before the socket becomes writable, so
            # in that case a connection failure would be handled by the
            # error path in _handle_events instead of here.
            if self._connect_future is None:
                gen_log.warning("Connect error on fd %s: %s",
                                self.socket.fileno(), errno.errorcode[err])
            print "Close connect error!"
            self.close()
            return
        if self._connect_callback is not None:
            callback = self._connect_callback
            self._connect_callback = None
            self._run_callback(callback)
        if self._connect_future is not None:
            future = self._connect_future
            self._connect_future = None
            future.set_result(self)
        self._connecting = False
