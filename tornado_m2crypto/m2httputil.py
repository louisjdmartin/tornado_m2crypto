from tornado.httputil import HTTPServerRequest


class M2HTTPServerRequest(HTTPServerRequest):

  def get_ssl_certificate(self, binary_form=False):
      """Returns the client's SSL certificate, if any.

      To use client certificates, the HTTPServer's
      `M2Crypto.SSL.Context.set_verify` field must be set, e.g.::

          SSL_OPTS = {

            'certfile': 'hostcert.pem',
            'keyfile': 'hostkey.pem',
            'cert_reqs': M2Crypto.SSL.verify_peer,
            'ca_certs': ca.cert.pem',
          }

          server = HTTPServer(app, ssl_options=SSL_OPTS)

      The return value is a M2Crypto.X509.X509Certificate
      See `M2Crypto.SSL.Connection.get_peer_cert` for more detail
      """

      return self.connection.stream.socket.get_peer_cert()

  def get_ssl_certificate_chain(self):
      """Returns the client's SSL certificate chain, if any.
       (Note that the chain does not contains the certificate itself !)

      To use client certificates, the HTTPServer's
      `M2Crypto.SSL.Context.set_verify` field must be set, e.g.::

          SSL_OPTS = {

            'certfile': 'hostcert.pem',
            'keyfile': 'hostkey.pem',
            'cert_reqs': M2Crypto.SSL.verify_peer,
            'ca_certs': ca.cert.pem',
          }

          server = HTTPServer(app, ssl_options=SSL_OPTS)

      The return value is a M2Crypto.X509.X509Stack
      See `M2Crypto.SSL.Connection.get_peer_cert_chain` for more detail
      """

      return self.connection.stream.socket.get_peer_cert_chain()
