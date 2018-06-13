#!/usr/bin/env python
# Simple HTTPS test server
# Run with: tox -e m2io_https
# Client: curl -k -v https://localhost:12345
import os
import M2Crypto
from M2Crypto import X509

#THIS WORKS AS TEST BUT NOT HERE WHY ????
CERTDIR = os.path.join(os.path.dirname(__file__), 'certs/')
SSL_OPTS = {

  'certfile': CERTDIR + 'MrBoincHost/hostcert.pem',
  'keyfile': CERTDIR + 'MrBoincHost/hostkey.pem',
  'cert_reqs': M2Crypto.SSL.verify_peer,
  'ca_certs': CERTDIR + 'ca/ca.cert.pem',
}

#SSL_OPTS = {
#
#  'certfile': '/tmp/hostcert/hostcert.pem',
#  'keyfile': '/tmp/hostcert/hostkey.pem',
#  'cert_reqs': M2Crypto.SSL.verify_peer,
#  'ca_certs': '/tmp/grid-security/allCAs.pem',
#  'sslDebug' : True
#}

# Patching
# You need it because TCPServer calls directly ssl_wrap_socket
from tornado_m2crypto.m2netutil import m2_wrap_socket
import tornado.netutil
tornado.netutil.ssl_wrap_socket = m2_wrap_socket

import tornado.iostream
tornado.iostream.SSLIOStream.configure('tornado_m2crypto.m2iostream.M2IOStream')



import tornado.httpserver
import tornado.ioloop
import tornado.web


class getToken(tornado.web.RequestHandler):
    def get(self):
        print self.request.connection.stream.socket.get_peer_cert().as_text() #False =  dictionnaire, True=Binaire
        print "CHRIS %s"%len(self.request.connection.stream.socket.get_peer_cert_chain())
        for c in self.request.connection.stream.socket.get_peer_cert_chain():
          print ('++++++++++++++++++++++')
          print c.as_text()
        self.write("hello\n\n")

application = tornado.web.Application([
    (r'/', getToken),
])

if __name__ == '__main__':
    http_server = tornado.httpserver.HTTPServer(application, ssl_options=SSL_OPTS)
    http_server.listen(12345)
    tornado.ioloop.IOLoop.instance().start()
