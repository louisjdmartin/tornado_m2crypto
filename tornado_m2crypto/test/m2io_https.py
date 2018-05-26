#!/usr/bin/env python
# Simple HTTPS test server
# Run with: tox -e m2io_https
# Client: curl -k -v https://localhost:12345


SSL_OPTS = {
  'certfile': 'tornado_m2crypto/test/test.crt',
  'keyfile':  'tornado_m2crypto/test/test.key',
}

# Patching
from tornado_m2crypto.netutil import m2_wrap_socket
import tornado.netutil
tornado.netutil.ssl_wrap_socket = m2_wrap_socket

import tornado.iostream
tornado.iostream.SSLIOStream.configure('tornado_m2crypto.m2iostream.M2IOStream')



import tornado.httpserver
import tornado.ioloop
import tornado.web

class getToken(tornado.web.RequestHandler):
    def get(self):
        self.write("hello\n\n")

application = tornado.web.Application([
    (r'/', getToken),
])

if __name__ == '__main__':
    http_server = tornado.httpserver.HTTPServer(application, ssl_options=SSL_OPTS)
    http_server.listen(12345)
    tornado.ioloop.IOLoop.instance().start()


