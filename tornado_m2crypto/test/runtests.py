
import tornado.test.runtests as original_runtests

import copy
import tornado


# Patching
# You need it because TCPServer calls directly ssl_wrap_socket
from tornado_m2crypto.m2netutil import m2_wrap_socket
import tornado.netutil
tornado.netutil.ssl_wrap_socket = m2_wrap_socket



print tornado.iostream
tornado.iostream.SSLIOStream.configure('tornado_m2crypto.m2iostream.M2IOStream')


import tornado.httputil
tornado.httputil.HTTPServerRequest.configure('tornado_m2crypto.m2httputil.M2HTTPServerRequest')

# Specific test
# M2_TEST_MODULES = [    'tornado.test.iostream_test.TestIOStreamSSL.test_flow_control',]

# All my tests
M2_TEST_MODULES = [    'm2iostream_test.TestIOStreamM2',
                       'tornado.test.httputil_test']

# Not everything passes here yet
# e.g. tornado.test.simple_httpclient_test.SimpleHTTPSClientTestCase
#
# M2_TEST_MODULES = copy.copy(original_runtests.TEST_MODULES)
# M2_TEST_MODULES.remove('tornado.test.iostream_test')
# M2_TEST_MODULES.append('m2iostream_test.TestIOStreamM2')


print "RUNNING %s"%M2_TEST_MODULES




original_runtests.TEST_MODULES = M2_TEST_MODULES

all = original_runtests.all
original_runtests.main()
