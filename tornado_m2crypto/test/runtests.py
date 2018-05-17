
import tornado.test.runtests as original_runtests

import tornado

print tornado.iostream
tornado.iostream.SSLIOStream.configure('tornado_m2crypto.m2iostream.M2IOStream')


M2_TEST_MODULES = [    'tornado.test.iostream_test',
                  ]

original_runtests.TEST_MODULES = M2_TEST_MODULES

all = original_runtests.all
original_runtests.main()
