# tornado_m2crypto

This extension is meant to run tornado with M2Crypto instead of the standard python SSL

# Dependencies

Of course, you need M2Crypto, BUT, there is a bug. The Merge Request has been accepted already, but I do not know when the SWIG files
will be regenerated on the repo.
So in the meantime, you are better of getting a local checkout of the repository, and apply this patch

```
diff --git a/SWIG/_m2crypto_wrap.c b/SWIG/_m2crypto_wrap.c
index 2ee0526..1d0674c 100644
--- a/SWIG/_m2crypto_wrap.c
+++ b/SWIG/_m2crypto_wrap.c
@@ -32249,7 +32249,7 @@ SWIG_init(void) {
   SWIG_Python_SetConstant(d, d == md ? public_interface : NULL, "SSL_OP_NO_TLSv1",SWIG_From_int((int)(0x04000000L)));
   SWIG_Python_SetConstant(d, d == md ? public_interface : NULL, "SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS",SWIG_From_int((int)(0x00000800L)));
   SWIG_Python_SetConstant(d, d == md ? public_interface : NULL, "SSL_MODE_ENABLE_PARTIAL_WRITE",SWIG_From_int((int)(SSL_MODE_ENABLE_PARTIAL_WRITE)));
-  SWIG_Python_SetConstant(d, d == md ? public_interface : NULL, "SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER",SWIG_From_int((int)(SSL_MODE_ENABLE_PARTIAL_WRITE)));
+  SWIG_Python_SetConstant(d, d == md ? public_interface : NULL, "SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER",SWIG_From_int((int)(SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER)));
   SWIG_Python_SetConstant(d, d == md ? public_interface : NULL, "SSL_MODE_AUTO_RETRY",SWIG_From_int((int)(SSL_MODE_AUTO_RETRY)));
   SWIG_addvarlink(SWIG_globals(),(char*)"_ssl_err",Swig_var__ssl_err_get, Swig_var__ssl_err_set);
   SWIG_addvarlink(SWIG_globals(),(char*)"_ssl_timeout_err",Swig_var__ssl_timeout_err_get, Swig_var__ssl_timeout_err_set);
```


Or just use my repo: git+https://gitlab.com/chaen/m2crypto@tmpUntilSwigUpdated


Same goes to Tornado, until my PR is accepted, use git+https://github.com/chaen/tornado.git@iostreamConfigurable


# How to use


The tornado_m2crypto/tests directory contains several examples.
Basically, just take any normal https server with tornado you want, and add the following at the beginning

```
# Patching
# needed because some direct calls to ssl_wrap_socket in TCPServer
from tornado_m2crypto.m2netutil import m2_wrap_socket
import tornado.netutil
tornado.netutil.ssl_wrap_socket = m2_wrap_socket


# Dynamically configurable
import tornado.iostream
tornado.iostream.SSLIOStream.configure('tornado_m2crypto.m2iostream.M2IOStream')
```





# How to test

There are several types of tests.

## Unit test

Almost a copy paste of the SSLIOStream tests from tornado:

`tox -r`

## HTTPS test

A simple HTTPS server

`tox -r -e m2io_https`

You can then talk to you using (only requires `requests` package)

`python test_client.py`


## DIRAC test

An HTTPS server converting the certificate to "DIRAC certificates"

`tox -r -e m2io_dirac`

You can talk to it the same way as the normal HTTPS test, and you can give it a proxy
Note: on the DIRAC side, one must comment out the registration of the VOMS NID in Core/Security/__init__.py
