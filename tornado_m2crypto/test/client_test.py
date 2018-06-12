import requests
#CERT='test.crt'
#KEY='test.key'
CERT='/tmp/proxy.pem'
KEY='/tmp/proxy.pem'
#CERT='/tmp/.globus/usercert.pem'
#KEY='/tmp/.globus/new_userkey.pem'
CERTDIR = '/home/chaen/dirac/tornadoM2Crypto/test_tornado_m2crypto/certs/'
import os
CERT= os.path.realpath(CERTDIR + 'MrBoinc/usercert.pem')
KEY=os.path.realpath(CERTDIR  + 'MrBoinc/userkey.pem')

print (CERT,KEY)
import sys




SERVER = 'https://localhost:12345'
print requests.get('https://localhost:12345', cert = (CERT,KEY), verify = False)
sys.exit(0)

# THIS IS FOR LATER POTENTIALLY

from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.ssl_ import create_urllib3_context

# This is the 2.11 Requests cipher string, containing 3DES.
CIPHERS = (
    'ECDH+AESGCM:DH+AESGCM:ECDH+AES256:DH+AES256:ECDH+AES128:DH+AES:ECDH+HIGH:'
    'DH+HIGH:ECDH+3DES:DH+3DES:RSA+AESGCM:RSA+AES:RSA+HIGH:RSA+3DES:!aNULL:'
    '!eNULL:!MD5'
)


class DESAdapter(HTTPAdapter):
    """
    A TransportAdapter that re-enables 3DES support in Requests.
    """
    def init_poolmanager(self, *args, **kwargs):
        context = create_urllib3_context(ciphers=CIPHERS)
        kwargs['ssl_context'] = context
        return super(DESAdapter, self).init_poolmanager(*args, **kwargs)

    def proxy_manager_for(self, *args, **kwargs):
        context = create_urllib3_context(ciphers=CIPHERS)
        kwargs['ssl_context'] = context
        return super(DESAdapter, self).proxy_manager_for(*args, **kwargs)

s = requests.Session()
s.mount(SERVER, DESAdapter())
print s.get(SERVER, cert = (CERT,KEY), verify = False)

#requests.get('https://localhost:12345', cert = (CERT,KEY), verify = False)
