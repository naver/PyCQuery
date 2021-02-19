from pycquery_krb.network.clientsocket import KerberosClientSocket
from pycquery_krb.network.aioclientsocket import AIOKerberosClientSocket
from pycquery_krb.network.aioclientsockssocket import AIOKerberosClientSocksSocket

class KerberosClientSocketSelector:
    def __init__(self):
        pass
    
    @staticmethod
    def select(target, is_async = False):
        if is_async is False:
            return KerberosClientSocket(target)
        else:
            if target.proxy is not None:
                return AIOKerberosClientSocksSocket(target)
            else:
                return AIOKerberosClientSocket(target)