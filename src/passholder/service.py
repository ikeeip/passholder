from zope.interface import Interface, implements
from twisted.application import internet, service 
from twisted.internet import protocol, defer
from twisted.internet.protocol import Protocol
from twisted.python import components, log
from OpenSSL import SSL
import txredisapi as redis
import os
import scrypt
import string
import binascii
import txredisapi


class IPassHolderService(Interface):

    def hold(passwd):
        """
        Return a deferred returning a string.
        """

    def unhold(hashed):
        """
        Return a deferred returning a string.
        """
        
    def remove(hashed):
        """
        Return a deferred returning a string.
        """


class PassHolderService(service.Service):
    implements(IPassHolderService)
    
    saltsize = 8

    def __init__(self, servicepasswd, encrypttime, db):
        self._servicepasswd = servicepasswd
        self._encrypttime = encrypttime
        self._db = db

    @defer.inlineCallbacks
    def hold(self, passwd):
        try:
            encoded = yield scrypt.encrypt(passwd, self._servicepasswd, self._encrypttime)
            hashed = yield binascii.b2a_hex(scrypt.hash(encoded, os.urandom(self.saltsize)))
            yield self._db.set("ph:" + hashed, encoded)
            defer.returnValue(hashed)
        except Exception:
            log.err()
            raise Exception('operation failed');

    @defer.inlineCallbacks
    def unhold(self, hashed):
        encoded = yield self._db.get("ph:" + hashed)
        if encoded is None:
            raise Exception('not found')
        try:
            decoded = yield scrypt.decrypt(encoded, self._servicepasswd, self._encrypttime)
            defer.returnValue(decoded)
        except Exception:        
            raise Exception('operation failed')
    
    @defer.inlineCallbacks    
    def remove(self, hashed):
        deleted = yield self._db.delete("ph:" + hashed)
        if deleted == 0:
            raise Exception('not found')
        defer.returnValue('ok')


class PassHolderProtocol(Protocol):
    
    def _eb(self, fail):
        self.write('e:2:' + fail.getErrorMessage())
    
    def _cb(self, data):
        self.write('s:'+data)
    
    def cmd_hold(self, passwd):
        self.factory.hold(passwd).addCallbacks(self._cb, self._eb)
    
    def cmd_unhold(self, hashed):
        self.factory.unhold(hashed).addCallbacks(self._cb, self._eb) 
    
    def cmd_remove(self, hashed):
        self.factory.remove(hashed).addCallbacks(self._cb, self._eb) 
    
    def dataReceived(self, data):
        try:
            (cmd, args) = string.split(data, ':', 1)
            method = {
                'h': self.cmd_hold,
                'u': self.cmd_unhold,
                'r': self.cmd_remove,
            }[cmd]
        except:
            self.write('e:1:invalid command')
            
        try:
            method(args)
        except:
            log.err()
            self.write('e:0:internal server error')
        
    def write(self, data):
        self.transport.write(data)
        

class IPassHolderFactory(Interface):

    def hold(passwd):
        """
        Return a deferred returning a string.
        """

    def unhold(hashed):
        """
        Return a deferred returning a string.
        """
        
    def remove(hashed):
        """
        Return a deferred returning a string.
        """
        
    def buildProtocol(addr):
        """
        Return a protocol returning a string.
        """   
     

class PassHolderFactoryFromService(protocol.ServerFactory):
    implements(IPassHolderFactory)

    protocol = PassHolderProtocol

    def __init__(self, service):
        self.service = service

    def hold(self, passwd):
        return self.service.hold(passwd)
    
    def unhold(self, hashed):
        return self.service.unhold(hashed)
    
    def remove(self, hashed):
        return self.service.remove(hashed)

components.registerAdapter(PassHolderFactoryFromService, IPassHolderService, IPassHolderFactory)


class ServerContextFactory:
    
    def __init__(self, certFile, keyFile, caCertFile):
        self._certFile = certFile
        self._keyFile = keyFile
        self._caCertFile = caCertFile
        
    def verifyCallback(self, connection, x509, errnum, errdepth, ok):
        if not ok:
            log.msg('invalid cert from subject:', x509.get_subject())
            return False
            
        return True

    def getContext(self):
        ctx = SSL.Context(SSL.SSLv23_METHOD)
        ctx.use_certificate_file(self._certFile)
        ctx.use_privatekey_file(self._keyFile)
        ctx.set_verify(SSL.VERIFY_PEER | SSL.VERIFY_FAIL_IF_NO_PEER_CERT, self.verifyCallback)
        ctx.load_verify_locations(self._caCertFile)
        return ctx
