from zope.interface import implements
from twisted.python import usage
from twisted.plugin import IPlugin
from twisted.application.service import IServiceMaker
from twisted.application import internet
from passholder.service import PassHolderService, IPassHolderFactory, ServerContextFactory
import txredisapi as redis
import os, string

class Options(usage.Options):

    optParameters = [
        ['password', 'p'],
        ['port', 'P', 8123, "port number to listen on", int],
        ['listen', None, "127.0.0.1", "interface to listen on"],

        ["redis-host", None, "127.0.0.1", "hostname or ip address of the redis server"],
        ["redis-port", None, 6379, "port number of the redis server", int],
        ["redis-pool", None, 10, "connection pool size", int],
        ["redis-db", None, 0, "redis database", int],

        ['server-cert', 'c', 'keys/server-cert.pem'],
        ['server-key', 'k', 'keys/server-key.pem'],
        ['ca-cert', 'a', 'keys/ca-cert.pem'],

        ['scrypt-enctime', 't', 0.1, None, float],
    ]

class PassHolderServiceMaker(object):
    implements(IServiceMaker, IPlugin)
    tapname = 'passholder'
    description = "Secure Password Holder service"
    options = Options

    def makeService(self, config):

        if config['password'] is None:
            raise usage.UsageError, "--password is required."
        if string.find(config['password'], 'env:') == 0:
            env = string.replace(config['password'], 'env:', '', 1)
            pwd = os.getenv(env)
            if pwd is None:
                raise usage.UsageError, "invalid environment variable in --password option"
            else:
                config['password'] = pwd

        db = redis.lazyConnectionPool(config['redis-host'], config['redis-port'], poolsize=config['redis-pool'], dbid=config['redis-db'])
        passHolderService = PassHolderService(config['password'], config['scrypt-enctime'], db)
        return internet.SSLServer(config['port'], 
            IPassHolderFactory(passHolderService),
            ServerContextFactory(config['server-cert'], config['server-key'], config['ca-cert']),
            interface=config["listen"]
        )

serviceMaker = PassHolderServiceMaker()
