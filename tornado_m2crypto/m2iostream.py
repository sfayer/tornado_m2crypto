"""
This module is meant to replace the standard SSLIOStream from Tornado, and to use M2Crypto instead of ssl.

In order to use it, just add the following at the beginning of your server

```

  # Patching
  # You need it because TCPServer calls directly ssl_wrap_socket
  from tornado_m2crypto.m2netutil import m2_wrap_socket
  import tornado.netutil
  tornado.netutil.ssl_wrap_socket = m2_wrap_socket

  # Set dynamically the IOStream you want
  import tornado.iostream
  tornado.iostream.SSLIOStream.configure('tornado_m2crypto.m2iostream.M2IOStream')
```

A complete example would be

```
  SSL_OPTS = {

    'certfile': 'hostcert.pem',
    'keyfile': 'hostkey.pem',
    'cert_reqs': M2Crypto.SSL.verify_peer,
    'ca_certs': 'ca.cert.pem',
  }

  # Patching
  # You need it because TCPServer calls directly ssl_wrap_socket
  from tornado_m2crypto.m2netutil import m2_wrap_socket
  import tornado.netutil
  tornado.netutil.ssl_wrap_socket = m2_wrap_socket

  # Set dynamically the IOStream you want
  import tornado.iostream
  tornado.iostream.SSLIOStream.configure('tornado_m2crypto.m2iostream.M2IOStream')

  # Set dynamically the HTTPServerRequest to use M2Crypto
  import tornado.httputil
  tornado.httputil.HTTPServerRequest.configure('tornado_m2crypto.m2httputil.M2HTTPServerRequest')

  # From now on, it is completely standard tornado https server

  import tornado.httpserver
  import tornado.ioloop
  import tornado.web


  class getToken(tornado.web.RequestHandler):
      def get(self):
          print(self.request.get_ssl_certificate().as_text())
          self.write("hello\n\n")

  application = tornado.web.Application([
      (r'/', getToken),
  ])

  if __name__ == '__main__':
      http_server = tornado.httpserver.HTTPServer(application, ssl_options=SSL_OPTS)
      http_server.listen(12345)
      tornado.ioloop.IOLoop.instance().start()
```


Note that to get the peer certificate, you need to use `self.request.connection.stream.socket.get_peer_cert()`

The supported SSL options are all described in `~m2netutil.ssl_options_to_m2_context`.

WARNING:
Until my MR/PR are accepted, please use

Tornado: git+https://github.com/chaen/tornado.git@iostreamConfigurable
M2Crypto: git+https://gitlab.com/chaen/m2crypto.git@tmpUntilSwigUpdated

TODO: in the iostream._read_to_buffer, we only catch socket.error. This works because
      ssl.SSLError inherits from socket.error, but not M2Crypto.SSL.SSLError, so one might
      need to overwrite that here

TODO: overwrite the close method to do like DIRAC M2SSLTransport.

"""

import errno
import os
import socket
import ssl

from tornado_m2crypto.m2netutil import m2_wrap_socket

from tornado.iostream import SSLIOStream, _ERRNO_WOULDBLOCK, IOStream
from tornado.log import gen_log

from M2Crypto import m2, SSL, Err


_client_m2_ssl_defaults = SSL.Context()
# Do I need to add the pruposes ?
# _client_m2_ssl_defaults.set_options(m2.X509_PURPOSE_SSL_CLIENT)

_server_m2_ssl_defaults = SSL.Context()
# _server_m2_ssl_defaults.set_options(m2.X509_PURPOSE_SSL_SERVER)


class M2IOStream(SSLIOStream):
    """A utility class to write to and read from a non-blocking SSL socket using M2Crypto.


    If the socket passed to the constructor is already connected,
    it should be wrapped with::

        ssl.wrap_socket(sock, do_handshake_on_connect=False, **kwargs)

    before constructing the `SSLIOStream`.  Unconnected sockets will be
    wrapped when `IOStream.connect` is finished.
    """

    def __init__(self, *args, **kwargs):
        pass

    def initialize(self, *args, **kwargs):
        """The ``ssl_options`` keyword argument may either be an
        `~M2Crypto.SSL.SSLContext` object or a dictionary of keywords arguments (see `~m2netutil.ssl_options_to_m2_context`.)
        """
        self._ssl_options = kwargs.pop("ssl_options", _client_m2_ssl_defaults)

        if kwargs.pop("create_context_on_init", False):
            server_side = kwargs.pop("server_side", False)
            do_handshake_on_connect = kwargs.pop("do_handshake_on_connect", False)
            connection = args[0]
            self.socket = m2_wrap_socket(
                connection,
                self._ssl_options,
                server_side=server_side,
                do_handshake_on_connect=do_handshake_on_connect,
            )

            args = (self.socket,) + args[1:]

        IOStream.__init__(self, *args, **kwargs)
        self._done_setup = False
        self._ssl_accepting = True
        self._handshake_reading = False
        self._handshake_writing = False
        self._ssl_connect_callback = None
        self._server_hostname = None

        # If the socket is already connected, attempt to start the handshake.
        try:
            n = self.socket.getpeername()
        except socket.error:
            pass
        else:
            # Indirectly start the handshake, which will run on the next
            # IOLoop iteration and then the real IO state will be set in
            # _handle_events.
            self._add_io_state(self.io_loop.WRITE)

    def _do_ssl_handshake(self):
        try:
            self._handshake_reading = False
            self._handshake_writing = False
            if not self._done_setup:
                self.socket.setup_ssl()
                # This server_side was added when creating the Connection
                # it is not a standard attribute
                if self.socket.server_side:
                    self.socket.set_accept_state()
                else:
                    self.socket.set_connect_state()
                self._done_setup = True
            # Actual accept/connect logic
            if self.socket.server_side:
                res = self.socket.accept_ssl()
            else:
                res = self.socket.connect_ssl()
            # The err_num is used for the handshake state either way
            err_num = self.socket.ssl_get_error(res)
            if res == 0:
                if err_num == ssl.SSL_ERROR_WANT_READ:
                    self._handshake_reading = True
                    return
                elif err_num == ssl.SSL_ERROR_WANT_WRITE:
                    self._handshake_writing = True
                    return
                else: # SSL_ERROR_ZERO_RETURN and others
                    return self.close()
            if res < 0:
                gen_log.error("Err: %s" % err_num)
                gen_log.error("Err Str: %s" % Err.get_error_reason(err_num))
                return self.close()
        except SSL.SSLError as err:
            try:
                peer = self.socket.getpeername()
            except Exception:
                peer = "(not connected)"
            gen_log.warning("SSL Error on %s %s: %s", self.socket.fileno(), peer, err)
            return self.close(exc_info=err)
        except socket.error as err:
            gen_log.error("Socket error!")
            # Some port scans (e.g. nmap in -sT mode) have been known
            # to cause do_handshake to raise EBADF and ENOTCONN, so make
            # those errors quiet as well.
            # https://groups.google.com/forum/?fromgroups#!topic/python-tornado/ApucKJat1_0
            if self._is_connreset(err) or err.args[0] in (errno.EBADF, errno.ENOTCONN):
                return self.close(exc_info=err)
            raise
        except AttributeError as err:
            # On Linux, if the connection was reset before the call to
            # wrap_socket, do_handshake will fail with an
            # AttributeError.
            return self.close(exc_info=err)
        else:
            self._ssl_accepting = False
            if not self._verify_cert(self.socket.get_peer_cert()):
                gen_log.error("VALIDATION FAILED!")
                self.close()
                return
            gen_log.debug("Connect complete! (Sever: %s)!" % self.socket.server_side)
            self._run_ssl_connect_callback()

    def close_fd(self):
        self.socket.shutdown(socket.SHUT_RDWR)
        super(M2IOStream, self).close_fd()

    def _verify_cert(self, peercert):
        """Returns True if peercert is valid according to the configured
        validation mode and hostname.
        """
        checker = getattr(
            self.socket, "postConnectionCheck", self.socket.serverPostConnectionCheck
        )
        addr = self.socket.socket.getpeername()[0]
        if checker and not checker(self.socket.get_peer_cert(), addr):
            return False
        return True

    def _handle_connect(self):
        # Call the superclass method to check for errors.
        self._handle_connect_super()
        if self.closed():
            return
        # When the connection is complete, wrap the socket for SSL
        # traffic.  Note that we do this by overriding _handle_connect
        # instead of by passing a callback to super().connect because
        # user callbacks are enqueued asynchronously on the IOLoop,
        # but since _handle_events calls _handle_connect immediately
        # followed by _handle_write we need this to be synchronous.
        #
        # The IOLoop will get confused if we swap out self.socket while the
        # fd is registered, so remove it now and re-register after
        # wrap_socket().
        self.io_loop.remove_handler(self.socket)
        old_state = self._state
        self._state = None
        self.socket = m2_wrap_socket(
            self.socket, self._ssl_options, server_hostname=self._server_hostname
        )
        self._add_io_state(old_state)

    def write_to_fd(self, data):

        try:
            res = self.socket.send(data)
            if res < 0:

                err = self.socket.ssl_get_error(res)
                # if the error is try again, let's do it !
                if err == SSL.m2.ssl_error_want_write:
                    return 0

                # Now this is is clearly not correct.
                # We get error "1 (ssl_error_ssl)" but the calling function (_handle_write)
                # is handling exception. So we might have to throw instead
                # of returning 0
                if res == -1:
                    # return 0
                    raise socket.error(errno.EWOULDBLOCK, "Fix me please")
                raise Exception()

            return res
        finally:
            # Avoid keeping to data, which can be a memoryview.
            # See https://github.com/tornadoweb/tornado/pull/2008
            del data

    def read_from_fd(self, buf):
        try:
            if self._ssl_accepting:
                # If the handshake hasn't finished yet, there can't be anything
                # to read (attempting to read may or may not raise an exception
                # depending on the SSL version)
                return None
            try:
                return self.socket.recv_into(buf)
            except TypeError as e:
                # Bug in M2Crypto?
                # TODO: This shouldn't use an exception path
                #       Either Connection should be subclassed with a working
                #       implementation of recv_into, or work out why it
                #       sometimes gets a None returned anyway, it's probably
                #       a race between the handshake and the first read?
                # print("Nothing to read?", repr(e))

                return None
            except SSL.SSLError as e:
                if e.args[0] == m2.ssl_error_want_read:
                    return None
                else:
                    raise ssl.SSLError(*e.args)
            except socket.error as e:
                if e.args[0] in _ERRNO_WOULDBLOCK:
                    return None
                else:
                    raise
        finally:
            buf = None

    # Do inherit because there is no such error in M2Crpto
    def _is_connreset(self, e):
        return IOStream._is_connreset(self, e)

    def _handle_connect_super(self):
        # Work around a bug where M2Crypto passes None as last argument to
        # getsockopt, but an int is required.
        err = self.socket.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR, 0)
        if err != 0:
            self.error = socket.error(err, os.strerror(err))
            # IOLoop implementations may vary: some of them return
            # an error state before the socket becomes writable, so
            # in that case a connection failure would be handled by the
            # error path in _handle_events instead of here.
            if self._connect_future is None:
                gen_log.warning(
                    "Connect error on fd %s: %s",
                    self.socket.fileno(),
                    errno.errorcode[err],
                )
            gen_log.warning("Close connect error!")
            self.close()
            return
        if self._connect_callback is not None:
            callback = self._connect_callback
            self._connect_callback = None
            self._run_callback(callback)
        if self._connect_future is not None:
            future = self._connect_future
            self._connect_future = None
            future.set_result(self)
        self._connecting = False

    def get_ssl_certificate(self, **kwargs):
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
        return self.socket.get_peer_cert()

    def get_ssl_certificate_chain(self, **kwargs):
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

        return self.socket.get_peer_cert_chain()
