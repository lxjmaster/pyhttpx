class PyhttpxBaseException(Exception):
    pass


class TLSVerifyDataException(PyhttpxBaseException):
    pass


class TLSHandshakeFailed(PyhttpxBaseException):
    pass


class TLSDecryptErrorException(PyhttpxBaseException):
    pass


class TLSEncryptedAlertException(PyhttpxBaseException):
    pass


class TLSCipherNotSupportedErrorException(PyhttpxBaseException):
    pass


class TLSExtensionNotSupportedErrorException(PyhttpxBaseException):
    pass


class TLSECCNotSupportedErrorException(PyhttpxBaseException):
    pass


class PyhttpxConnectionAbortedError(PyhttpxBaseException):
    pass


class ConnectionTimeout(PyhttpxBaseException):
    pass


class ConnectionClosed(PyhttpxBaseException):
    pass


class ReadTimeout(PyhttpxBaseException):
    pass


class TooManyRedirects(PyhttpxBaseException):
    pass


# websocket
class SwitchingProtocolError(PyhttpxBaseException):
    pass


class SecWebSocketKeyError(PyhttpxBaseException):
    pass


class WebSocketClosed(PyhttpxBaseException):
    pass


class ProxyError(IOError):
    """Socket_err contains original socket.error exception."""

    def __init__(self, msg, socket_err=None):
        self.msg = msg
        self.socket_err = socket_err

        if socket_err:
            self.msg += ": {}".format(socket_err)

    def __str__(self):
        return self.msg
