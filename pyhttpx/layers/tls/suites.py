import struct

CIPHER_SUITES = [
    0x1301,
    0x1302,
    0x1303,
    0xC02B,
    0xC02F,
    0xCCA9,
    0xCCA8,
    0xC02C,
    0xC030,
    0xC00A,
    0xC009,
    0xC013,
    0xC014,
    0x009C,
    0x009D,
    0x002F,
    0x0035,
]

if 1 == 0:
    CIPHER_SUITES = [
        # 0xc02b,0xc02f,
        # 0xcca8,0xcca9,
        0x002F,
        0x0035,
    ]
TLS_SUITES = {
    0x1301: {
        "name": "TLS_AES_128_GCM_SHA256",
        "key_len": 16,
        "sha": "sha256",
        "type": "aead",
        "kct": "ECDHE",
    },
    0x1302: {
        "name": "TLS_AES_256_GCM_SHA384",
        "key_len": 32,
        "sha": "sha384",
        "type": "aead",
        "kct": "ECDHE",
    },
    0x1303: {
        "name": "TLS_CHACHA20_POLY1305_SHA256",
        "key_len": 32,
        "sha": "sha256",
        "type": "aead",
        "kct": "ECDHE",
    },
    0xC02B: {
        "name": "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
        "key_len": 16,
        "sha": "sha256",
        "type": "aead",
        "kct": "ECDHE",
    },
    0xC02F: {
        "name": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        "key_len": 16,
        "sha": "sha256",
        "type": "aead",
        "kct": "ECDHE",
    },
    0xC02C: {
        "name": "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
        "key_len": 32,
        "sha": "sha384",
        "type": "aead",
        "kct": "ECDHE",
    },
    0xC030: {
        "name": "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        "key_len": 32,
        "sha": "sha384",
        "type": "aead",
        "kct": "ECDHE",
    },
    0x009C: {
        "name": "TLS_RSA_WITH_AES_128_GCM_SHA256",
        "key_len": 16,
        "sha": "sha256",
        "type": "aead",
        "kct": "RSA",
    },
    0x009D: {
        "name": "TLS_RSA_WITH_AES_256_GCM_SHA384",
        "key_len": 32,
        "sha": "sha384",
        "type": "aead",
        "kct": "RSA",
    },
    0xCCA8: {
        "name": "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
        "key_len": 32,
        "sha": "sha256",
        "type": "stream",
        "kct": "ECDHE",
    },
    0xCCA9: {
        "name": "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
        "key_len": 32,
        "sha": "sha256",
        "type": "stream",
        "kct": "ECDHE",
    },
    0x002F: {
        "name": "TLS_RSA_WITH_AES_128_CBC_SHA",
        "key_len": 16,
        "sha": "sha256",
        "hmac-algorithm": "sha1",
        "type": "block",
        "mac_key_len": 20,
        "kct": "RSA",
    },
    0x0035: {
        "name": "TLS_RSA_WITH_AES_256_CBC_SHA",
        "key_len": 32,
        "sha": "sha256",
        "hmac-algorithm": "sha1",
        "type": "block",
        "mac_key_len": 20,
        "kct": "RSA",
    },
    0xC009: {
        "name": "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
        "key_len": 16,
        "sha": "sha256",
        "hmac-algorithm": "sha1",
        "type": "block",
        "mac_key_len": 20,
        "kct": "ECDHE",
    },
    0xC00A: {
        "name": "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
        "key_len": 32,
        "sha": "sha256",
        "hmac-algorithm": "sha1",
        "kct": "ECDHE",
        "type": "block",
        "mac_key_len": 20,
    },
    0xC013: {
        "name": "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
        "key_len": 16,
        "sha": "sha256",
        "hmac-algorithm": "sha1",
        "type": "block",
        "mac_key_len": 20,
        "kct": "ECDHE",
    },
    0xC014: {
        "name": "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
        "key_len": 32,
        "sha": "sha256",
        "hmac-algorithm": "sha1",
        "type": "block",
        "mac_key_len": 20,
        "kct": "ECDHE",
    },
}


class CipherSuites:
    def __init__(self, context=None):
        self.ciphers = context.ciphers or CIPHER_SUITES

    def dump(self):
        temp = b"".join([struct.pack("!H", i) for i in self.ciphers])
        return struct.pack("!H", len(temp)) + temp


from pyhttpx.layers.tls.crypto.ciphers import _tls_cipher_algs


def get_algs_from_ciphersuite_name(ciphersuite_name):
    """ """
    tls1_3 = False
    kx_alg = None
    cipher_alg = None
    hmac_alg = None
    hash_alg = None
    if ciphersuite_name.startswith("TLS"):
        s = ciphersuite_name[4:]

        if "WITH" in s:
            kx_name, s = s.split("_WITH_")
            kx_alg = kx_name

            hash_name = s.split("_")[-1]
            hash_alg = hash_name

            cipher_name = s[: -(len(hash_name) + 1)]
            if tls1_3:
                cipher_name += "_TLS13"

            cipher_alg = _tls_cipher_algs.get(cipher_name)

            hmac_alg = None
            if cipher_alg is not None and cipher_alg.type != "aead":
                hmac_name = "HMAC-%s" % hash_name
                hmac_alg = hmac_name

        else:
            tls1_3 = True
            kx_alg = "TLS13"
            hash_name = s.split("_")[-1]
            hash_alg = hash_name

            cipher_name = s[: -(len(hash_name) + 1)]

            if tls1_3:
                cipher_name += "_TLS13"

            cipher_alg = _tls_cipher_algs.get(cipher_name)

    return kx_alg, cipher_alg, hmac_alg, hash_alg, tls1_3


if __name__ == "__main__":
    for i in list(TLS_SUITES.values())[:4]:
        print(i["name"], get_algs_from_ciphersuite_name(i["name"]))
