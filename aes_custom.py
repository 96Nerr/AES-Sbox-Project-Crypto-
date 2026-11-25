"""AES-128 dengan S-box custom (vektorisasi numpy). Mode: CBC (PKCS7) dan CTR."""
import numpy as np
from sbox_core import gmul

_T = {m: np.array([gmul(x, m) for x in range(256)], dtype=np.uint8) for m in (2, 3, 9, 11, 13, 14)}
SR = np.array([4 * ((c + r) % 4) + r for c in range(4) for r in range(4)])
ISR = np.argsort(SR)


class CustomAES:
    def __init__(self, key: bytes, sbox):
        assert len(key) == 16
        self.sb = np.array(sbox, dtype=np.uint8)
        self.isb = np.argsort(sbox).astype(np.uint8)       # inverse S-box
        w, rcon = [list(key[4 * i:4 * i + 4]) for i in range(4)], 1
        for i in range(4, 44):
            t = w[i - 1][:]
            if i % 4 == 0:
                t = t[1:] + t[:1]
                t = [int(self.sb[b]) for b in t]
                t[0] ^= rcon
                rcon = gmul(rcon, 2)
            w.append([w[i - 4][k] ^ t[k] for k in range(4)])
        self.rk = np.array(w, dtype=np.uint8).reshape(11, 16)

    @staticmethod
    def _mix(s, inv=False):
        a = s.reshape(-1, 4, 4)
        a0, a1, a2, a3 = (a[:, :, i] for i in range(4))
        T = _T
        if not inv:
            r = [T[2][a0] ^ T[3][a1] ^ a2 ^ a3, a0 ^ T[2][a1] ^ T[3][a2] ^ a3,
                 a0 ^ a1 ^ T[2][a2] ^ T[3][a3], T[3][a0] ^ a1 ^ a2 ^ T[2][a3]]
        else:
            r = [T[14][a0] ^ T[11][a1] ^ T[13][a2] ^ T[9][a3], T[9][a0] ^ T[14][a1] ^ T[11][a2] ^ T[13][a3],
                 T[13][a0] ^ T[9][a1] ^ T[14][a2] ^ T[11][a3], T[11][a0] ^ T[13][a1] ^ T[9][a2] ^ T[14][a3]]
        return np.stack(r, axis=2).reshape(-1, 16)

    def enc(self, blocks):                       # blocks: (N,16) uint8
        s = blocks ^ self.rk[0]
        for r in range(1, 10):
            s = self._mix(self.sb[s][:, SR]) ^ self.rk[r]
        return self.sb[s][:, SR] ^ self.rk[10]

    def dec(self, blocks):
        s = blocks ^ self.rk[10]
        for r in range(9, 0, -1):
            s = self._mix(self.isb[s[:, ISR]] ^ self.rk[r], inv=True)
        return self.isb[s[:, ISR]] ^ self.rk[0]


def _pad(b):
    n = 16 - len(b) % 16
    return b + bytes([n]) * n


def cbc_encrypt(aes, data: bytes, iv: bytes) -> bytes:
    p = np.frombuffer(_pad(data), np.uint8).reshape(-1, 16)
    out, prev = np.empty_like(p), np.frombuffer(iv, np.uint8)
    for i in range(len(p)):
        prev = aes.enc((p[i] ^ prev)[None])[0]
        out[i] = prev
    return out.tobytes()


def cbc_decrypt(aes, data: bytes, iv: bytes) -> bytes:
    c = np.frombuffer(data, np.uint8).reshape(-1, 16)
    prevs = np.vstack([np.frombuffer(iv, np.uint8), c[:-1]])
    p = (aes.dec(c) ^ prevs).tobytes()
    return p[:-p[-1]]


def ctr_crypt(aes, data: bytes, nonce: bytes) -> bytes:
    """Enkripsi = dekripsi. nonce 8 byte + counter 8 byte (big-endian)."""
    n = -(-len(data) // 16)
    ctr = np.zeros((n, 16), np.uint8)
    ctr[:, :8] = np.frombuffer(nonce[:8], np.uint8)
    ctr[:, 8:] = np.arange(n, dtype=">u8").view(np.uint8).reshape(n, 8)
    ks = aes.enc(ctr).ravel()[:len(data)]
    return (np.frombuffer(data, np.uint8) ^ ks).tobytes()


def encrypt(aes, data, mode, iv):
    return cbc_encrypt(aes, data, iv) if mode == "CBC" else ctr_crypt(aes, data, iv)


def decrypt(aes, data, mode, iv):
    return cbc_decrypt(aes, data, iv) if mode == "CBC" else ctr_crypt(aes, data, iv)
