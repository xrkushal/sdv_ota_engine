"""Reference model of the resumable firmware-chunk authentication engine.

It implements the rules of rtl/ota_auth_engine.v on top of the Ascon-AEAD128
golden model, and it plays the sender: seal_image() cuts a firmware image into
64-byte chunks and encrypts each one.

Chunk i of image version V:  nonce = i (4 bytes) | V (4 bytes) | 8 zero bytes
                             AD    = total_chunks (4 bytes) | is_last (1 byte) | 3 zero bytes
All numbers are little-endian.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ascon_ref as A

(ACCEPT, COMPLETE, BEGIN_NEW, BEGIN_RESUME, ERR_TAG,
 ERR_INDEX, ERR_ROLLBACK, ERR_NOIMAGE, ERR_COMPLETE, ERR_ARG) = range(10)
NAMES = ["ACCEPT", "COMPLETE", "BEGIN_NEW", "BEGIN_RESUME", "ERR_TAG",
         "ERR_INDEX", "ERR_ROLLBACK", "ERR_NOIMAGE", "ERR_COMPLETE", "ERR_ARG"]


def nonce_of(version, index):
    return index.to_bytes(4, "little") + version.to_bytes(4, "little") + bytes(8)


def ad_of(total, is_last):
    return total.to_bytes(4, "little") + bytes([1 if is_last else 0]) + bytes(3)


def seal_image(key, version, fw, chunk=64):
    """Sender side. Returns a list of (ciphertext, tag), one per chunk."""
    n = max(1, -(-len(fw) // chunk))
    out = []
    for i in range(n):
        part = fw[i * chunk:(i + 1) * chunk]
        r = A.encrypt(key, nonce_of(version, i), ad_of(n, i == n - 1), part)
        out.append((r[:-16], r[-16:]))
    return out


class EngineRef:
    def __init__(self):
        self.power_on()

    def power_on(self):
        """Clears the key and all saved state (the por_n reset)."""
        self.key = bytes(16)
        self.version = self.total = self.next = 0
        self.valid = self.complete = False

    def set_key(self, key):
        self.key = key

    def begin(self, version, total):
        if total == 0:
            return ERR_ARG
        if not self.valid or version > self.version:
            self.version, self.total, self.next = version, total, 0
            self.valid, self.complete = True, False
            return BEGIN_NEW
        if version < self.version:
            return ERR_ROLLBACK
        if total == self.total:
            return BEGIN_RESUME
        return ERR_ARG

    def reaches_core(self, index, length):
        """True when a submit passes every check before the tag is verified."""
        if not self.valid or self.complete or index != self.next:
            return False
        last = index == self.total - 1
        return (1 <= length <= 64) if last else (length == 64)

    def submit(self, index, length, ct, tag):
        """Return (response code, plaintext or None). Only the first `length`
        bytes of ct are used, like the hardware."""
        if not self.valid:
            return ERR_NOIMAGE, None
        if self.complete:
            return ERR_COMPLETE, None
        if index != self.next:
            return ERR_INDEX, None
        if not self.reaches_core(index, length):
            return ERR_ARG, None
        last = index == self.total - 1
        ct = ct.ljust(64, b"\0")            # the data bus is 64 bytes wide, missing bytes are zero
        pt = A.decrypt(self.key, nonce_of(self.version, index), ad_of(self.total, last),
                       ct[:length] + tag)
        if pt is None:
            return ERR_TAG, None
        self.next += 1
        if last:
            self.complete = True
            return COMPLETE, pt
        return ACCEPT, pt