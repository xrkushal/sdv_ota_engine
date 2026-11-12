"""Golden model of Ascon-AEAD128 (NIST SP 800-232).

Written from the specification and checked against the official known-answer
tests of the ascon-c repository (1089 vectors).  The 128-bit rate block is held
as one integer: x0 is the low 64 bits and x1 the high 64 bits, which matches
the little-endian byte order of the standard.

Run:  python3 model/ascon_ref.py vectors/LWC_AEAD_KAT_128_128.txt
"""
import sys

M64 = (1 << 64) - 1
IV = 0x00001000808C0001                      # Ascon-AEAD128 initial value
RC = [0xF0, 0xE1, 0xD2, 0xC3, 0xB4, 0xA5, 0x96, 0x87, 0x78, 0x69, 0x5A, 0x4B]
DSEP = 1 << 63                               # domain separation bit in x4


def _ror(x, n):
    return ((x >> n) | (x << (64 - n))) & M64


def _round(s, c):
    x0, x1, x2, x3, x4 = s
    x2 ^= c
    x0 ^= x4
    x4 ^= x3
    x2 ^= x1
    t0 = x0 ^ (~x1 & M64 & x2)
    t1 = x1 ^ (~x2 & M64 & x3)
    t2 = x2 ^ (~x3 & M64 & x4)
    t3 = x3 ^ (~x4 & M64 & x0)
    t4 = x4 ^ (~x0 & M64 & x1)
    t1 ^= t0
    t0 ^= t4
    t3 ^= t2
    t2 = ~t2 & M64
    return [t0 ^ _ror(t0, 19) ^ _ror(t0, 28),
            t1 ^ _ror(t1, 61) ^ _ror(t1, 39),
            t2 ^ _ror(t2, 1) ^ _ror(t2, 6),
            t3 ^ _ror(t3, 10) ^ _ror(t3, 17),
            t4 ^ _ror(t4, 7) ^ _ror(t4, 41)]


def permute(s, rounds):
    """p12 uses all 12 constants, p8 the last 8."""
    for c in RC[12 - rounds:]:
        s = _round(s, c)
    return s


def _le(b):
    return int.from_bytes(b, "little")


def _xor_rate(s, v):
    s[0] ^= v & M64
    s[1] ^= v >> 64


def _rate(s):
    return s[0] | (s[1] << 64)


def _init(key, nonce):
    k0, k1 = _le(key[:8]), _le(key[8:])
    s = permute([IV, k0, k1, _le(nonce[:8]), _le(nonce[8:])], 12)
    s[3] ^= k0
    s[4] ^= k1
    return s, k0, k1


def _absorb_ad(s, ad):
    if ad:
        i = 0
        while len(ad) - i >= 16:
            _xor_rate(s, _le(ad[i:i + 16]))
            s = permute(s, 8)
            i += 16
        last = ad[i:]
        _xor_rate(s, _le(last) | (1 << (8 * len(last))))
        s = permute(s, 8)
    s[4] ^= DSEP
    return s


def _finalise(s, k0, k1):
    s[2] ^= k0
    s[3] ^= k1
    s = permute(s, 12)
    s[3] ^= k0
    s[4] ^= k1
    return s[3].to_bytes(8, "little") + s[4].to_bytes(8, "little")


def encrypt(key, nonce, ad, pt):
    """Return ciphertext || 16-byte tag."""
    s, k0, k1 = _init(key, nonce)
    s = _absorb_ad(s, ad)
    ct, i = b"", 0
    while len(pt) - i >= 16:
        _xor_rate(s, _le(pt[i:i + 16]))
        ct += _rate(s).to_bytes(16, "little")
        s = permute(s, 8)
        i += 16
    last = pt[i:]
    _xor_rate(s, _le(last))
    ct += _rate(s).to_bytes(16, "little")[:len(last)]
    _xor_rate(s, 1 << (8 * len(last)))
    return ct + _finalise(s, k0, k1)


def decrypt_raw(key, nonce, ad, ct):
    """Return (plaintext candidate, computed tag); the caller compares tags."""
    s, k0, k1 = _init(key, nonce)
    s = _absorb_ad(s, ad)
    pt, i = b"", 0
    while len(ct) - i >= 16:
        c = _le(ct[i:i + 16])
        pt += (_rate(s) ^ c).to_bytes(16, "little")
        s[0], s[1] = c & M64, c >> 64
        s = permute(s, 8)
        i += 16
    last = ct[i:]
    n = len(last)
    mask = (1 << (8 * n)) - 1
    c = _le(last)
    r = _rate(s)
    pt += ((r ^ c) & mask).to_bytes(16, "little")[:n]
    r = ((r & ~mask) | c) ^ (1 << (8 * n))
    s[0], s[1] = r & M64, r >> 64
    return pt, _finalise(s, k0, k1)


def decrypt(key, nonce, ad, ct_tag):
    """Return plaintext, or None when the tag is wrong (nothing is released)."""
    ct, tag = ct_tag[:-16], ct_tag[-16:]
    pt, calc = decrypt_raw(key, nonce, ad, ct)
    return pt if calc == tag else None


def read_kat(path):
    recs, cur = [], {}
    for line in open(path):
        line = line.strip()
        if not line:
            if cur:
                recs.append(cur)
                cur = {}
            continue
        name, _, val = line.partition("=")
        cur[name.strip()] = bytes.fromhex(val.strip()) if name.strip() != "Count" else int(val)
    if cur:
        recs.append(cur)
    return recs


def check_kat(path):
    recs = read_kat(path)
    for r in recs:
        out = encrypt(r["Key"], r["Nonce"], r["AD"], r["PT"])
        assert out == r["CT"], "encrypt mismatch at Count=%d" % r["Count"]
        assert decrypt(r["Key"], r["Nonce"], r["AD"], r["CT"]) == r["PT"], \
            "decrypt mismatch at Count=%d" % r["Count"]
        bad = bytearray(r["CT"])
        bad[0] ^= 1
        assert decrypt(r["Key"], r["Nonce"], r["AD"], bytes(bad)) is None, \
            "tamper not caught at Count=%d" % r["Count"]
    return len(recs)


if __name__ == "__main__":
    n = check_kat(sys.argv[1])
    print("PASS: %d official Ascon-AEAD128 known-answer vectors (encrypt, decrypt, tamper)" % n)