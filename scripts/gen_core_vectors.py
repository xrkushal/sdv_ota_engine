"""Write the core test-vector files used by tb/tb_core_kat.sv.

core_kat.txt : all official Ascon-AEAD128 known-answer vectors
core_ext.txt : every (ad_len 0..32) x (pt_len 0..64) pair with random data,
               expected values from the Python golden model
Line format (hex): ad_len pt_len key nonce ad[256b] pt[512b] ct[512b] tag[128b]
Vectors are little-endian integers: byte i sits in bits [8*i +: 8].
"""
import os
import random
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "model"))
import ascon_ref as A

ROOT = os.path.join(os.path.dirname(__file__), "..", "vectors")


def line(key, nonce, ad, pt):
    out = A.encrypt(key, nonce, ad, pt)
    ct, tag = out[:-16], out[-16:]
    le = lambda b, n: "%0*x" % (n // 4, int.from_bytes(b, "little"))
    return "%02x %02x %s %s %s %s %s %s\n" % (
        len(ad), len(pt), le(key, 128), le(nonce, 128), le(ad, 256), le(pt, 512), le(ct, 512), le(tag, 128))


def main():
    recs = A.read_kat(os.path.join(ROOT, "LWC_AEAD_KAT_128_128.txt"))
    with open(os.path.join(ROOT, "core_kat.txt"), "w") as f:
        for r in recs:
            f.write(line(r["Key"], r["Nonce"], r["AD"], r["PT"]))
    rnd = random.Random(2026)
    n = 0
    with open(os.path.join(ROOT, "core_ext.txt"), "w") as f:
        for adl in range(33):
            for ptl in range(65):
                f.write(line(rnd.randbytes(16), rnd.randbytes(16), rnd.randbytes(adl), rnd.randbytes(ptl)))
                n += 1
    print("core_kat.txt: %d vectors, core_ext.txt: %d vectors" % (len(recs), n))


if __name__ == "__main__":
    main()