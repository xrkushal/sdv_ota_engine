"""Write vectors/engine_random.txt: a constrained-random script for tb/tb_engine.sv and tb/tb_axi.sv.

Same line format as gen_engine_directed.py (it reuses its Script class).  A fixed seed makes
the run repeatable; pass another seed to explore:   python3 scripts/gen_engine_random.py [ops] [seed]
The generator plays a sender with several images; at every step it chooses at random between the
good next chunk and a fault (flipped ciphertext or tag bit, zero tag, wrong length, replayed or
skipped index, index beyond the image), a begin with a new / same / older / wrong-size version,
a soft reset, a power-on reset, a wrong key, an interrupted submit, or a submit with other
commands pulsed while busy.  Expected results come from model/engine_ref.py.
"""
import copy
import os
import random
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "..", "model"))
import engine_ref as E
from gen_engine_directed import Script

OUT = os.path.join(HERE, "..", "vectors", "engine_random.txt")


def flip(b, bit):
    v = bytearray(b)
    v[(bit // 8) % len(v)] ^= 1 << (bit % 8)
    return bytes(v)


def build(nops, seed):
    rnd = random.Random(seed)
    s = Script(rnd)
    true_key = rnd.randbytes(16)
    s.key(true_key)
    images = {}                     # (version, total) -> list of (ct, tag, length)
    cur = None                      # image the sender is sending
    counts = {}
    ops = 0

    def note(name):
        counts[name] = counts.get(name, 0) + 1

    def image(version, total):
        if (version, total) not in images:
            fw = rnd.randbytes((total - 1) * 64 + rnd.randint(1, 64))
            ch = E.seal_image(true_key, version, fw)
            images[(version, total)] = [(c, t, len(fw[i * 64:(i + 1) * 64])) for i, (c, t) in enumerate(ch)]
        return images[(version, total)]

    def do_begin():
        ref = s.ref
        c = rnd.random()
        if not ref.valid or c < 0.35:
            ver = ref.version + rnd.choice([1, 1, 2, 7]) if ref.valid else rnd.randint(1, 50)
            tot = rnd.choice([1, 1, 1, 2, 2, 3, 4, 5, 6, 8, 9, 12])
        elif c < 0.65:
            ver, tot = ref.version, ref.total
        elif c < 0.80:
            ver, tot = max(0, ref.version - rnd.randint(1, 3)), rnd.randint(1, 6)
        elif c < 0.90:
            ver, tot = ref.version, ref.total + rnd.randint(1, 3)
        else:
            ver, tot = rnd.randint(0, 80), rnd.choice([0, 1, 3, 4])
        code = copy.deepcopy(ref).begin(ver, tot)
        s.begin(ver, tot, code)
        note("begin " + E.NAMES[code])
        return (ver, tot) if code in (E.BEGIN_NEW, E.BEGIN_RESUME) else None

    def do_submit():
        ref = s.ref
        if cur is None:
            return
        ch = image(*cur)
        total = cur[1]
        c = rnd.random()
        if c < 0.70:
            idx = ref.next
        elif c < 0.80:
            idx = max(0, ref.next - rnd.randint(1, 3))                       # replay
        elif c < 0.90:
            idx = ref.next + rnd.randint(1, 3)                               # skip ahead
        else:
            idx = rnd.randint(0, total + 2)
        if idx < total:
            ct, tag, length = ch[idx]
        else:
            ct, tag, length = rnd.randbytes(64), rnd.randbytes(16), 64
        fault = rnd.random()
        garbage = False
        if fault < 0.60:
            kind = "good"
        elif fault < 0.70:
            ct = flip(ct[:length], rnd.randrange(8 * length)); kind = "flip-ct"
        elif fault < 0.80:
            tag = flip(tag, rnd.randrange(128)); kind = "flip-tag"
        elif fault < 0.85:
            tag = bytes(16); kind = "zero-tag"
        elif fault < 0.92:
            length = rnd.choice([0, 1, 7, 16, 33, 63, 64, 65, 100, 127]); kind = "bad-len"
        else:
            garbage = True; kind = "garbage-tail"
        ct = ct.ljust(64, b"\0")
        code, _ = copy.deepcopy(ref).submit(idx, length, ct, tag)
        mode = rnd.random()
        if ref.reaches_core(idx, length) and mode < 0.15:
            s.submit(idx, length, ct, tag, code, garbage, op=7); note("submit+disturb")
        elif ref.reaches_core(idx, length) and mode < 0.30:
            s.interrupt(idx, length, ct, tag, rnd.randrange(0, 25)); note("interrupt")
        else:
            s.submit(idx, length, ct, tag, code, garbage); note("submit " + E.NAMES[code])

    while ops < nops:
        r = rnd.random()
        n0 = len(s.lines)
        if r < 0.08 or cur is None or ((s.ref.complete or not s.ref.valid) and rnd.random() < 0.9):
            got = do_begin()
            if got:
                cur = got
        elif r < 0.12:
            s.reset(); note("soft reset")
        elif r < 0.13:
            s.power(); s.key(true_key); note("power-on reset")
        elif r < 0.14:
            s.key(rnd.randbytes(16)); note("wrong key loaded")
            do_submit()
            s.key(true_key)
        else:
            do_submit()
        ops += sum(1 for ln in s.lines[n0:] if not ln.startswith("6 "))
    return s, counts


if __name__ == "__main__":
    nops = int(sys.argv[1]) if len(sys.argv) > 1 else 6000
    seed = int(sys.argv[2]) if len(sys.argv) > 2 else 20261030
    s, counts = build(nops, seed)
    with open(OUT, "w") as f:
        f.write("\n".join(s.lines) + "\n")
    n_ops = sum(1 for ln in s.lines if not ln.startswith("6 "))
    print("wrote %s: %d lines, %d operations (seed %d)" % (os.path.relpath(OUT), len(s.lines), n_ops, seed))
    for k in sorted(counts):
        print("  %-22s %d" % (k, counts[k]))