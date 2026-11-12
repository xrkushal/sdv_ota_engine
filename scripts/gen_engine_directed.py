"""Write vectors/engine_directed.txt, the directed test script for tb/tb_engine.sv.

Every line is eight hex fields:  op a b c data tag exp_code exp_plain
  0 K  a=key                                  load the key
  1 B  b=version c=total                      begin / resume an image
  2 S  b=index c=length data tag              submit one chunk
  3 R                                         soft reset (saved state is kept)
  4 P                                         power-on reset (state and key cleared)
  5 I  a=cycles b=index c=length data tag     submit, then soft-reset after `a` cycles
  6 Q  a=version b=next c=total exp_code=flags (bit0 valid, bit1 complete)   check state
  7 D  like S, but begin, key load and submit are also pulsed while busy (must be ignored)
exp_code is the expected response code and exp_plain the expected plaintext.
A Q line is written after every other line, so the saved state is checked at every step.
Expected values come from model/engine_ref.py.  Some expectations are also
asserted here by hand so a wrong model cannot hide a wrong rule.
"""
import os
import random
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "model"))
import engine_ref as E

OUT = os.path.join(HERE, "..", "vectors", "engine_directed.txt")


class Script:
    def __init__(self, rnd):
        self.ref, self.lines, self.rnd = E.EngineRef(), [], rnd

    def _w(self, op, a=0, b=0, c=0, data=b"", tag=b"", code=0, plain=b""):
        h = lambda x: "%x" % (x if isinstance(x, int) else int.from_bytes(x, "little"))
        self.lines.append(" ".join(h(v) for v in (op, a, b, c, data, tag, code, plain)))

    def q(self):
        r = self.ref
        self._w(6, a=r.version, b=r.next, c=r.total, code=int(r.valid) | (int(r.complete) << 1))

    def key(self, k):
        self.ref.set_key(k)
        self._w(0, a=k)
        self.q()

    def begin(self, version, total, expect):
        code = self.ref.begin(version, total)
        assert code == expect, (version, total, E.NAMES[code], E.NAMES[expect])
        self._w(1, b=version, c=total, code=code)
        self.q()

    def _data(self, ct, length, garbage):
        ct = ct[:64]
        if garbage:
            ct = ct[:length] + self.rnd.randbytes(64 - len(ct[:length]))
        return ct

    def submit(self, index, length, ct, tag, expect, garbage=False, op=2):
        if op == 7:
            assert self.ref.reaches_core(index, length)
        code, pt = self.ref.submit(index, length, ct, tag)
        assert code == expect, (index, length, E.NAMES[code], E.NAMES[expect])
        self._w(op, b=index, c=length, data=self._data(ct, length, garbage), tag=tag,
                code=code, plain=pt or b"")
        self.q()

    def interrupt(self, index, length, ct, tag, cycles):
        assert self.ref.reaches_core(index, length) and cycles < 25
        self._w(5, a=cycles, b=index, c=length, data=self._data(ct, length, False), tag=tag)
        self.q()

    def reset(self):
        self._w(3)
        self.q()

    def power(self):
        self.ref.power_on()
        self._w(4)
        self.q()


def lens(chunks, fw):
    n = len(chunks)
    return [64] * (n - 1) + [len(fw) - 64 * (n - 1)]


def flip(b, bit):
    out = bytearray(b)
    out[bit // 8] ^= 1 << (bit % 8)
    return bytes(out)


def send(s, chunks, fw, lo, hi, garbage_last=True):
    """Send chunks lo..hi-1 in order; ACCEPT, except COMPLETE on the last one."""
    ls, n = lens(chunks, fw), len(chunks)
    for i in range(lo, hi):
        ct, tag = chunks[i]
        s.submit(i, ls[i], ct, tag, E.COMPLETE if i == n - 1 else E.ACCEPT,
                 garbage=garbage_last and i == n - 1)


def build():
    rnd = random.Random(7)
    s = Script(rnd)
    key = rnd.randbytes(16)
    fw = rnd.randbytes(5 * 64 + 20)                   # 6 chunks, the last one 20 bytes
    N = 6

    # 0. nothing started yet
    s.q()
    s.key(key)
    c1 = E.seal_image(key, 1, fw)
    s.submit(0, 64, c1[0][0], c1[0][1], E.ERR_NOIMAGE)
    s.begin(1, 0, E.ERR_ARG)

    # 1. a whole image, then the "already complete" cases
    s.begin(1, N, E.BEGIN_NEW)
    send(s, c1, fw, 0, N)
    s.submit(0, 64, c1[0][0], c1[0][1], E.ERR_COMPLETE)
    s.begin(1, N, E.BEGIN_RESUME)
    s.begin(1, N + 1, E.ERR_ARG)

    # 2. interrupt at every chunk boundary, then resume (soft reset keeps the state)
    for b in range(N + 1):
        v = 10 + b
        ch = E.seal_image(key, v, fw)
        s.begin(v, N, E.BEGIN_NEW)
        send(s, ch, fw, 0, b)
        s.reset()
        s.begin(v, N, E.BEGIN_RESUME)
        send(s, ch, fw, b, N)

    # 3. interrupt in the middle of a chunk: the chunk does not count, the next try works
    ch = E.seal_image(key, 30, fw)
    ls = lens(ch, fw)
    s.begin(30, N, E.BEGIN_NEW)
    s.interrupt(0, 64, ch[0][0], ch[0][1], 1)
    send(s, ch, fw, 0, 2)
    for cyc in (5, 12, 19):
        s.interrupt(2, 64, ch[2][0], ch[2][1], cyc)
        s.reset()
    send(s, ch, fw, 2, 5)
    s.interrupt(5, ls[5], ch[5][0], ch[5][1], 9)
    send(s, ch, fw, 5, 6)

    # 4. tampering: one flipped ciphertext bit, one flipped tag bit, then the good chunk
    ch = E.seal_image(key, 40, fw)
    ls = lens(ch, fw)
    s.begin(40, N, E.BEGIN_NEW)
    for i in range(N):
        ct, tag = ch[i]
        s.submit(i, ls[i], flip(ct, rnd.randrange(8 * ls[i])), tag, E.ERR_TAG)
        s.submit(i, ls[i], ct, flip(tag, rnd.randrange(128)), E.ERR_TAG)
        s.submit(i, ls[i], ct, bytes(16), E.ERR_TAG)
        send(s, ch, fw, i, i + 1)

    # 5. replay, reorder and replay across versions
    ch = E.seal_image(key, 50, fw)
    ls = lens(ch, fw)
    s.begin(50, N, E.BEGIN_NEW)
    send(s, ch, fw, 0, 1)
    s.submit(0, 64, ch[0][0], ch[0][1], E.ERR_INDEX)          # replay
    s.submit(2, 64, ch[2][0], ch[2][1], E.ERR_INDEX)          # skip ahead
    send(s, ch, fw, 1, 2)
    s.submit(0, 64, ch[0][0], ch[0][1], E.ERR_INDEX)
    s.submit(1, 64, ch[1][0], ch[1][1], E.ERR_INDEX)
    send(s, ch, fw, 2, N)
    s.begin(51, N, E.BEGIN_NEW)                               # new version, old chunks
    s.submit(0, 64, ch[0][0], ch[0][1], E.ERR_TAG)
    send(s, E.seal_image(key, 51, fw), fw, 0, N)

    # 6. anti-rollback, begin rules and truncation
    ch = E.seal_image(key, 70, fw)
    s.begin(70, N, E.BEGIN_NEW)
    send(s, ch, fw, 0, 2)
    s.begin(69, N, E.ERR_ROLLBACK)
    s.begin(70, N, E.BEGIN_RESUME)
    s.begin(70, N - 1, E.ERR_ARG)
    s.begin(71, 3, E.BEGIN_NEW)                               # newer version restarts
    fw4 = fw[:3 * 64 + 10]                                    # sender really has 4 chunks
    c4 = E.seal_image(key, 72, fw4)
    s.begin(72, 3, E.BEGIN_NEW)                               # engine told 3 chunks
    s.submit(0, 64, c4[0][0], c4[0][1], E.ERR_TAG)            # total is in the AD: caught
    s.begin(73, 4, E.BEGIN_NEW)
    send(s, E.seal_image(key, 73, fw4), fw4, 0, 4)

    # 7. bad lengths
    ch = E.seal_image(key, 80, fw)
    ls = lens(ch, fw)
    s.begin(80, N, E.BEGIN_NEW)
    s.submit(0, 0, ch[0][0], ch[0][1], E.ERR_ARG)
    s.submit(0, 63, ch[0][0], ch[0][1], E.ERR_ARG)
    s.submit(0, 65, ch[0][0], ch[0][1], E.ERR_ARG)
    send(s, ch, fw, 0, N - 1)
    s.submit(N - 1, 0, ch[N - 1][0], ch[N - 1][1], E.ERR_ARG)
    s.submit(N - 1, 21, ch[N - 1][0], ch[N - 1][1], E.ERR_TAG)
    s.submit(N - 1, 64, ch[N - 1][0], ch[N - 1][1], E.ERR_TAG)
    send(s, ch, fw, N - 1, N)

    # 8. commands pulsed while the engine is busy must be ignored
    ch = E.seal_image(key, 90, fw)
    ls = lens(ch, fw)
    s.begin(90, N, E.BEGIN_NEW)
    s.submit(0, 64, ch[0][0], ch[0][1], E.ACCEPT, op=7)
    s.submit(1, 64, ch[1][0], flip(ch[1][1], 3), E.ERR_TAG, op=7)
    s.submit(1, 64, ch[1][0], ch[1][1], E.ACCEPT, op=7)
    send(s, ch, fw, 2, N)

    # 9. power-on reset clears the state and the key
    ch = E.seal_image(key, 5, fw)
    s.power()
    s.submit(0, 64, ch[0][0], ch[0][1], E.ERR_NOIMAGE)
    s.begin(5, N, E.BEGIN_NEW)                                # nothing saved, any version
    s.submit(0, 64, ch[0][0], ch[0][1], E.ERR_TAG)            # key is zero again
    s.key(key)
    send(s, ch, fw, 0, N)
    return s.lines


if __name__ == "__main__":
    lines = build()
    with open(OUT, "w") as f:
        f.write("\n".join(lines) + "\n")
    print("engine_directed.txt: %d lines (%d operations)" % (len(lines), sum(1 for l in lines if l[0] != "6")))