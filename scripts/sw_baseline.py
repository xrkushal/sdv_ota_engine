"""Software baseline: time the pure-Python Ascon-AEAD128 verify of one 64-byte chunk and compare it
with the hardware cycle count.  Run from sdv_ota_engine:  python3 scripts/sw_baseline.py [clock_MHz]
The Python time is for this machine (a cloud sandbox); the ARM core on the PYNQ-Z2 is slower, so
run this script on the board too and quote that number.  The hardware time is cycles / clock.
"""
import os, sys, time
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "model"))
import engine_ref as E
import ascon_ref as A

MHZ = float(sys.argv[1]) if len(sys.argv) > 1 else 100.0
HW_CYCLES = 71           # measured in tb_core_kat: 8-byte header + 64-byte chunk
key = bytes(range(16))
fw = bytes(range(256)) * 4
chunks = E.seal_image(key, 7, fw)
n = len(chunks)
t0 = time.perf_counter()
reps = 20
for _ in range(reps):
    for i, (ct, tag) in enumerate(chunks):
        pt = A.decrypt(key, E.nonce_of(7, i), E.ad_of(n, i == n - 1), ct + tag)
        assert pt is not None
dt = (time.perf_counter() - t0) / (reps * n)
hw = HW_CYCLES / (MHZ * 1e6)
print("software (Python, this machine): %.1f us per 64-byte chunk  (%.0f KB/s)" % (dt * 1e6, 64 / dt / 1024))
print("hardware core at %.0f MHz:        %.2f us per 64-byte chunk  (%.0f MB/s)" % (MHZ, hw * 1e6, 64 / hw / 1e6))
print("speed-up: %.0fx   (a 1 MB image: software %.1f s, hardware %.3f s)" % (dt / hw, dt * 16384, hw * 16384))