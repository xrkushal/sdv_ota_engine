"""Mutation check: inject one bug at a time into rtl/ota_auth_engine.v and confirm the
verification catches it.  Run from sdv_ota_engine:   python3 scripts/mutation_check.py
For each bug it builds tb_engine + engine_checks.sv (assertions) and runs the directed and the
random script.  CAUGHT = the testbench reported FAIL or an assertion failed.  A build error
counts as INVALID (the mutation itself was wrong), never as caught.  Exit code 1 if any bug escapes.
"""
import os, shutil, subprocess, sys

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
os.chdir(ROOT)
SRC = open("rtl/ota_auth_engine.v").read()
MUTANTS = [
    ("tag check skipped",            "if (core_tag_ok) begin", "if (1'b1) begin"),
    ("same version restarts image",  "(begin_version > version_r)", "(begin_version >= version_r)"),
    ("index check removed",          "else if (chunk_index != next_r)    respond(ERR_INDEX);", "else if (1'b0)    respond(ERR_INDEX);"),
    ("next index never advances",    "next_r      <= next_r + 32'd1;", "next_r      <= next_r;"),
    ("soft reset clears progress",   "end else if (!rst_n) begin\n            st          <= E_IDLE;", "end else if (!rst_n) begin\n            next_r <= 32'd0;\n            st          <= E_IDLE;"),
    ("plaintext released on bad tag","respond(ERR_TAG);", "begin plain_valid <= 1'b1; respond(ERR_TAG); end"),
    ("last-chunk flag not in AD",    "31'd0, is_last, total_r", "31'd0, 1'b0, total_r"),
    ("version not in nonce",         "{64'd0, version_r, chunk_index}", "{64'd0, 32'd0, chunk_index}"),
    ("short middle chunk accepted",  "(chunk_len == 7'd64);", "(chunk_len != 7'd0);"),
    ("image never marked complete",  "complete_r <= 1'b1;", "complete_r <= 1'b0;"),
    ("power reset keeps key",        "key_r       <= 128'd0;", "key_r       <= key_r;"),
    ("wrong header length",          ".ad_len(6'd8)", ".ad_len(6'd4)"),
    ("key load allowed while busy",  "if (key_we && !busy)", "if (key_we)"),
    ("resume with other size accepted","end else if (begin_total == total_r) begin", "end else if (1'b1) begin"),
    ("zero-chunk image accepted",    "if (begin_total == 32'd0) begin", "if (1'b0) begin"),
    ("power reset keeps image",      "valid_r     <= 1'b0;", "valid_r     <= valid_r;"),
    ("rollback not rejected",        "end else if (begin_version < version_r) begin\n                            respond(ERR_ROLLBACK);", "end else if (1'b0) begin\n                            respond(ERR_ROLLBACK);"),
]
FLAGS = "--binary --timing --assert -Wno-fatal -Wno-WIDTH -Wno-UNUSEDSIGNAL -Wno-TIMESCALEMOD".split()
shutil.rmtree("build/mut", ignore_errors=True)
os.makedirs("build/mut")
escaped = 0
print("%-3s %-34s %s" % ("#", "injected bug", "result"))
for i, (name, old, new) in enumerate(MUTANTS, 1):
    if SRC.count(old) != 1:
        print("%-3d %-34s INVALID (pattern found %d times)" % (i, name, SRC.count(old))); escaped += 1; continue
    d = "build/mut/m%d" % i
    os.makedirs(d)
    open(d + "/ota_auth_engine.v", "w").write(SRC.replace(old, new))
    cmd = ["verilator"] + FLAGS + ["-Irtl", "rtl/ascon_round.v", "rtl/ascon_aead_core.v", d + "/ota_auth_engine.v",
           "tb/engine_checks.sv", "tb/tb_engine.sv", "--top-module", "tb_engine", "-Mdir", d + "/obj", "-o", "sim"]
    b = subprocess.run(cmd, capture_output=True, text=True)
    if b.returncode != 0:
        print("%-3d %-34s INVALID (build error)" % (i, name)); escaped += 1; continue
    by = []
    for script in ("vectors/engine_directed.txt", "vectors/engine_random.txt"):
        try:
            r = subprocess.run([d + "/obj/sim", "+script=" + script], capture_output=True, text=True, timeout=120)
            out = r.stdout
        except subprocess.TimeoutExpired:
            out = "RESULT: FAIL timeout"
        if "RESULT: PASS" not in out: by.append("testbench")
        if "SVA FAIL" in out or "Assertion failed" in out or "%Error" in out + r.stderr: by.append("assertion")
    by = sorted(set(by))
    if by: print("%-3d %-34s CAUGHT by %s" % (i, name, " + ".join(by)))
    else:  print("%-3d %-34s ESCAPED" % (i, name)); escaped += 1
print("\n%d bugs injected, %d caught, %d escaped" % (len(MUTANTS), len(MUTANTS) - escaped, escaped))
sys.exit(1 if escaped else 0)