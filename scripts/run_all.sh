#!/usr/bin/env bash
# Runs every check in order and prints a one-line verdict per step.
# From sdv_ota_engine:   bash scripts/run_all.sh          (about 1 minute)
#                        bash scripts/run_all.sh --full   (adds the 17-bug mutation check, about 3 more minutes)
set -u
cd "$(dirname "$0")/.."
V="verilator --binary --timing -Wno-fatal -Wno-WIDTH -Wno-UNUSEDSIGNAL -Wno-TIMESCALEMOD -Irtl"
CORE="rtl/ascon_round.v rtl/ascon_aead_core.v"
ENG="$CORE rtl/ota_auth_engine.v"
AXI="$ENG rtl/ota_axil_wrapper.v"
mkdir -p build reports
FAILS=0
step() {   # step "name" "expected text" command...
  local name="$1" want="$2"; shift 2
  local out; out=$("$@" 2>&1); local rc=$?
  echo "$out" > "reports/$(echo "$name" | tr ' /' '__').log"
  if [ $rc -eq 0 ] && echo "$out" | grep -q "$want"; then printf "PASS  %s\n" "$name"
  else printf "FAIL  %s   (see reports/)\n" "$name"; FAILS=$((FAILS+1)); fi
}
build() { "$@" > /dev/null 2>&1 || { echo "build failed: $*"; FAILS=$((FAILS+1)); }; }

[ -f vectors/LWC_AEAD_KAT_128_128.txt ] || { echo "missing vectors/LWC_AEAD_KAT_128_128.txt (see step 2 of the run steps)"; exit 2; }
step "1 golden model vs official vectors" "PASS: 1089 official" python3 model/ascon_ref.py vectors/LWC_AEAD_KAT_128_128.txt
python3 scripts/gen_core_vectors.py > /dev/null && python3 scripts/gen_engine_directed.py > /dev/null && python3 scripts/gen_engine_random.py > /dev/null
build $V $CORE tb/tb_core_kat.sv --top-module tb_core_kat -Mdir build/core -o tb_core_kat
step "2 core known-answer test" "RESULT: PASS" ./build/core/tb_core_kat
build $V $ENG tb/tb_engine.sv --top-module tb_engine -Mdir build/engine -o tb_engine
step "3 engine directed test" "RESULT: PASS" ./build/engine/tb_engine +script=vectors/engine_directed.txt
build $V $AXI tb/tb_axi.sv --top-module tb_axi -Mdir build/axi -o tb_axi
step "4 AXI wrapper test" "RESULT: PASS" ./build/axi/tb_axi +script=vectors/engine_directed.txt
build $V --assert $ENG tb/engine_checks.sv tb/tb_engine.sv --top-module tb_engine -Mdir build/engchk -o tb_engchk
step "5 engine random test + assertions" "0 vacuous, 0 failures" ./build/engchk/tb_engchk +script=vectors/engine_random.txt
step "6 functional coverage 100%" "COVERAGE: 46 of 46" ./build/engchk/tb_engchk +script=vectors/engine_random.txt
build $V --assert $AXI tb/engine_checks.sv tb/tb_axi.sv --top-module tb_axi -Mdir build/axichk -o tb_axichk
step "7 AXI random test + assertions" "RESULT: PASS tb_axi" ./build/axichk/tb_axichk +script=vectors/engine_random.txt
step "8 software baseline and demo (mock)" "RESULT: PASS demo" bash -c "python3 scripts/sw_baseline.py && python3 pynq/demo.py --mock"
if [ "${1:-}" = "--full" ]; then
  step "9 mutation check (17 bugs)" "17 caught, 0 escaped" python3 scripts/mutation_check.py
fi
echo
if [ $FAILS -eq 0 ]; then echo "ALL CHECKS PASSED"; else echo "$FAILS STEP(S) FAILED"; exit 1; fi