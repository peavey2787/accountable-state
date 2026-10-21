#!/usr/bin/env bash
# Runs the TLC model checker over spec/Accountability.tla.
#   ./scripts/model-check.sh              positive configs (all invariants/properties must hold)
#   ./scripts/model-check.sh --negative   negative configs (TLC MUST find a violation)
# Needs Java 11+. If `java` is missing, a JRE (PyPI jdk4py wheel, Temurin) and tla2tools.jar
# v1.7.4 (GitHub release) are downloaded once into .tla-tools/ (git/zip-excluded).
set -euo pipefail
cd "$(dirname "$0")/.."
TOOLS="$PWD/.tla-tools"; mkdir -p "$TOOLS"
JAR="$TOOLS/tla2tools.jar"
if [ ! -s "$JAR" ]; then
  python3 - "$JAR" <<'PY'
import sys, urllib.request
urllib.request.urlretrieve("https://github.com/tlaplus/tlaplus/releases/download/v1.7.4/tla2tools.jar", sys.argv[1])
PY
fi
if command -v java >/dev/null; then JAVA=java; else
  JAVA="$TOOLS/jre/jdk4py/java-runtime/bin/java"
  if [ ! -x "$JAVA" ]; then
    python3 - "$TOOLS" <<'PY'
import sys, json, urllib.request, zipfile
t = sys.argv[1]
d = json.load(urllib.request.urlopen("https://pypi.org/pypi/jdk4py/json"))
u = [f for f in d["urls"] if "manylinux_2_17_x86_64" in f["filename"]][0]
urllib.request.urlretrieve(u["url"], t + "/jdk.whl")
zipfile.ZipFile(t + "/jdk.whl").extractall(t + "/jre")
PY
    chmod +x "$JAVA"
  fi
fi
run() { # cfg
  local out="$TOOLS/$1.out"
  ( cd spec && nice -n 19 timeout "${TLC_TIMEOUT:-600}" "$JAVA" -Xmx3g -XX:+UseSerialGC -cp "$JAR" tlc2.TLC -workers "${TLC_WORKERS:-2}" -metadir "$TOOLS/states-$1" -config "$1.cfg" Accountability.tla ) > "$out" 2>&1 || true
  echo "== $1: $(grep -E 'Model checking completed|Error:|Invariant .* is violated|Temporal properties were violated|Timeout|exceeded' "$out" | head -2 | tr '\n' ' ')"
  grep -E "states generated|distinct states found" "$out" | tail -1
}
if [ "${1:-}" = --negative ]; then
  for c in neg_nopin neg_nowal; do
    run "$c"
    grep -qE "is violated|Error: " "$TOOLS/$c.out" && grep -q "Invariant NoSelfEquivocation is violated" "$TOOLS/$c.out" \
      || { echo "FAIL: $c was expected to violate NoSelfEquivocation" >&2; exit 1; }
  done
  echo "negative models fail as expected (the safeguards are necessary in the model)"
  exit 0
fi
for c in ${MODEL_CONFIGS:-n2 n3 n2_live}; do
  run "$c"
  grep -q "Model checking completed. No error has been found" "$TOOLS/$c.out" \
    || { echo "FAIL: $c" >&2; tail -n 30 "$TOOLS/$c.out" >&2; exit 1; }
done
echo "PASS: all bounded models checked with no error"
