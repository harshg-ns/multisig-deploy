#!/bin/sh
#  Build, prove, and test. Everything: no separate proof step to forget.
set -eu
cd "$(dirname "$0")/.."

for t in gprbuild gnatprove ssh-keygen; do
   command -v "$t" >/dev/null || { echo "missing: $t (see README)"; exit 2; }
done

echo "== build =="
gprbuild -P quorum.gpr -p -q
gprbuild -P tests.gpr  -p -q

echo "== prove =="
gnatprove -P quorum.gpr --level=2 --report=fail -j0

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

TMP="$TMP" . ./test/fixtures.sh

echo "== logic, plumbing, and 2-of-3 with real signatures =="
./test/harness "$TMP"

fails=0
expect () {
   want=$1; shift
   got=$(./quorum "$@" 2>&1 || true)
   case "$got" in
      *"$want"*) ;;
      *) echo "FAIL binary: wanted '$want', got '$got'"; fails=$((fails+1)) ;;
   esac
}

echo "== binary =="
expect REFUSE_QUORUM   "$TMP/manifest" "$TMP/sk-roster" "$TMP/cancelled" "$TMP/sig.alice"
expect REFUSE_MANIFEST "$TMP/badmanifest" "$TMP/sk-roster" "$TMP/cancelled" "$TMP/sig.alice"
expect REFUSE_ROSTER   "$TMP/manifest" "$TMP/roster" "$TMP/cancelled" "$TMP/sig.alice"
expect "cancellation list unreadable" \
                       "$TMP/manifest" "$TMP/sk-roster" "$TMP/absent" "$TMP/sig.alice"
expect "not a regular file" \
                       "$TMP/link-to-manifest" "$TMP/sk-roster" "$TMP/cancelled" "$TMP/sig.alice"
expect usage           "$TMP/manifest" "$TMP/sk-roster" "$TMP/cancelled"
expect usage           "$TMP/manifest" "$TMP/sk-roster" "$TMP/cancelled" \
                       s1 s2 s3 s4 s5 s6 s7 s8 s9

if ./quorum "$TMP/manifest" "$TMP/sk-roster" "$TMP/cancelled" "$TMP/sig.alice" \
     >/dev/null 2>&1; then
   echo "FAIL binary: exit status 0 on a refusal"; fails=$((fails+1))
fi

#  Guard against shipping a build with assertions compiled out. -gnata is what
#  makes Decide's precondition, Read_File's postcondition and the environment
#  invariant in Verify real at runtime; without it the binary looks identical
#  and silently drops all three. A raise site carries its source file name, so
#  the name surviving into the binary is evidence the checks were generated.
if command -v strings >/dev/null; then
   if ! strings ./quorum | grep -qx "edge.adb"; then
      echo "FAIL binary: assertions are not compiled in — is -gnata missing?"
      fails=$((fails+1))
   fi
fi

[ "$fails" -eq 0 ] && echo " 9 passed, 0 failed" || { echo " $fails failed"; exit 1; }
