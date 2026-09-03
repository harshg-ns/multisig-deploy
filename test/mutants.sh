#!/bin/sh
#  A proof that proves nothing is worse than no proof, because it is believed.
#  Each mutation below breaks one rule; each must be caught by the prover or by
#  the test suite. A mutant that escapes means the corresponding test is
#  decoration.
#
#  Audit R1: this works on a private copy of the tree, never on src/. Two
#  reasons. It can then run concurrently with test/run.sh in the same checkout,
#  and — the one that actually matters — a killed run can no longer leave
#  weakened source behind. The previous version mutated src/ in place and
#  restored on a trap, so a SIGKILL between the mutation and the restore left a
#  Threshold of 1 sitting in the working tree.
set -eu
HERE=$(cd "$(dirname "$0")/.." && pwd)

for t in gprbuild gnatprove ssh-keygen; do
   command -v "$t" >/dev/null || { echo "missing: $t (see README)"; exit 2; }
done

WORK=$(mktemp -d)
FIX=$(mktemp -d)
trap 'rm -rf "$WORK" "$FIX"' EXIT

#  Fixtures come from the same script run.sh uses, so the two never drift.
TMP="$FIX" . "$HERE/test/fixtures.sh" >/dev/null

cp -R "$HERE/src" "$HERE/test" "$HERE/quorum.gpr" "$HERE/tests.gpr" "$WORK/"
cd "$WORK"

mkdir -p pristine
cp src/quorum.ads src/quorum.adb src/edge.adb pristine/
restore () { cp pristine/quorum.ads pristine/quorum.adb pristine/edge.adb src/; }

fails=0

caught_by_tests () {
   gprbuild -P tests.gpr -p -q
   ./test/harness "$FIX" >/dev/null 2>&1 && return 1
   return 0
}

echo "-- mutant: Decide stops checking the author"
perl -0pi -e 's/      if Signed_By_Author \(M\.Author, R, Verified\) then\n         return Refuse_Author;\n      end if;/      null;/' src/quorum.adb
gnatprove -P quorum.gpr --level=2 --report=fail -j0 2>&1 \
  | grep -q "postcondition might fail" \
  || { echo "   NOT CAUGHT by the prover"; fails=$((fails+1)); }
restore

for m in "Threshold       : constant := 2;|Threshold       : constant := 1;" \
         "Min_Delay_Hours : constant := 24;|Min_Delay_Hours : constant := 0;" \
         "Min_Enrolled    : constant := 3;|Min_Enrolled    : constant := 1;"
do
   from=${m%%|*}; to=${m##*|}
   echo "-- mutant: $to"
   perl -pi -e "s/\Q$from\E/$to/" src/quorum.ads
   caught_by_tests || { echo "   NOT CAUGHT by the tests"; fails=$((fails+1)); }
   restore
done

#  Everything below is in edge.adb, outside the proof, which is where every
#  defect found by audit so far has lived. Note what the first one establishes:
#  it over-reads and is caught by Read_File's own postcondition. The exact
#  audited defect — a single read of Buf'Length + 1 — is caught by the redzone
#  fence instead; ADVERSARIAL_AUDIT.md records that run against the original
#  code, since it is not a one-line mutation.
echo "-- mutant: Read_File over-reads its buffer (the class of audit A2/A3)"
perl -pi -e "s/Buf'Length - Total\)/Buf'Length - Total + 1)/" src/edge.adb
caught_by_tests || { echo "   NOT CAUGHT"; fails=$((fails+1)); }
restore

echo "-- mutant: Verify stops rewinding the sealed descriptors"
perl -0pi -e 's/      if C_Lseek \(Roster\.Fd, 0, Seek_Set\) \/= 0\n        or else C_Lseek \(Message\.Fd, 0, Seek_Set\) \/= 0\n      then\n         return;\n      end if;/      null;/' src/edge.adb
caught_by_tests || { echo "   NOT CAUGHT by the reuse tests"; fails=$((fails+1)); }
restore

echo "-- mutant: Verify stops emptying the environment (audit R3)"
perl -pi -e "s/^      Drop_Environment;/      null;/" src/edge.adb
caught_by_tests || { echo "   NOT CAUGHT by the environment tests"; fails=$((fails+1)); }
restore

[ "$fails" -eq 0 ] && echo "all mutants caught" || { echo "$fails escaped"; exit 1; }
