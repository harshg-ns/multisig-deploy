#!/bin/sh
#  Fixture generation, shared by run.sh and mutants.sh so the two never drift.
#  Usage: TMP=<dir> . test/fixtures.sh
set -eu

#  Real Ed25519 keys and real ssh-keygen signatures. Software keys, because a
#  genuine sk-* signature needs a physical authenticator to touch; the roster
#  grammar refuses software keys, so these never reach Parse_Roster.
#  alice, bob, carol are enrolled. dave and erin are not. bob is the author.
for who in alice bob carol dave erin; do
   ssh-keygen -q -t ed25519 -N '' -C "$who" -f "$TMP/$who"
done
for who in alice bob carol; do
   printf '%s@ns.com %s\n' "$who" "$(cut -d' ' -f1,2 "$TMP/$who.pub")"
done > "$TMP/roster"

manifest () {
   printf 'ns-release-manifest v1\n'
   printf 'commit: %s\n' "4bfc31f51e0000000000000000000000000000ab"
   printf 'digest: sha256:%s\n' "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
   printf 'target: P1\n'
   printf 'signed_at: 2026-09-01T09:00:00Z\n'
   printf 'execute_after: 2026-09-02T09:00:00Z\n'
   printf 'expires_at: 2026-09-05T09:00:00Z\n'
   printf 'author: %s\n' "${1:-swayam@ns.com}"
}

manifest "bob@ns.com"    > "$TMP/manifest"
manifest "archit@ns.com" > "$TMP/tampered"

sign () {  # sign <key> <message> <namespace> -> $TMP/sig.<name>
   cp "$TMP/$2" "$TMP/msg.$4"
   ssh-keygen -Y sign -q -f "$TMP/$1" -n "$3" "$TMP/msg.$4"
   mv "$TMP/msg.$4.sig" "$TMP/sig.$4"
   rm -f "$TMP/msg.$4"
}
sign alice manifest ns-release      alice
sign alice manifest ns-release      alice2   # same key, a second signature file
sign bob   manifest ns-release      bob
sign carol manifest ns-release      carol
sign dave  manifest ns-release      dave
sign erin  manifest ns-release      erin
sign alice manifest something-else  otherns

#  Race fixtures. The initial roster is a grammatically valid sk-* roster;
#  the attacker roster reuses the same principal names with software keys.
cp "$TMP/manifest" "$TMP/race-manifest"
cat > "$TMP/race-roster" <<'EOF'
alice@ns.com sk-ssh-ed25519@openssh.com AAAAGnNrLXNzaC1lZDI1NTE5QG9wZW5zc2guY29tAAAAIB0000000000000000
bob@ns.com sk-ssh-ed25519@openssh.com AAAAGnNrLXNzaC1lZDI1NTE5QG9wZW5zc2guY29tAAAAIC1111111111111111
carol@ns.com sk-ssh-ed25519@openssh.com AAAAGnNrLXNzaC1lZDI1NTE5QG9wZW5zc2guY29tAAAAID2222222222222222
EOF
{
   printf 'alice@ns.com %s\n' "$(cut -d' ' -f1,2 "$TMP/dave.pub")"
   printf 'carol@ns.com %s\n' "$(cut -d' ' -f1,2 "$TMP/erin.pub")"
   printf 'bob@ns.com %s\n' "$(cut -d' ' -f1,2 "$TMP/alice.pub")"
} > "$TMP/attacker-roster"

#  Boundary cases for Edge.Read_File. 4096 is exactly the buffer and must be
#  accepted; 4097 is one byte over and must be refused without a byte being
#  written past the buffer. harness.adb (Redzone) checks both with a fence.
{ head -c 4095 /dev/zero | tr '\000' '1'; printf '\n'; } > "$TMP/roster-4096"
{ head -c 4096 /dev/zero | tr '\000' '1'; printf '\n'; } > "$TMP/roster-4097"
cp "$TMP/roster-4097" "$TMP/cancelled-4097"

#  Black-box the binary. A synthetic sk-* roster is grammatically valid and
#  cryptographically useless, which is exactly what is needed to show the
#  binary refuses rather than assumes.
cat > "$TMP/sk-roster" <<'EOF'
swayam@ns.com sk-ssh-ed25519@openssh.com AAAAGnNrLXNzaC1lZDI1NTE5QG9wZW5zc2guY29tAAAAIB0000000000000000
archit@ns.com sk-ssh-ed25519@openssh.com AAAAGnNrLXNzaC1lZDI1NTE5QG9wZW5zc2guY29tAAAAIC1111111111111111
malek@ns.com sk-ecdsa-sha2-nistp256@openssh.com AAAAInNrLWVjZHNhLXNoYTItbmlzdHAyNTZAb3BlbnNzaC5jb20AAAAIbmlzdA
EOF
: > "$TMP/cancelled"
printf 'garbage\n' > "$TMP/badmanifest"
ln -s "$TMP/manifest" "$TMP/link-to-manifest"
