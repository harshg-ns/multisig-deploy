#!/bin/sh
#  Closes SPEC.md gap G1: prove a signature from a REAL FIDO2 key verifies
#  through this program. Needs a human to touch the key, so it cannot live in
#  run.sh and no CI can run it.
#
#    ./test/bench-sk.sh [~/.ssh/ns-commit-signing]
#
#  Touch the key once when prompted. Nothing outside a temp dir is written and
#  the key is only ever used to sign a throwaway manifest.
set -eu
cd "$(dirname "$0")/.."

KEY=${1:-$HOME/.ssh/ns-commit-signing}
[ -f "$KEY.pub" ] || { echo "no such public key: $KEY.pub"; exit 2; }

#  Apple ships OpenSSH without built-in FIDO support, so SIGNING with an sk-*
#  key needs a middleware provider. /usr/lib/ssh-keychain.dylib is Apple's
#  Secure Enclave provider; a YubiKey on Linux needs none. Verification never
#  needs one, which is the point the second assertion below establishes.
PROVIDER=${SSH_SK_PROVIDER:-}
if [ -z "$PROVIDER" ] && [ -f /usr/lib/ssh-keychain.dylib ]; then
   PROVIDER=/usr/lib/ssh-keychain.dylib
fi
if [ -n "$PROVIDER" ]; then
   echo "signing provider: $PROVIDER"
   set -- -w "$PROVIDER"
else
   set --
fi

ALG=$(cut -d' ' -f1 "$KEY.pub")
case "$ALG" in
   sk-ssh-ed25519@openssh.com|sk-ecdsa-sha2-nistp256@openssh.com) ;;
   *) echo "$KEY.pub is $ALG, not a FIDO2 key — this bench proves nothing with it"; exit 2 ;;
esac
echo "key algorithm: $ALG"

command -v gprbuild >/dev/null || { echo "missing: gprbuild (see README)"; exit 2; }
gprbuild -P quorum.gpr -p -q

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

#  The real key is enrolled in slot 1. Slots 2 and 3 are grammatically valid
#  sk-* entries that cannot sign, so a pass here means slot 1 verified and
#  nothing else did.
{
   printf 'harsh@ns.com %s\n' "$(cut -d' ' -f1,2 "$KEY.pub")"
   printf 'archit@ns.com sk-ssh-ed25519@openssh.com AAAAGnNrLXNzaC1lZDI1NTE5QG9wZW5zc2guY29tAAAAIC1111111111111111\n'
   printf 'malek@ns.com sk-ecdsa-sha2-nistp256@openssh.com AAAAInNrLWVjZHNhLXNoYTItbmlzdHAyNTZAb3BlbnNzaC5jb20AAAAIbmlzdA\n'
} > "$TMP/roster"

cat > "$TMP/manifest" <<'EOF'
ns-release-manifest v1
commit: 4bfc31f51e0000000000000000000000000000ab
digest: sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08
target: P1
signed_at: 2026-09-01T09:00:00Z
execute_after: 2026-09-02T09:00:00Z
expires_at: 2036-09-05T09:00:00Z
author: bob@ns.com
EOF
: > "$TMP/cancelled"

echo
echo "TOUCH THE KEY, or approve the Touch ID prompt, when asked."
echo "Signing a throwaway manifest, namespace ns-release."
ssh-keygen -Y sign "$@" -f "$KEY" -n ns-release "$TMP/manifest"
mv "$TMP/manifest.sig" "$TMP/sig.harsh"
echo

#  THE DECISIVE ASSERTION. Edge.Verify runs ssh-keygen with an emptied
#  environment (audit R3), so a real sk-* signature must verify with no
#  environment at all and no provider. If this fails, the R3 fix broke the
#  program for exactly the keys it exists to verify, and that would be a far
#  worse defect than the one R3 closed.
if env -i /usr/bin/ssh-keygen -Y verify -f "$TMP/roster" -I harsh@ns.com \
        -n ns-release -s "$TMP/sig.harsh" < "$TMP/manifest" >/dev/null 2>&1
then
   echo "PASS: a real $ALG signature verifies with an EMPTY environment and no"
   echo "      provider, which is exactly how Edge.Verify invokes ssh-keygen."
else
   echo "FAIL: a real $ALG signature does not verify under 'env -i'."
   echo "      Verification needs something from the environment, so"
   echo "      Drop_Environment breaks the program for real hardware keys."
   exit 1
fi

#  Integration smoke check. One signature is one signer, so the expected
#  verdict is REFUSE_QUORUM. Note honestly what this does and does not show:
#  REFUSE_QUORUM is reached both at one signer and at zero, so on its own it
#  cannot distinguish "verified" from "did not verify". The assertion above is
#  what establishes verification; this only shows the whole program runs the
#  path and reaches the threshold check rather than refusing the roster.
echo
out=$(./quorum "$TMP/manifest" "$TMP/roster" "$TMP/cancelled" "$TMP/sig.harsh" 2>&1 || true)
echo "$out"
case "$out" in
   *REFUSE_QUORUM*)
      echo
      echo "PASS: the program accepted a roster containing a real $ALG key and"
      echo "      reached the threshold check."
      echo
      echo "G1 is closed for the single-signature path. A full 2-of-3 bench still"
      echo "      needs a second physical key held by a second person, and"
      echo "      enrolment attestation (G3) is a separate question again."
      ;;
   *REFUSE_ROSTER*)
      echo
      echo "FAIL: the roster grammar rejected a genuine $ALG key. Parse_Roster is wrong."
      exit 1 ;;
   *)
      echo
      echo "FAIL: unexpected verdict from the program."
      exit 1 ;;
esac
