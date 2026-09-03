# quorum

`quorum` decides whether a release may execute. It returns success only when **two distinct
enrolled hardware-key holders** have signed **this exact release manifest**, the manifest’s signed
**24-hour queue delay** has elapsed, the authorisation has **not expired**, the manifest **author is
excluded** as an approver, and **no roster member has cancelled** it. Any parse failure, malformed
roster, software key, missing file, symlinked control file, invalid signature, failed threshold, or
cancellation is refused.

## Use

```sh
quorum MANIFEST ROSTER CANCELLED SIG [SIG ...]
```

- `MANIFEST` — signed release manifest describing the commit, artifact digest, target, signing and
  execution times, expiry, and author.
- `ROSTER` — enrolled signer list; only OpenSSH FIDO hardware-key algorithms are accepted.
- `CANCELLED` — one digest per line, or an empty file. A malformed list counts as cancelled.
- `SIG...` — one or more detached OpenSSH signatures over the manifest.

Exit `0` means **release**. Every other exit means **do not release**. In CI, run this as a required
deploy step before release credentials are available:

```yaml
- run: ./quorum manifest security/release-signers cancelled sigs/*.sig
```

Each approver signs the manifest itself:

```sh
ssh-keygen -Y sign -f ~/.ssh/id_ed25519_sk -n ns-release manifest
```

Signing may require a FIDO provider on macOS; verification does not.

## Build and test

```sh
./test/run.sh          # build, prove, and run tests
./test/mutants.sh      # mutate security rules and verify detection
./test/bench-sk.sh     # verify with a real FIDO2 key; requires one touch

QUORUM_MODE=release gprbuild -P quorum.gpr -p
strip -x quorum
```

The build preserves runtime assertions and rejects a stripped-down proof configuration. On Linux,
set `QUORUM_LINK_GC=gc_sections` if using release-mode section stripping.

## Inputs and outputs

The manifest and roster use fixed, byte-exact ASCII layouts rather than YAML or JSON. The verifier
binds signatures to every manifest field, including commit, artifact digest, and execution window.
It calls `/usr/bin/ssh-keygen -Y verify` directly, reads only its exit status, and does not
reimplement signature verification.

Successful output reports that the release is authorised. Refusals identify the failed check—for
example invalid manifest, invalid roster, cancellation, insufficient distinct signers, or attempted
approval by the manifest author. The program fails closed.

## Current status

- The decision core is written in SPARK Ada and is proved for the stated security property, absence
  of runtime errors, and termination.
- Filesystem, clock, process-spawn, and OpenSSH integration code sit outside that proof and fail
  closed.
- One real FIDO2 signature has been verified; a complete real-world 2-of-3 approval has not yet been
  exercised.
- The program does not establish build provenance or signer intent. It proves only that the presented
  manifest satisfies the encoded release policy.

## Documentation

- `SPEC.md` — threat model, input grammars, formal security property, proof boundary, trusted
  assumptions, known gaps, test inventory, and change-control rules.
- `ADVERSARIAL_AUDIT.md` — audit findings, severity, fixes, and dispositions.
- `visual.html` — one-page visual explanation of the mechanism.

## Requirements

- GNAT, `gprbuild`, and `GNATprove`.
- OpenSSH `ssh-keygen`.
- Linux or macOS on x86-64 or aarch64.

Install the Ada toolchain with Alire:

```sh
curl -LO https://github.com/alire-project/alire/releases/download/v2.1.1/alr-2.1.1-bin-aarch64-macos.zip
unzip alr-2.1.1-bin-aarch64-macos.zip
./bin/alr toolchain --select gnat_native gprbuild
./bin/alr install gnatprove
```
