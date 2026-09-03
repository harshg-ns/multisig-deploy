# quorum — technical specification

Written for someone auditing this repository who has no other context, and who is trying to find
the flaw. §12 says where to look first. Everything asserted here is checkable against the source;
where something is assumed rather than established, it says so.

**Audit history.** Two adversarial audits on 2026-09-02. The first found one critical policy
bypass and two out-of-bounds writes; a fourth and more severe variant of the bypass turned up while
reproducing it. The second confirmed those fixes and found an inherited process environment through
which a loader variable could subvert the verifier, a descriptor leak, and a mutation script that
could leave weakened source in the working tree. All six are fixed. `ADVERSARIAL_AUDIT.md` holds
the findings and the dispositions — read it before this.

**The lesson worth carrying: every defect found so far has been in the 431 lines outside the
proof, and none in the 561 inside it.** Draw the right conclusion. The proved core has never
needed a correction, and the boundary has needed six; so the boundary is where an auditor's time
goes, and §12 is ordered accordingly.

Line references are to the tree as committed. Constants are quoted from `src/quorum.ads:8-15`.

---

## 1. What this program decides

`quorum` is a single-shot decision procedure. It is given a release manifest, a roster of enrolled
signers, a cancellation list, and one or more detached signatures. It exits 0 if and only if the
release described by the manifest may execute at the moment it is run, and non-zero otherwise.

```
quorum MANIFEST ROSTER CANCELLED SIG [SIG ...]
```

It performs no action. It authorises one. The deploy job runs it as a required step before
assuming any credential; a non-zero exit must abort the job.

There are no flags, no subcommands, no configuration file, and no environment variables. Every
policy parameter is a compile-time constant. This is deliberate: a control whose behaviour can be
selected at the call site is a control the caller can weaken, and the caller here is a CI job that
an attacker may already influence.

## 2. The control it implements

NS's release plan (`../../ns-ideal-security/HARDPOINT.md`) requires, at steps 4.4, 4.5 and 4.7:

- a **real two-person rule** — GitHub's required reviewers is 1-of-N regardless of how many
  reviewers are listed, and there is no reviewer-count field;
- a **signed release manifest** binding the authorisation to the commit *and* the artifact digest,
  with an expiry — GitHub records that "someone approved this run", which is not a signature over
  what ships and does not expire;
- a **24-hour delay** on any change touching a money-egress path, so that a release is
  "shippable, and revocable" rather than shipped.

A market scan (`../../ns-ideal-security/multisig-deploy-market-scan.md`) found no product that
does this. The nearest commercial k-of-n controls gate the wrong object: HashiCorp Vault
Enterprise control groups gate *unwrapping a secret*, and Teleport access requests grant *a human
a role*. Neither binds the approval to an artifact digest. This program is the missing piece;
GitHub still supplies the chokepoint and the wait timer.

## 3. Threat model

**Assumed capabilities of the attacker.**

1. Full user-level code execution on a developer laptop: reading files, driving the `ssh-agent`
   socket, using stolen tokens, opening pull requests, and merging if review can be obtained.
2. Write access to the CI workflow definition, and therefore control of this program's argument
   vector, working directory, and every file path it is given.
3. Control of one enrolled private key — but not the human presence check that key requires.
4. A poisoned build-time dependency in any other part of the NS tree.
5. A hostile or prompt-injected AI agent with the same access as (1) and (2).

**Explicitly out of scope.**

6. Coercion or compromise of `Threshold` distinct key holders at once.
7. Compromise of the YubiKey hardware or its firmware. EUCLEAK (CVE-2024-45678) is mitigated by
   the ≥ 5.7.0 firmware floor in `HARDPOINT.md` 2.1, not here.
8. Compromise of OpenSSH itself, or of the toolchain that built this binary.
9. A malicious change that `Threshold` competent humans read and approved. A signature proves
   origin; it can never prove intent.
10. Root on the machine running this program. Root can replace the binary.
11. The system clock being wrong. See §8 and gap G4.

**The property claimed against (1)–(5):** none of them, alone or in combination, causes `quorum`
to exit 0 for a release that fewer than `Threshold` distinct enrolled holders signed, or whose
signed 24-hour delay has not elapsed, or which has been cancelled.

## 4. The security property, formally

`src/quorum.ads:137-160`. Proved by GNATprove, not merely asserted:

```ada
Post => (if Decide'Result = Allow then
           R.Count >= Min_Enrolled
           and then Members (Verified) >= Threshold
           and then not Signed_By_Author (M.Author, R, Verified)
           and then Epoch (M.Execute_After) - Epoch (M.Signed_At)
                      >= Min_Delay_Hours * 3600
           and then Epoch (Now) >= Epoch (M.Execute_After)
           and then Epoch (Now) < Epoch (M.Expires_At)
           and then not Revoked);
```

Read it as: *nothing is allowed unless all seven conjuncts hold.* It is one-directional on
purpose. The converse — that everything satisfying the seven is allowed — would restate the body
of `Decide` in its own contract and prove nothing; and it is the wrong risk. A control that
wrongly refuses causes an outage. A control that wrongly allows causes the thing the control
exists to prevent.

Precondition, same location:

```ada
Pre => Well_Formed (M) and then Valid (Now) and then Consistent (R, Verified)
```

`Consistent` (`quorum.ads:93`) says no bit is set in the signer set beyond `R.Count`. It is
established by `Edge.Attribute_One`'s postcondition (`edge.ads:41-51`) and re-checked at runtime
in `main.adb:88-91`.

## 5. Architecture and trust boundary

| unit | lines | SPARK | role |
|---|---|---|---|
| `src/quorum.ads` + `.adb` | 561 | **proved** | grammars, time, the decision. No I/O, no clock, no environment, no allocation, no recursion. |
| `src/edge.ads` | 97 | proved-as-contract | the boundary's declaration. What the core is entitled to assume. |
| `src/edge.adb` | 298 | **`SPARK_Mode => Off`** | filesystem, clock, `ssh-keygen`, five libc syscalls. |
| `src/main.adb` | 133 | not analysed | argument handling, orchestration, output. |

Untrusted bytes enter only through `Edge.Read_File`. They reach the core as a `String` slice and
leave it as typed values.

**The invariant that matters, stated correctly.** *The bytes OpenSSH verifies are the bytes the
core parsed.* Each input path is read exactly once. The manifest and roster slices that were parsed
are then **sealed** — copied into a file created with `mkstemp` and unlinked immediately, so no path
in the filesystem names them any more — and `Edge.Verify` is given those seals rather than any
path. A control that hands a *path* to its verifier can be given two different answers on the
second lookup, which is precisely findings A0 and A1 of the audit: an earlier version of this
document claimed no path was re-read, and that claim was false. The cancellation list is read once
into a buffer and never re-opened.

The signature files are still named by path, deliberately. A substituted signature gains an
attacker nothing, because whatever it contains must still verify against the sealed roster bytes
over the sealed message bytes.

`Edge` is declared with `Abstract_State => (World with External => (Async_Writers => True))`, which
is how SPARK is told that the outside world changes underneath it. Every `Edge` subprogram has
`Global => (Input => World)`, so the core cannot accidentally acquire a hidden dependency on the
environment.

### What `Edge` is trusted to do, in full

1. **`Read_File`** — refuses symlinks and non-regular files. Reads in a loop with a count of at
   most `Buf'Length - Total`, because a short read is legal, and **never** more than the buffer
   holds. A file larger than the buffer is detected by a separate one-byte read into a local
   `Probe`, and refused: a file that fills the buffer exactly is otherwise indistinguishable from a
   truncated one, and a silently truncated manifest is a forged manifest. An earlier version asked
   `read(2)` for `Buf'Length + 1` into a `Buf'Length` buffer, which was a one-byte out-of-bounds
   write on every oversized input (audit A2, A3).
2. **`Get_Now`** (`edge.adb:58`) — `Ada.Calendar.Clock` split at `Time_Zone => 0`. Refuses a
   clock outside 2000–2099 rather than clamping. There is no override of any kind.
3. **`Verify`** — **empties the process environment first.** `Spawn` execs with the caller's
   environment and the threat model grants the attacker that environment, so `environ` is replaced
   with an empty block, which is what `execv` passes to `execve` on both glibc and Darwin. Without
   it, one inherited `LD_PRELOAD` on Linux replaces `ssh-keygen`'s behaviour without touching
   OpenSSH (audit R3). Apple's runtime hardening already blocks injection into a signed
   `/usr/bin/ssh-keygen`, but that is a property of the platform, not of this program, and it is
   why the regression test asserts the *parent's* environment is empty after a verification rather
   than trying to demonstrate an injection macOS will not permit. Then it spawns
   `/usr/bin/ssh-keygen` with the argument vector
   `-Y verify -f /dev/fd/N -I PRINCIPAL -n ns-release -s SIG`, the sealed message on standard
   input, stdout and stderr to `/dev/null`. **Only the exit status is read.** No shell, no `PATH`
   resolution, no output parsing. The binary is checked to be a regular non-symlink file first.
   The sealed descriptors are shared across calls, so each call `lseek`s both back to zero first.
   Standard input is redirected with libc `dup`/`dup2`, whose return values are checked; a failure
   to restore standard input after the spawn forces the exit code to `-1` rather than letting the
   verification be reported as successful.
4. **`Unseal`** — closes the descriptor. Process exit is a complete cleanup boundary for a
   single-shot CLI, so this exists for the case where `Edge` is reused in something longer-lived,
   where two leaked descriptors per decision is a resource-exhaustion bug rather than a rounding
   error (audit R2). `main` and the tests call it.
5. **`Seal`** — `mkstemp` (`O_CREAT | O_EXCL`, mode 0600) in `/tmp`, `unlink` at once, write the
   bytes, keep the descriptor. The descriptor is then the only reference to those bytes in the
   system, and the program never writes to it again. `Seal` must be handed the same slice that was
   parsed, from the same buffer; re-reading the path to seal it would reintroduce the race the type
   exists to remove.
6. **`Attribute_One`** — credits one signature to at most one enrolled slot by trying each
   principal in turn and stopping at the first that verifies.

**No cryptography is implemented in this repository.** OpenSSH is already the root of trust for
NS commit signing; a second implementation of Ed25519 would be a second thing to be wrong. This is
a deliberate divergence from `../hardpoint-rs`, which implements Ed25519, ECDSA and RSA itself
specifically to avoid spawning a process. The objection is answered rather than ignored: an exit
status is one bit, not a rendering, and `-Y verify` reports policy failures the same way it
reports bad signatures.

## 6. Input grammars

All three are strict. Anything not described below is refused. There is no normalisation step,
no whitespace trimming, no case folding, and no unicode processing — bytes are compared to bytes.

### 6.1 Manifest — `Parse_Manifest`, `quorum.adb:172`

Eight lines, fixed order, fixed widths except the last, US-ASCII only, LF line endings, ending in
LF. Total length 276–337 bytes.

| bytes | content |
|---|---|
| 1–22 | `ns-release-manifest v1` |
| 23 | LF |
| 24–31 | `commit: ` |
| 32–71 | 40 characters of `[0-9a-f]` |
| 72 | LF |
| 73–87 | `digest: sha256:` |
| 88–151 | 64 characters of `[0-9a-f]` |
| 152 | LF |
| 153–161 | `target: P` |
| 162 | one character of `[1-9]` |
| 163 | LF |
| 164–174 | `signed_at: ` |
| 175–194 | timestamp, §8 |
| 195 | LF |
| 196–210 | `execute_after: ` |
| 211–230 | timestamp |
| 231 | LF |
| 232–243 | `expires_at: ` |
| 244–263 | timestamp |
| 264 | LF |
| 265–272 | `author: ` |
| 273 – `Last-1` | 3–64 characters of `[a-z0-9._@-]` |
| `Last` | LF |

The layout is fixed so that parsing is index arithmetic. **It is not YAML and not JSON.** Duplicate
keys, reordered fields, anchors and aliases, type coercion, `!!` tags, comments, BOMs, unicode
confusables in field names, integer overflow in a length prefix, and every other structured-format
attack are not defended against — they are not expressible. A parser with no state machine has no
state machine bug.

The author field is last so it can be the only variable-length field; length therefore pins the
whole layout, checked once at `quorum.adb:180-184`.

Rejected by construction, each covered by a test: upper-case hex, CRLF, a wrong header version,
`target: P0`, non-ASCII or upper-case or space-containing author names, trailing bytes after the
final LF, a missing final LF, and every malformed timestamp in §8.

### 6.2 Roster — `Parse_Roster`, `quorum.adb:299`

`Min_Enrolled` (3) to `Max_Enrolled` (8) lines, each ending LF, the file ending LF. Each line is
exactly three space-separated fields:

```
principal  algorithm  base64-key
```

- `principal` — 3 to 64 characters of `[a-z0-9._@-]`. Must be unique across the file: the same
  principal enrolled twice is not two humans (`quorum.adb:320-324`).
- `algorithm` — **exactly one of** `sk-ssh-ed25519@openssh.com` or
  `sk-ecdsa-sha2-nistp256@openssh.com` (`quorum.adb:36-37`).
- `base64-key` — at least 40 characters of `[A-Za-z0-9+/=]`.

A third space anywhere on the line is a refusal (`quorum.adb:253`). This kills OpenSSH's
`allowed_signers` options field and comment field in one rule — including `cert-authority`,
which would otherwise turn one enrolled line into a certificate authority able to mint signers,
and `namespaces=`, which would silently narrow or widen what a key may sign.

**This is where hardware is enforced.** Because only FIDO2 algorithms may be enrolled, any
signature that `ssh-keygen -Y verify` accepts against this file was necessarily made by a
hardware-resident key, so no SSHSIG blob needs to be parsed to establish it. The check happens
once, at the trust root, rather than per signature.

Enrolment of the keys themselves — proving that a key was generated inside genuine manufacturer
hardware, and that `-O verify-required` was set so each signature demands a touch — is out of
scope for this program. It is `HARDPOINT.md` 2.2 and 2.4, and gap G1.

### 6.3 Cancellation list — `Is_Revoked`, `quorum.adb:337`

Zero or more lines, each exactly 64 characters of `[0-9a-f]`, each ending LF. Returns true if the
manifest's digest appears.

**A malformed list counts as a cancellation** (`quorum.adb:341`, `:348`, `:351`). An empty file
cancels nothing; a file with no final LF, or any line that is not a bare 64-character digest,
cancels everything. This is the fail-closed direction: the alternative is that corrupting the
cancellation list silently re-enables a cancelled release.

`main.adb:52-56` refuses outright if the file cannot be read at all. An absent list is not an
empty one.

## 7. The decision procedure

`Decide`, `quorum.adb:366-397`. Seven guards, in this order, first failure returned:

| # | guard | refusal |
|---|---|---|
| 1 | `R.Count >= Min_Enrolled` | `Refuse_Enrolment` |
| 2 | `Members (Verified) >= Threshold` | `Refuse_Quorum` |
| 3 | no verified signer equals `M.Author` | `Refuse_Author` |
| 4 | `Epoch (Execute_After) - Epoch (Signed_At) >= 86400` | `Refuse_Delay` |
| 5 | `Epoch (Now) >= Epoch (Execute_After)` | `Refuse_Early` |
| 6 | `Epoch (Now) < Epoch (Expires_At)` | `Refuse_Expired` |
| 7 | `not Revoked` | `Refuse_Revoked` |

The order affects only which refusal code is reported, never whether the release is allowed; the
postcondition is a conjunction. Order is chosen so the most structural failure is reported first,
because the code is what a human reads at 3am.

Three design choices carry more of the weight than the proof does:

**The signer set is a set indexed by enrolment slot** (`quorum.ads:79-89`). `Signer_Set` is
`array (1 .. Max_Enrolled) of Boolean`. "Two *distinct* humans" therefore holds by construction:
`Attribute_One` sets at most one bit per signature and stops at the first match, so one holder
presenting two signature files — or the same file twice, or eight copies — occupies one slot and
counts once. There is no counter to overflow and no list to deduplicate. This is verified with
real signatures, not only reasoned about: see the `sig.alice` + `sig.alice2` case in §10.

**`Min_Enrolled` is 3, not 2.** A 2-of-2 quorum means one lost or broken key blocks every release,
which is when someone builds an ungated fast path. `HARDPOINT.md` 5.5 makes the same point about
holidays.

**The delay is enforced, not asserted.** Guard 4 refuses unless the *signed bytes themselves*
contain a gap of at least 24 hours between `signed_at` and `execute_after`. A queued release
cannot shorten its own delay, and `Min_Delay_Hours` is a compile-time constant with no flag to
change it. Guard 5 then requires that gap to have actually elapsed against the internal clock. The
GitHub environment wait timer is the *mechanism* that makes the job wait; guard 5 is the
*authority*, because an administrator bypass or a workflow re-run can reset a timer and cannot
reset a value inside a signed file.

## 8. Time

Timestamps are the 20-character form `YYYY-MM-DDTHH:MM:SSZ`. Nothing else parses: no fractional
seconds, no offsets other than `Z`, no lower-case `t` or `z`, no omitted separators
(`quorum.adb:118-160`).

- **Range** is 2000–2099 (`quorum.ads:44`). Within that window every year divisible by 4 is a leap
  year, with no century exception, so `Month_Days` (`quorum.adb:76`) is three lines and there is
  no Gregorian edge case. 2100 is outside the range on purpose.
- **`Valid`** (`quorum.ads:62`) rejects impossible dates: `2026-02-31` and `2027-02-29` are
  refused, `2028-02-29` is accepted.
- **No leap seconds.** `23:59:60` is refused because `Second_Num` is `0 .. 59`. A policy clock does
  not need them and admitting them would add an arithmetic special case to every comparison.
- **All ordering is by `Epoch`** (`quorum.adb:92`), seconds since 2000-01-01T00:00:00Z, bounded
  `0 .. 3_155_760_000` and proved not to overflow. Because every comparison goes through the same
  metric, no lemma about the ordering of the record components is needed anywhere — a common
  source of subtle bugs in hand-rolled date code is simply absent.
- **`Now` is UTC from the system clock, obtained internally.** No `--now`, no environment
  variable, no test hook. The previous Python implementation gated a `--now` flag behind an
  environment variable; the threat model grants the attacker the environment, so the flag was
  removed rather than gated.

## 9. What the proof covers

GNATprove 16.1.0, `--level=2`, provers Alt-Ergo 2.6.1 / CVC5 1.3.2 / Z3 4.15.4.

```
Success: all checks proved (241 checks)
```

| category | checks | |
|---|---|---|
| Run-time checks | 157 | no overflow, no range violation, no index out of bounds, no division by zero, no uninitialised read — **on any input at all** |
| Functional contracts | 29 | including the §4 postcondition |
| Assertions | 13 | loop invariants and the `Epoch` bound |
| Initialization | 24 | flow analysis |
| Termination | 17 | every loop and subprogram terminates |
| Flow dependencies | 1 | |

Zero unproved. Zero `pragma Annotate (GNATprove, ...)` justifications — nothing is suppressed;
`grep -r Annotate src/` returns nothing.

**What this does and does not mean.** It means: for every possible input, the program cannot crash,
cannot read uninitialised memory, cannot loop forever, and cannot return `Allow` unless the seven
conjuncts of §4 hold. It does **not** mean the seven conjuncts are the right policy — that is a
human judgement, argued in §2 and §7 and open to challenge. It does not cover `edge.adb` or
`main.adb` (§5). It does not cover the compiler, the runtime, OpenSSH, or the hardware.

`test/mutants.sh` exists because a proof that proves nothing is worse than no proof, since it gets
believed. It deletes guard 3 and confirms GNATprove reports
`postcondition might fail, cannot prove not Signed_By_Author`; flips `Threshold` to 1,
`Min_Delay_Hours` to 0 and `Min_Enrolled` to 1; makes `Read_File` over-read its buffer; stops
`Verify` rewinding the sealed descriptors; and stops it emptying the environment. All seven must be
caught or the script exits non-zero.

Note what each mutant establishes. The over-read mutant is caught by `Read_File`'s own
postcondition, not by the red-zone fence. The exact audited defect — a single `read(2)` of
`Buf'Length + 1` — is caught by the fence, and because that is not a one-line mutation,
`ADVERSARIAL_AUDIT.md` records the run against the original code from commit `34a8267` instead:
two fence assertions fail there and pass after the fix.

## 10. Test inventory

`./test/run.sh` — builds, proves, and runs 88 checks. Fixtures are generated fresh into a
`mktemp -d` on every run by `test/fixtures.sh`, which `test/mutants.sh` also sources so the two
never drift; nothing is committed.

**46 grammar and decision tests** (`test/harness.adb`), against `Quorum` directly: 19 manifest
cases, 8 roster cases, 5 cancellation cases, 14 decision cases including the exact boundaries —
a window of exactly 24h allows, one second under refuses, `Now` exactly at `Execute_After`
allows, `Now` exactly at `Expires_At` refuses.

**10 OpenSSH plumbing tests** with real Ed25519 keys and real `ssh-keygen` signatures: a genuine
signature verifies; a tampered message does not; a signature is not attributed to another
principal; a signature made in a different namespace is refused; an unsealed message fails closed;
an unsealed roster fails closed; a sealed descriptor still verifies on a second use, which is what
the `lseek` rewind exists for; an *unsealed* descriptor then fails closed, which is what `Unseal`
must guarantee; and the process has an environment before the first verification and none after
it, which is the regression test for R3.

**11 race tests** (`Manifest_Race`, `Reopen_Race`), the regression tests for audit findings A0 and
A1: parse the manifest and roster, seal exactly those bytes, then replace both files on disk before
verification, and present signatures the attacker holds. Both must credit zero signers and refuse.

**6 red-zone tests** (`Redzone`), the regression tests for A2 and A3. A `String (1 .. Max_Roster +
8)` is passed to `Read_File` as `Arena (1 .. Max_Roster)` and the eight following bytes are checked
against a fence. Slices of one `String` are contiguous by definition, so this witnesses an
out-of-bounds write by construction rather than by observing where a compiler placed two locals.
A file of exactly the buffer size must still be accepted.

**7 whole-pipeline 2-of-3 tests**, also with real signatures, running exactly what `main` runs —
read, parse, `Attribute_One` per signature, `Decide`:

| signatures presented | expected |
|---|---|
| alice + carol | **Allow**, 2 signers |
| alice + alice (two signature files, one key) | `Refuse_Quorum`, **1** signer |
| dave + erin (neither enrolled) | `Refuse_Quorum`, 0 signers |
| alice + dave (one enrolled, one stranger) | `Refuse_Quorum`, 1 signer |
| alice + bob, where bob is the manifest's author | `Refuse_Author` |
| alice + bob + carol, bob the author | `Refuse_Author` |
| alice + carol, over a *different* manifest | `Refuse_Quorum`, 0 signers |

**8 black-box tests** of the binary, checking refusal codes and exit status: a synthetic but
grammatically valid `sk-*` roster yields `REFUSE_QUORUM`; a garbage manifest yields
`REFUSE_MANIFEST`; a software-key roster yields `REFUSE_ROSTER`; an absent cancellation list, a
symlinked manifest, too few arguments and too many arguments each refuse; and the process exits
non-zero on refusal.

**Determinism.** No test reads the wall clock: `Decide` takes `Now` as a parameter and the tests
pass a fixed instant. `Edge.Get_Now` is consequently exercised only by the binary tests, which do
not depend on its value.

## 11. Known gaps and residual risk

Numbered so an audit can refer to them.

**G1 — One real hardware signature has been through this program; a real 2-of-3 has not.**
*Was the highest gap here; now partly closed.* `./test/bench-sk.sh` was run on 2026-09-02 against a
genuine `sk-ecdsa-sha2-nistp256@openssh.com` key held in the macOS Secure Enclave, with a Touch ID
presence check. Two results:

1. **The signature verifies under `env -i` — no environment, no FIDO provider.** This is the
   decisive one, because it is exactly how `Verify` invokes `ssh-keygen` after audit R3. Had it
   failed, emptying the environment would have broken the program for precisely the keys it exists
   to verify, which would have been a worse defect than the one R3 closed.
2. The program accepted a roster containing a real `sk-*` public key and reached the threshold
   check, refusing with `REFUSE_QUORUM` at one signature.

What is still not established: a 2-of-3 with two distinct physical keys in two people's hands. That
needs a second key and a second person, and no single operator can produce it — which is the
control working. Note the bench cannot distinguish "verified" from "did not verify" from the
program's verdict alone, since `REFUSE_QUORUM` is reached at both one signer and zero; assertion 1
is what establishes verification, and the script says so.

**Operational consequence, and it is a good one: signing needs a FIDO provider, verifying does
not.** Apple ships OpenSSH without built-in FIDO support, so an approver on macOS must sign through
`SSH_SK_PROVIDER=/usr/lib/ssh-keychain.dylib` or `ssh-keygen -w`. The verifier needs nothing, so
the emptied environment costs it nothing. Enrolment attestation remains a separate question (G3).

**`./test/bench-sk.sh` closes the single-signature half of this in about two minutes, and needs
only a key that already exists.** This machine's git signing key is
`sk-ecdsa-sha2-nistp256@openssh.com` — a FIDO2 key in daily use — so the bench enrols it in slot 1
beside two unusable but grammatically valid `sk-*` entries, signs a throwaway manifest with one
touch, and asserts the program reaches `REFUSE_QUORUM`. That verdict is the proof: it can only be
reached if `Parse_Roster` accepted a genuine `sk-*` public key and the signature verified through
the sealed path. `REFUSE_ROSTER` would mean the grammar rejects real hardware keys.

A full 2-of-3 bench still needs a second physical key held by a second person, and the enrolment
question is separate again (G3). Related: `HARDPOINT.md` step 0.4 asks whether macOS emits `sk-*`
keys at all — the existence of this key answers that in the affirmative, though not which provider
issued it.

**G2 — `main.adb` and `edge.adb` are outside the proof.** 431 lines, and every defect found by audit has been in them. `Decide`'s precondition is
checked at runtime instead, because the build enables `-gnata`; a build without `-gnata` would
lose that check, which is why `main.adb:88-91` also tests `Consistent` explicitly.

**G3 — Enrolment is assumed, not verified here.** That a roster line's key was generated inside
genuine manufacturer hardware, with `-O verify-required` so every signature demands a touch, is
established by FIDO attestation at enrolment time (`HARDPOINT.md` 2.4) and by whoever reviews
changes to the roster file. This program checks the algorithm name, which is a claim about the
key's type, not proof of its provenance. The roster file must be `CODEOWNERS`-protected.

**G4 — The clock is trusted.** An attacker who can move the system clock forward past
`execute_after` retires the delay. Mitigation is environmental: the deploy runs on a machine whose
time is not attacker-controllable. Nothing in this program can detect it.

**G5 — Build provenance is not checked.** The manifest names a digest. That the digest is the
artifact CI built from that commit is `HARDPOINT.md` 3.2–3.4 and must run as a separate step in
the same job. `quorum` returning 0 does not mean the right bytes will be deployed.

**G6 — A signature proves origin, never intent.** Two genuine holders signing a malicious change
passes every check, and always will. Review is the control for that, and review is human.

**G7 — `Max_Enrolled` is 8 and `Threshold` is fixed at 2.** A larger organisation or a
higher threshold needs a source change and a re-proof. This is a feature at 45 seats and a
limitation later.

**G8 — Mode bits on `/usr/bin/ssh-keygen` are not checked.** Symlink and regular-file checks are.
A writable `/usr/bin` is out of scope (§3 item 10).

**G9 — No audit record is written.** The program prints its verdict to stdout/stderr and exits.
`HARDPOINT.md` 5.2 requires an immutable log outside the deploy authority; that is the caller's
job and is not implemented anywhere yet.

**G10 — Single target per manifest, and the target is not cross-checked.** `target: P1` is parsed
and printed but the program cannot know which path the caller will actually deploy to. A manifest
signed for `P1` presented to a `P4` deploy job is refused by nothing here. The deploy job must
compare.

**G11 — No replay window beyond expiry.** Nothing prevents the same manifest and signatures being
presented repeatedly inside `[execute_after, expires_at)`. For an idempotent deploy of a fixed
digest this is intended; if a deploy is not idempotent, the caller needs its own once-only record.

**G18 — Emptying the environment is permanent, process-global, and must stay that way.** `Verify`
replaces `environ` on its first call and never restores it. That is a deliberate choice, and the
third audit was right to flag it and right to warn against "fixing" it: the invariant is *no child
of this process ever receives an environment*, and it is only unconditional while it is
irreversible. A save-and-restore around each spawn would preserve the guarantee for the spawns this
package performs today while leaving a window in which any later code path — a future addition, an
exception path, a library — spawns with the attacker's environment intact. The failure mode of
clearing permanently is that a host application embedding `Edge` loses its environment: loud,
immediate, and caught the first time anyone tries. The failure mode of restoring is a silent
bypass. Nothing in this program reads an environment variable after verification, so for this CLI
the cost is zero.

The consequence is a constraint, and it is the same constraint as G2 and the reason `Unseal` exists:
**`Edge` is a single-shot boundary, not a library.** Embedding it in a long-lived host means
revisiting this and the descriptor ownership together. A `pragma Assert` immediately before the
spawn checks the invariant at the only point it can be violated, so it holds independently of the
test suite — deleting the environment test cannot quietly remove the guarantee, though a build
without `-gnata` drops the check while keeping the fix.

**G16 — Emptying the environment is not the same as a clean environment.** `Verify` replaces
`environ` before the first spawn, which closes the `LD_PRELOAD` path. It does not and cannot
address a compromised dynamic linker, a modified `/usr/bin/ssh-keygen`, or a hostile
`/etc/ld.so.preload`, all of which need root and are out of scope (§3 item 10). Running the gate
in a platform-controlled minimal environment is still the right operational posture; this is
defence in depth, not a substitute for it.

**G17 — `test/mutants.sh` and `test/run.sh` are the validation, and validation scripts are code.**
`mutants.sh` now copies the tree into a `mktemp -d` and mutates only that copy, so it can run
concurrently with `run.sh` in one checkout and a killed run cannot leave a `Threshold` of 1 in the
working tree (audit R1). Verified by running both concurrently and confirming `src/` is
bit-identical afterwards. But nothing checks that the copy is complete: a source file added to the
project and not to the `cp -R` list would be silently taken from the pristine tree.

**G13 — Sealing depends on `mkstemp` succeeding in `/tmp`.** If `/tmp` is unwritable or full,
`Seal` fails and the program refuses — fail-closed, but a denial-of-service on releases. The
template directory is hardcoded rather than taken from `TMPDIR`, because the threat model grants
the attacker the environment. `O_EXCL` means an attacker cannot pre-create the path or aim it
elsewhere; the worst they achieve by filling `/tmp` is refusal. The sealed bytes are public keys
and a manifest, so their brief presence on disk leaks nothing.

**G14 — Sealing depends on `/dev/fd/N` resolving in the child.** OpenSSH has no way to take an
allowed-signers file descriptor, so the seal is named to it as `/dev/fd/N`. This was verified
empirically on macOS against an unlinked file, and works via `/proc/self/fd` on Linux. On a
platform without `/dev/fd`, every verification fails and every release is refused. That is the
right direction to fail, but it is a portability cliff and it is not covered by the proof.

**G15 — Sealing depends on descriptor inheritance across `Spawn`.** The sealed descriptors must
survive into the child with the same numbers. GNAT's `Spawn` does not set `FD_CLOEXEC` and does not
close descriptors, so they do. If a future runtime changed that, `/dev/fd/N` would resolve to
nothing in the child and everything would refuse. Again fail-closed, again invisible to the proof.

**G12 — `Refuse_Manifest` and `Refuse_Roster` do not say what was wrong.** Deliberate — a parser
that explains itself to an attacker is an oracle — but it costs debugging time, and the tests are
where the intended rejections are documented.

## 12. Where to attack it

If the goal is to find a flaw, these are the places worth the time, in order:

1. **`Parse_Manifest`'s offset arithmetic** (`quorum.adb:172-234`). Every constant in the §6.1
   table is hand-derived. An off-by-one that made two fields overlap, or that let the author slice
   extend into a timestamp, would be a real break. The proof establishes that no index is out of
   bounds; it does **not** establish that the offsets describe the intended grammar. That
   correspondence is checked only by the 19 manifest tests.
2. **`Epoch`** (`quorum.adb:92-107`). Same argument: proved not to overflow, not proved to be the
   correct calendar. If `Before_Month` or the leap adjustment were wrong, guards 4–6 would compare
   wrong numbers and the proof would not notice. Attack the leap-year adjustment across a February
   boundary and across a year boundary.
3. **`Parse_Roster_Line`'s space counting** (`quorum.adb:236-297`). The "exactly two spaces" rule
   is what excludes the options and comment fields. Tabs are not spaces — is a tab reachable? It
   is not, because the principal, algorithm and base64 character classes exclude it, but check
   that reasoning rather than trusting this sentence.
4. **The seal.** This is new code and it is where the last critical bypass lived, so it deserves
   the most suspicion. Establish that no path names the sealed bytes after `Seal` returns; that the
   `lseek` before each spawn is sufficient given that `/dev/fd/N` shares the file offset on macOS;
   that a failed `mkstemp`, `unlink`, `write`, `lseek`, `dup` or `dup2` cannot produce `Ok = True`;
   and that nothing between the parse and the seal can substitute the buffer contents. Then ask the
   question the audit asked and this design has to keep answering: **is there any remaining path
   from an attacker-controlled name to the bytes OpenSSH actually verifies?**
5. **The `Refuse_Author` comparison.** It compares the manifest's author *name* to roster
   principals. Two humans with confusable principals, or a roster entry whose principal does not
   correspond to the human the commit is attributed to, would defeat it. The binding between a git
   author identity and a roster principal is a convention, not a check.
6. **`Is_Revoked`'s fail-closed direction** (`quorum.adb:337-364`). Confirm there is no input for
   which a malformed list returns `False`.
7. **The `Consistent` invariant across `Attribute_One`.** Its postcondition is *assumed*, not
   proved, because the body is outside SPARK. Read `Attribute_One` and check the assumption holds.
8. **The order of guards in `Decide`.** Confirm that no reordering could make the postcondition
   provable while allowing a release that should be refused. (It cannot — the postcondition is a
   conjunction — but the argument is worth reconstructing.)

Places not worth the time **in `quorum.ads`/`quorum.adb`**, because the proof closes them there:
buffer overruns, integer overflow, uninitialised reads, unbounded loops, and any input-dependent
crash. That exemption stops at the SPARK boundary, and the 2026-09-02 audit is the demonstration —
it found a one-byte out-of-bounds write in `edge.adb`, thirty lines from a package that had 241
checks proved. **In `edge.adb` and `main.adb`, assume nothing.**

## 13. Change control

If any of the following changes, the proof and the tests must both be re-run, and the §4
postcondition re-read:

- any constant in `quorum.ads:8-15`, especially `Threshold` and `Min_Delay_Hours`;
- the compiler switches in `quorum.gpr`. **`-gnata` is not optional in either mode**: `Decide`'s
  precondition, `Read_File`'s postcondition and the environment invariant in `Verify` are all
  runtime-checked, and a build without it looks identical while dropping all three. `run.sh` fails
  if the binary carries no sign of them. The `release` mode adds `-Os` and section stripping, which
  takes the binary from 573 KB to 153 KB after `strip -x` and changes nothing that is checked;
- the accepted algorithm list (`quorum.adb:36-37`) — adding a non-`sk-` algorithm silently
  removes the hardware requirement, which no test outside `roster: rejects a software key` would
  catch;
- the manifest grammar — every offset in §6.1 is coupled to every other;
- `Epoch`'s range bound, if the year range is widened past 2099;
- the `ssh-keygen` invocation, particularly the `-n ns-release` namespace: signatures made under
  one namespace must never verify under another, and changing it invalidates every existing
  signature;
- anything in `Seal` or `Verify`. These are the boundary between a name an attacker may control and
  the bytes OpenSSH verifies, and that boundary is where every critical finding so far has been;
- the `cp -R` list in `test/mutants.sh`, if a source file is added to the project (G17).

`./test/run.sh` runs the build, the proof and every test in one command, so there is no separate
proof step to forget. CI should run exactly that.

## 14. Implementation choices

### Why Ada/SPARK

The selection brief was maximum security, formal verification, low maintenance, and resistance to
supply-chain attack. The absence of a dependency graph is decisive: SPARK has no package manager,
lockfile, vendored source, or build step that fetches anything. The trusted supply chain is the GNAT
compiler/runtime and OpenSSH, both already required by the release path.

The security policy is `Decide`'s postcondition in the same source as the implementation, so it
cannot drift into a separate model. GNATprove discharges it on every proof run and also proves
absence of runtime errors and termination for the core. Ada's stability and the maturity of SPARK
tooling—developed for flight software—support the low-maintenance requirement.

Alternatives were rejected as follows:

- **Rust** is memory-safe but not verified at the code level with mature tooling here, and Cargo
  introduces the dependency graph this design excludes. A zero-dependency `no_std` core narrows the
  gap but does not eliminate the package/lockfile layer.
- **Python** has no proof story and a large C interpreter in the trusted base.
- **C with Frama-C/ACSL** can be proved, but opam adds a dependency graph and hand-written untrusted
  input parsing remains high-risk.
- **F\*/Low\*** is strong for crypto but inappropriate for this non-crypto control and too costly to
  maintain.
- **Coq/Lean with extraction** moves trust into the extracted runtime and deployment gap.
- **Go, Zig, and TypeScript** lack the required formal-verification story and module supply chains.
- **Shell** delegates crypto correctly but cannot express or carry this proof reliably.

The accepted cost is maintainability risk: the team does not normally write Ada. That is tolerable
only because the implementation is small, stable, and readable. If it grows materially, revisit the
choice.

### Core design choices

- Signer identity is indexed by roster enrolment slot, so duplicate signatures from one holder cannot
  count as two signers.
- The roster admits only `sk-ssh-ed25519@openssh.com` and
  `sk-ecdsa-sha2-nistp256@openssh.com`, enforcing hardware-key provenance at enrolment rather than by
  parsing signature blobs.
- The delay is compiled in and enforced in both directions: the signed interval from `signed_at` to
  `execute_after` must be at least 24 hours, and the current time must be at or after
  `execute_after`. No flag can shorten it.
- Manifests and rosters use fixed byte layouts instead of YAML or JSON, eliminating duplicate keys,
  reordering, aliases, Unicode confusion, and coercion as parser attack surface.
- OpenSSH is invoked by absolute path with an argument vector, without a shell, and only its exit
  status is consumed.
