# quorum adversarial audit

**Scope:** `experiments/quorum`
**Date:** 2026-09-02
**Initial result:** **not bulletproof.** One critical policy bypass and two memory-corruption bugs were confirmed by executable tests. A fourth, more severe manifest-race bypass was then found while reproducing A1. All four were subsequently fixed; see §“Response” and §“Re-audit” for current status.

## Executive summary

The SPARK core is strong, but `Edge` and `main` violate the assumptions the core relies on. `main` parses one set of files and then asks `Edge.Verify` to reopen the same paths. An attacker with CI working-directory write access—which the threat model explicitly grants—can replace the roster between parse and verification. This defeats the hardware-key, distinct-signer, and author guards at once: the program attributes software-key signatures to roster slots, verifies signatures against a swapped file, and returns `Allow`.

Separately, `Edge.Read_File` passes `Buf'Length + 1` to `read(2)`. On the built `main` stack, that writes one attacker-controlled byte outside the roster buffer into the already-loaded manifest, and one byte outside the cancellation buffer into the already-loaded roster. Today's subsequent checks fail closed, but the writes are real and stack-layout dependent.

## Findings

### A1 — Roster replacement bypasses the entire 2-of-3 policy

**Severity: Critical**

**Location:** `src/main.adb:65` parses the roster; `src/edge.adb:101` and `src/edge.adb:114` reopen it during signature verification.

**Root cause:** The roster is read by name once into `Roster_Buf`, parsed into `R`, and then every signature is verified by reopening `Roster_Path` from disk. Nothing re-reads the roster after the decision, but it *is* re-read between the decision's inputs and the cryptographic verification that establishes those inputs. The spec's claim that "nothing downstream re-reads a file by name after a decision has been made about its contents" is therefore misleading: the decision inputs are built from a later read, and that read is attacker-raceable.

**Exploit:**

1. Start with a valid sk-* roster containing principals `alice@ns.com`, `bob@ns.com`, and `carol@ns.com`.
2. Let `main` read and parse that roster.
3. Before signature verification begins, replace the roster file with one using the same principal names but attacker-controlled software keys.
4. Present signatures from two attacker-controlled software keys, one attributed to `alice@ns.com` and one to `carol@ns.com`.
5. Keep the manifest author as `bob@ns.com`.

**Expected result:** Refuse. No hardware key has signed anything, and the parsed roster did not contain the attacker keys.

**Observed result:** `Allow`. The signatures are attributed to roster slots 1 and 3 because `ssh-keygen -Y verify` uses the swapped roster file. `Decide` sees two distinct slots, three enrolled principals, and no signed author. It returns `Allow`.

**Test:** `test/harness.adb` — `Reopen_Race` → `race: a swapped roster does not enrol attacker keys`

**Fix:** Open the roster once, hold the file descriptor open, and pass that descriptor to `ssh-keygen` verification. OpenSSH does not accept an allowed-signers file descriptor directly, so a robust fix requires either:

1. locking the roster file with `flock` and verifying no inode/stat change occurs across the window; or
2. writing a private, mode-0600 copy of the parsed roster bytes to a secure temporary file, verifying signatures against that copy only, and refusing if the original file changes before, during, or after verification; or
3. extending `Edge.Verify` to accept a byte array and constructing the allowed-signers input from those exact bytes in a private file.

Do not simply re-read and compare before calling `ssh-keygen`; that leaves the same race between comparison and verification. The verifier must consume the same bytes that were parsed, with no second lookup by path.

### A2 — Attacker-controlled byte written past the roster buffer

**Severity: High**

**Location:** `src/edge.adb:42` — `Read (Fd, Buf'Address, Buf'Length + 1)`.

**Root cause:** `Buf` has exactly `Max_Roster` bytes, but `read(2)` is allowed to write `Max_Roster + 1` bytes. In the built binary's stack layout, `Roster_Buf` ends immediately before `Manifest_Buf`. A 4097-byte roster therefore writes the 4097th byte into `Manifest_Buf (1)`.

**Reproduction:** `test/harness.adb` — `Redzone` → `redzone: an oversized roster leaves the manifest parseable`.

**Expected:** `Read_File` must not write outside `Buf`.

**Observed:** the first manifest byte changes from `n` to the roster's 4097th byte (`1` in the fixture).

**Impact:** Currently mitigated by later failure: the 4097-byte roster is refused, and in the observed stack layout the manifest corruption also prevents a valid allow. This is nevertheless an out-of-bounds write in trusted code, and stack layout is not a security boundary. A different build can place a return address, saved register, length, or another control value at `Buf'Length + 1`.

**Fix:** pass `Buf'Length` to `read(2)`. To preserve the intended “file filled the buffer exactly” refusal without an overflow, read `Buf'Length` bytes and, if `N = Buf'Length`, issue a second one-byte read into a single local byte. Reject if the second read returns any byte.

### A3 — Attacker-controlled byte written past the cancellation buffer

**Severity: High**

**Location:** `src/edge.adb:42`, called from `src/main.adb:53`.

**Root cause:** The same `Buf'Length + 1` read length is used for `Cancel_Buf`. On the built binary's stack layout, the byte after `Cancel_Buf` is `Roster_Buf (1)`. A 4097-byte cancellation list writes its final byte into the first roster byte.

**Reproduction:** `test/harness.adb` — `Redzone` → `redzone: an oversized cancellation list leaves the roster valid`.

**Expected:** `Read_File` must not write outside `Cancel_Buf`.

**Observed:** the first roster byte changes from `a` to `1`, making the parsed roster invalid.

**Impact:** Same as A2. The program refuses because the oversized cancellation list is rejected, but the write itself occurs first. This is another stack-layout-dependent out-of-bounds write.

**Fix:** same as A2. The `+1` probe must go into a separate one-byte buffer, never into `Buf'Length + 1`.

## What the proof does and does not cover

The SPARK core still proves the intended policy for the values it is given: 241 checks pass, with no unproved checks. This does not protect against these findings because:

1. `main` and `Edge` are outside the proof.
2. `Edge.Verify`'s precondition—that the roster used for verification is the same roster passed to `Decide`—is not stated or checked anywhere.
3. `Read_File` writes through `Address` into an external buffer, so the proof cannot see the actual read length or the resulting memory write.

These are exactly the gaps the project already calls out in `SPEC.md` §11 G2, but the severity is higher than that framing suggests: the roster reopen race is a complete policy bypass under the threat model, not merely residual risk.

## Test results

The audit suite adds:

1. `Reopen_Race` — deterministic manifest and roster replacement between parse and verify.
2. `Redzone` — exact-size boundary probes that place a parsed value immediately after each oversized input.

Current result:

```text
FAIL race: a swapped roster does not enrol attacker keys
FAIL redzone: an oversized roster leaves the manifest parseable
FAIL redzone: fixture roster is valid
FAIL redzone: an oversized cancellation list leaves the roster valid

68 passed, 4 failed
```

`redzone: fixture roster is valid` fails as a direct consequence of A3: the cancellation-list overflow corrupts the roster that the test had already parsed.

## Recommended fixes, in order

1. **Fix the roster reopen race.** The bytes used to verify signatures must be the exact bytes parsed into `R`, with no second path-based lookup. This is the critical finding.
2. **Fix `Read_File`'s `+1` read length.** Read into the buffer, then probe for one additional byte into a separate local variable.
3. **Remove the misleading spec claim.** `SPEC.md` currently says nothing downstream re-reads a file by name after a decision has been made; the roster is in fact reopened during input construction. Update the spec to state the actual invariant once fixed.
4. **Do not trust “regular file” as a TOCTOU defense.** A regular file can be replaced by another regular file. Holding a descriptor open or using a locked, private copy is what removes the race.
5. **Check `C_Dup` and `C_Dup2` return values.** `SPEC.md` already flags this; it remains a real failure path and should be fail-closed.

## Things that resisted attack

The following attacks were attempted or reviewed and did not produce a bypass on their own:

1. A 512-byte manifest does not trigger A2/A3 because the manifest buffer is the first buffer read and the overflow lands in another local variable in the observed build.
2. A malformed or absent cancellation list fails closed.
3. Duplicate roster principal names are rejected by `Parse_Roster`.
4. Manifest fields are fixed-width and cannot be shifted into one another by the tested mutations.
5. Signatures over a different manifest fail when no race occurs.

None of these positive results reduce the impact of A1–A3.

---

# Response — 2026-09-02, after the audit

**All three findings were reproduced and fixed. A fourth, more severe variant of A1 was found while
reproducing it.** Current result: **85 tests pass, 0 fail** (77 in the harness, 8 black-box), and
`Success: all checks proved (241 checks)` still holds. The audit was correct on every point,
including that the spec's own re-read claim was misleading.

## A0 — Manifest replacement authorises a manifest nobody signed (found while reproducing A1)

**Severity: Critical. Higher impact than A1**, because it needs no attacker key material at all —
only two genuine signatures over any manifest that ever existed, plus the same file swap A1 needs.

A1's test swapped the manifest so that verification saw *different* bytes from the ones parsed,
which fails safely: the signatures no longer verify. The direction that pays is the reverse. The
attacker puts the manifest they want shipped at the path, lets `main` parse it, and then swaps in
the manifest that two enrolled holders really did sign. `ssh-keygen` verifies happily against the
genuine bytes; `Decide` authorises the parsed ones.

Reproduced before any fix, with the pre-fix code:

```text
FAIL race2: a manifest nobody signed is not authorised
```

`test/harness.adb` — `Manifest_Race`.

## Fixes

**A0 and A1 — sealed bytes.** `Edge` gained a private `Sealed` type. `Seal` copies bytes into a
file created with `mkstemp` (`O_CREAT | O_EXCL`, mode 0600), **unlinks it immediately**, and keeps
the descriptor. From that moment no path in the filesystem names those bytes, so nothing can
substitute them. `Verify` now takes two `Sealed` values instead of two paths: the message is fed to
`ssh-keygen` by `dup2`-ing the sealed descriptor onto standard input, and the roster is named as
`/dev/fd/N`, which OpenSSH accepts for `-f` (verified empirically on an unlinked file before the
design was committed). `main` seals the exact slices it parsed, from the same buffers.

The audit's option 2 was a private mode-0600 copy plus a change check; sealing is strictly
stronger, because there is no name left to check. Its option 1, `flock` plus a stat comparison, was
rejected for the reason the audit gives about option "re-read and compare": any scheme that
validates a path still races the use of that path.

`Sig_Path` is deliberately still a path, and this is now stated in `src/edge.ads`. A substituted
signature file gains nothing: whatever it contains must still verify against the sealed roster over
the sealed message.

**A2 and A3 — bounded read.** `Read_File` now loops with a count of at most `Buf'Length - Total`,
and detects oversize with a separate one-byte read into a local `Probe`. The `+ 1` is gone.

**Audit item 5 — `C_Dup` / `C_Dup2` return values** are now checked. A failed `dup` or `dup2`
returns a refusal; a failure restoring standard input after the spawn forces the exit code to `-1`
so the verification cannot be reported as successful.

## Evidence that the new tests are witnesses, not decoration

The audit's `Redzone` relied on two locals happening to be adjacent on the stack, which the audit
itself notes is not a security boundary — and one of its four assertions
(`redzone: an oversized roster leaves the manifest parseable`) could not have passed even after a
correct fix, because it re-parsed a 13-byte slice.

The replacement takes a single `String (1 .. Max_Roster + 8)`, passes `Arena (1 .. Max_Roster)` to
`Read_File`, and checks the eight following bytes. Slices of one `String` are contiguous by
definition, so adjacency is guaranteed by the language rather than observed in one build. Spliced
against the original `Read_File` from commit `34a8267`, it fails exactly as it should:

```text
FAIL redzone: nothing is written past the roster buffer
FAIL redzone: nothing is written past the cancellation buffer
 75 passed, 2 failed
```

and passes after the fix. `test/mutants.sh` gained two entries covering the same code, and
`test/fixtures.sh` was factored out of `run.sh` so the mutation run uses identical fixtures.

## Spec corrections

`SPEC.md` §5 claimed "nothing downstream re-reads a file by name after a decision has been made
about its contents." That was false, and the audit is right that it was the misleading sentence
that hid A0 and A1. It now states the invariant that actually holds and names the mechanism that
enforces it. Three new gaps (G13–G15) record what sealing itself depends on: `mkstemp` in `/tmp`,
`/dev/fd/N` resolution, and descriptor inheritance across `Spawn`.

## What remains open

G1 is unchanged and is still the largest gap: **no `sk-*` signature from real hardware has been
through this program.** The audit did not test that either, and it cannot be tested without a
physical touch.

---

# Third audit — 2026-09-02

**Result: R1, R2, and R3 are fixed. No new policy bypass found.**

## R1 — mutation isolation: fixed

`test/mutants.sh` now copies `src/`, `test/`, and both project files into a private temporary
workspace before mutating anything. This closes both parts of the hazard:

1. a `SIGKILL` can no longer leave weakened source in the real working tree;
2. it no longer shares `src/` or object directories with `test/run.sh`.

Verified concurrently in the same checkout:

```text
run=0 mutants=0
Success: all checks proved (241 checks)
80 passed, 0 failed
8 passed, 0 failed
all mutants caught
```

After both runs, `git diff --exit-code -- quorum/src` was clean. G17 remains accurate: if a source
or test file is added without extending the copy list, a future mutant run could silently omit it.
This is a maintainability gap, not a release-policy bypass.

## R2 — descriptor release: fixed

`Edge.Unseal` closes a positive descriptor and sets it to `-1`. `main` unseals both descriptors
after the decision, and the harness unseals its fixtures after use. The additional test matters:
`Verify` refuses a negative descriptor, so use-after-unseal cannot be confused with successful
verification. This is the right fail-closed semantics.

The type remains non-controlled. That is appropriate for this single-shot CLI: ownership is local,
no exceptions propagate through `main`, and explicit unseal is easier to audit than implicit
finalization. Do not reuse `Edge` in an exception-heavy or long-lived service without revisiting
that ownership model.

## R3 — child environment: fixed

`Verify` calls `Drop_Environment` before any child can exist. The implementation replaces the C
`environ` symbol with a single null-pointer block, which is the representation `execv` passes to
`execve`. An empty environment is stronger and more future-proof than a loader-variable denylist,
and nothing in this program requires an inherited variable.

The regression test checks the parent had an environment before the first verification and none
after it. A mutant that removes the call is caught. macOS cannot reproduce the original `LD_PRELOAD`
attack against Apple-signed `/usr/bin/ssh-keygen`, so this is the strongest locally falsifiable
test; the actual injection case remains Linux validation work.

G16 correctly records the limits: replacing `environ` cannot neutralize a compromised linker or
`/etc/ld.so.preload`, both of which already require root and remain out of scope.

## Residual observations

1. **No new confirmed vulnerability.**
2. **`Drop_Environment` is irreversible and process-global.** In this CLI, that is intentional:
   once a child can be spawned, every later child must see the same empty environment. Nothing after
   verification needs an environment variable. If `Edge` is ever embedded in a host application that
   needs its environment preserved, this design must be revisited; do not silently restore `environ`.
3. **G1 remains open:** no real `sk-*` signature has yet passed through the program. Run
   `./test/bench-sk.sh` at the machine with the enrolled key before promoting this to a live gate.

---

# Re-audit — 2026-09-02

**Result: no remaining confirmed policy bypass in the sealed path.**

The four original findings are closed:

1. **A0 and A1 are closed.** `main` now seals the exact parsed manifest and roster slices, and
   `Verify` consumes only those descriptors. Swapping either path after parse no longer changes the
   bytes OpenSSH verifies. Both race tests cover the profitable direction, and `Manifest_Race`
   specifically proves that a genuinely signed manifest cannot authorize a different parsed manifest.
2. **A2 and A3 are closed.** `Read_File` never passes `read(2)` a count larger than the buffer. The
   fence test uses a single `String`, so contiguity is guaranteed by Ada rather than by a compiler's
   stack layout, and it covers roster, cancellation, and exact-fit cases.
3. **`C_Dup` and `C_Dup2` failures now fail closed.**
4. **The spec now states the real invariant:** the bytes OpenSSH verifies are the bytes the core
   parsed. G13–G15 record the sealing dependencies.

Validation performed:

```text
Success: all checks proved (241 checks)
77 passed, 0 failed    # harness, including real signatures and race regressions
8 passed, 0 failed     # binary
all mutants caught      # six mutants
```

## R1 — Validation commands mutate shared build trees and are unsafe to run concurrently

**Severity: Medium (operational).**

`test/run.sh` and `test/mutants.sh` both build into `obj/` and `obj-test/` and mutate `src/`.
Running them concurrently corrupts the other run's objects. In this re-audit, a concurrent run
produced a false GNATprove timeout on `Signed_By_Author` and a false harness postcondition failure;
a clean sequential rerun passed all 85 checks and all 241 proof checks.

This is not a runtime vulnerability in `quorum`, but it is a CI hazard: a parallel matrix job can
report false failures or, worse, mask a real one. Do not run the two scripts concurrently in the same
checkout. If CI uses parallel jobs, give each job its own checkout, or serialize them with a
workspace lock.

## R2 — `Sealed` has no explicit release path and leaks descriptors

**Severity: Low in the current single-shot CLI; Higher if reused in a service.**

`Sealed` stores a raw descriptor, `Seal` never closes it on success, there is no `Close` procedure,
and the private type is not controlled. `main` therefore leaks two descriptors until process exit.
The harness leaks more because it creates several seals per run.

For this CLI, process exit is a complete cleanup boundary and the leak is bounded. It becomes a real
resource-exhaustion issue if `Edge` is reused in a long-lived process or called repeatedly in a
library context. Add an explicit `Close_Sealed` (or make `Sealed` a `Limited_Controlled` type and
close it in `Finalize`) before any such reuse. An explicit close is also clearer and easier to audit
than implicit finalization.

## R3 — The threat model says the attacker controls the environment, but `Spawn` inherits it

**Severity: High on Linux CI unless the environment is constrained; mitigated on current signed
macOS system binaries.**

`GNAT.OS_Lib.Spawn` does not provide a sanitized environment. The child therefore inherits the
caller's environment, including `LD_PRELOAD` on Linux. On macOS, current Apple-signed runtime
binaries such as `/usr/bin/ssh-keygen` restrict dynamic-library injection, but that is an OS/build
property, not a property of this program. The spec explicitly grants the attacker CI workflow and
environment control, so on an unrestricted Linux runner an attacker can alter the verifier's process
environment.

This is adjacent to the spec's declared out-of-scope item “compromise of OpenSSH,” but it is not the
same: it does not require compromising OpenSSH's source or binary. It requires only an inherited
loader variable in a trusted-looking child.

Recommended controls:

1. Execute the deploy gate in a minimal, fixed environment produced by the platform, not by the
   attacker-controlled workflow.
2. On Linux, unset `LD_PRELOAD`, `LD_LIBRARY_PATH`, and other loader/plugin variables before
   spawning the verifier; use a POSIX `execve` wrapper with an empty or allowlisted environment.
3. Prefer a direct `fork`/`execve` boundary that constructs the child environment explicitly.
4. Do not document “no environment variables” while using an inherited-environment `Spawn`; that
   phrase currently means “the decision core does not read one,” not “the child cannot be affected
   by one.”

---

# Response to the re-audit — 2026-09-02

**All three findings accepted. R3 and R1 are fixed rather than documented; R2 is fixed.** Current
result: **88 tests pass, 0 fail** (80 in the harness, 8 black-box), `Success: all checks proved
(241 checks)`, and **seven** mutants caught.

## R3 — inherited environment: fixed

The re-audit is right, and its fourth recommendation is the sharpest point in either report: this
project had been writing "no environment variables" to mean *the decision core reads none*, while
the child inherited everything. Those are different claims and only one of them was true.

`Verify` now replaces `environ` with an empty block before any child can exist. That is what
`execv` passes to `execve` on both glibc and Darwin, so the child gets no environment at all —
no `LD_PRELOAD`, no `LD_AUDIT`, no `DYLD_*`, and nothing that a future loader adds either, which
is why an empty environment was chosen over unsetting a denylist. This program reads no
environment variable, so there is nothing to preserve. Recommendation 3, a `fork`/`execve` wrapper
with an explicit environment, would be equivalent; replacing `environ` achieves it without
reimplementing `Spawn`.

Recommendation 1 — run the gate in a platform-controlled minimal environment — still stands as the
operational posture, and is now recorded as **G16** together with what emptying the environment
does *not* cover: a compromised dynamic linker, a modified `ssh-keygen` binary, or
`/etc/ld.so.preload`, all of which need root and are already out of scope.

The regression test asserts the parent has an environment before the first verification and none
after it. It deliberately does not attempt to demonstrate an injection, because macOS will not
permit one against a signed system binary and a test that cannot fail on the development machine
is not a test. A mutant that removes the call is caught.

## R1 — shared build trees: fixed, and the worse hazard closed

`test/mutants.sh` now copies the project into a `mktemp -d` and mutates only that copy. `src/` is
never touched.

The concurrency problem is real and is fixed — both scripts were run simultaneously in one
checkout and both passed, with `src/` bit-identical afterwards. But the reason to fix it this way
was the hazard the finding understated: the previous version mutated `src/` in place and restored
on an `EXIT` trap, so a `SIGKILL` between the mutation and the restore left a `Threshold` of 1, or
a `Min_Delay_Hours` of 0, sitting in the working tree of a security control — one `git commit` away
from being real. Working on a copy removes that entirely rather than narrowing the window.

Recorded as **G17**, with the residual: nothing checks that the `cp -R` list is complete, so a
source file added to the project and not to that list would be silently taken from the pristine
tree.

## R2 — descriptor leak: fixed

`Edge.Unseal` closes the descriptor and resets the field to `-1`. `main` calls it after the
decision; the harness calls it in `Plumbing` and `Run_Pipeline`. An explicit close was chosen over
`Limited_Controlled` for the reason the finding gives — it is easier to audit — and because a
controlled type in the `Edge` boundary would add finalization semantics to the one package that
should stay dull.

A test now verifies the other half of this, which the finding did not ask for but which matters
more: **an unsealed descriptor fails closed.** `Unseal` sets `Fd` to `-1`, and `Verify` refuses on
a negative descriptor, so a use-after-unseal cannot be mistaken for a successful verification.

## Standing

Six defects have now been found in this program by audit. **All six were in the 431 lines outside
SPARK; none were in the 561 inside it, which have never needed a correction.** The right conclusion
is not that the proof is worth little — it is that the proof holds and the boundary is where the
bugs live, so that is where review time belongs. `SPEC.md` §12 is ordered on that basis.

G1 remains the largest open gap: no `sk-*` signature from real hardware has been through this
program. `./test/bench-sk.sh` closes the single-signature half of it with one touch of the
`sk-ecdsa-sha2-nistp256@openssh.com` key already in use on this machine for git commit signing.
Neither audit tested that either, and neither could.

---

# Response to the third re-audit — 2026-09-02

Nothing to fix. The one substantive item is residual observation 2, and it changed my mind.

## On `Drop_Environment` being irreversible

**I was about to add a save-and-restore around the spawn, and the audit talked me out of it.** The
instinct was that an irreversible process-global side effect is poor form, and that scoping it to
the window where a child can exist would keep the same guarantee with no collateral damage. The
audit's "do not silently restore `environ`" is the better argument, and the reason is the asymmetry
of the two failure modes.

Restoring preserves the guarantee only for the spawns this package performs *today*. It leaves a
window in which any later code path — a new feature, an exception path, a library someone links —
spawns a child with the attacker's environment intact, and that failure is silent. Clearing
permanently can only break a host application that embeds `Edge` and needs its environment, which
fails loudly and immediately the first time anyone tries it. A loud availability failure in a reuse
that does not exist beats a silent security failure in a plausible edit.

It is also the consistent answer. R2's disposition already established that `Edge` is a single-shot
boundary and not a library, and that reuse in a long-lived process needs the descriptor ownership
revisited. The environment is the same constraint, so it is recorded the same way rather than
engineered around: **G18**, cross-referenced to G2 and to `Unseal`.

Two changes, neither of them behavioural:

1. The rationale is now in `src/edge.adb` at the declaration, addressed to whoever next has the
   instinct I had, and says plainly not to add a restore.
2. `pragma Assert (Environ = Empty_Env'Address)` sits immediately before `Spawn` — the only point
   the invariant can be violated. It fires at `edge.adb:278` under the R3 mutant, *before* the
   harness's own environment check runs, so the guarantee no longer depends on a test existing.
   Verified by applying the mutant: `raised ADA.ASSERTIONS.ASSERTION_ERROR : edge.adb:278`. A build
   without `-gnata` drops the check while keeping the fix.

## Standing

Six findings across three audits, **all six in the 431 lines outside SPARK and none in the 561
inside**, which have never needed a correction. 241 proof checks, 88 tests, seven mutants.

G1 is the only open gap that matters: no `sk-*` signature from real hardware has been through this
program, and no audit could test it. `./test/bench-sk.sh` closes the single-signature half with one
touch of the key already used here for commit signing. **Do not promote this to a live gate before
that runs.**

---

# Fourth audit — 2026-09-02

**Result: nothing to fix.**

The decision not to restore `environ` is correct. The security boundary is global and temporal:
once this process can create children, no later child may inherit an attacker-controlled
environment. Save-and-restore would narrow that invariant to the current call sites and turn any
future spawn into a silent bypass. Permanent clearing instead makes any embedding conflict fail
loudly and immediately. That is the preferable failure mode.

The source rationale is explicit and resists the likely “cleanup” refactor (`src/edge.adb:42`). The
pre-spawn assertion checks the invariant at the only point a child can be created
(`src/edge.adb:278`). An independent isolated R3 mutant was applied and reproduced:

```text
mutant_rc=1
raised ADA.ASSERTIONS.ASSERTION_ERROR : edge.adb:278
```

Thus the guarantee fails before any child exists and before the harness test can mask its absence.
The limitation is accurately documented: builds without `-gnata` omit the assertion but retain the
fix.

Full validation:

```text
Success: all checks proved (241 checks)
80 passed, 0 failed    # harness
8 passed, 0 failed     # binary
all mutants caught      # seven mutants
```

No new finding. G1 remains the only deployment blocker requiring physical key interaction.
