--  The boundary with the untrusted world: the filesystem, the clock, and
--  OpenSSH. The body is deliberately outside SPARK; this spec is the contract
--  the proved core is entitled to assume, and everything it assumes is listed
--  in README.md under "What is trusted".

with Quorum;

package Edge
  with SPARK_Mode,
       Abstract_State => (World with External),
       Initializes    => World
is

   procedure Read_File
     (Path : String; Buf : out String; Last : out Natural; Ok : out Boolean)
   with Global => (In_Out => World),
        Post   => (if Ok then Last <= Buf'Last and then Last >= Buf'First - 1);
   --  Regular files only: a symlink, a directory or a FIFO is refused, because
   --  a control file that can be repointed between two reads is not a control.
   --  Never passes read(2) a count larger than Buf; oversize is detected by a
   --  separate one-byte probe.

   procedure Get_Now (T : out Quorum.Timestamp; Ok : out Boolean)
   with Global => (In_Out => World),
        Post   => (if Ok then Quorum.Valid (T));
   --  UTC, from the system clock. There is no override: no flag, no
   --  environment variable. A caller that can choose "now" can retire the
   --  queue delay and resurrect an expired authorisation.

   -----------------------------------------------------------------------
   --  Sealed bytes
   --
   --  A Sealed holds a copy of bytes that no filesystem path refers to any
   --  more: the copy is created, written, and unlinked immediately, so the
   --  descriptor is the only reference to it in the system. Handing OpenSSH a
   --  Sealed rather than a path is what makes the bytes it verifies the same
   --  bytes the core parsed. A path can be replaced between the parse and the
   --  verification; an unlinked inode we hold open cannot.
   -----------------------------------------------------------------------

   type Sealed is private;

   procedure Seal (Content : String; S : out Sealed; Ok : out Boolean)
   with Global => (In_Out => World);
   --  Seal must be given the same slice that was parsed, from the same buffer.
   --  Re-reading the path to seal it would reintroduce exactly the race this
   --  type exists to remove.

   procedure Unseal (S : in out Sealed)
   with Global => (In_Out => World);
   --  Release the descriptor. Process exit is a complete cleanup boundary for
   --  a single-shot CLI, so this exists for the case where Edge is reused in
   --  something longer-lived, where leaking two descriptors per decision is a
   --  resource-exhaustion bug rather than a rounding error.

   procedure Verify
     (Sig_Path  : String;
      Roster    : Sealed;
      Message   : Sealed;
      Principal : String;
      Ok        : out Boolean)
   with Global => (In_Out => World);
   --  ssh-keygen -Y verify, by exit status only. No output is parsed, no PATH
   --  is resolved, no shell is involved, and no cryptography is reimplemented
   --  here: OpenSSH is already the root of trust for commit signing.
   --
   --  Sig_Path is still a path, and deliberately so: a substituted signature
   --  file gains nothing, because whatever it contains must still verify
   --  against these sealed roster bytes over these sealed message bytes.
   --
   --  Empties the process environment before spawning anything, because the
   --  child inherits it and a loader variable in it is a bypass. "This program
   --  reads no environment variable" was never the same claim as "no
   --  environment reaches the child"; now both hold.

   procedure Attribute_One
     (R        : Quorum.Roster;
      Roster   : Sealed;
      Message  : Sealed;
      Sig_Path : String;
      V        : in out Quorum.Signer_Set)
   with Global => (In_Out => World),
        Pre    => Quorum.Consistent (R, V),
        Post   => Quorum.Consistent (R, V);
   --  Credit one signature to at most one enrolled principal. Trying each
   --  principal by exit status is what avoids parsing ssh-keygen's output.
   --  Lives here, not in the caller, so main and the tests exercise the same
   --  code: an attribution loop that exists twice is an attribution loop that
   --  disagrees with itself.

private

   type Sealed is record
      Fd : Integer := -1;
   end record;

end Edge;
