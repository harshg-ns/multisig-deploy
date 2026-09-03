--  Tests. The decision matrix is exercised against Quorum directly; the
--  OpenSSH plumbing is exercised against real signatures made by test/run.sh.

with Ada.Command_Line; use Ada.Command_Line;
with Ada.Environment_Variables;
with Ada.Directories;
with Ada.Text_IO;      use Ada.Text_IO;
with Quorum;           use Quorum;
with Edge;

procedure Harness is

   Passed, Failed : Natural := 0;

   procedure Check (What : String; Cond : Boolean) is
   begin
      if Cond then
         Passed := Passed + 1;
      else
         Failed := Failed + 1;
         Put_Line (Standard_Error, "FAIL " & What);
      end if;
   end Check;

   LF : constant Character := Character'Val (10);

   Hex40 : constant String := "4bfc31f51e0000000000000000000000000000ab";
   Hex64 : constant String :=
     "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";

   --  A well-formed manifest, assembled from parts so a test can mutate one
   --  field without hand-maintaining a 300-byte blob.
   function Build
     (Commit : String := Hex40;
      Digest : String := Hex64;
      Target : String := "1";
      Author : String := "swayam@ns.com";
      Signed : String := "2026-09-01T09:00:00Z";
      Exec   : String := "2026-09-02T09:00:00Z";
      Expiry : String := "2026-09-05T09:00:00Z") return String
   is ("ns-release-manifest v1" & LF
       & "commit: " & Commit & LF
       & "digest: sha256:" & Digest & LF
       & "target: P" & Target & LF
       & "signed_at: " & Signed & LF
       & "execute_after: " & Exec & LF
       & "expires_at: " & Expiry & LF
       & "author: " & Author & LF);

   function Parses (Raw : String) return Boolean is
      M  : Manifest;
      Ok : Boolean;
   begin
      if Raw'Length > Max_Manifest then
         return False;
      end if;
      Parse_Manifest (Raw, M, Ok);
      return Ok;
   end Parses;

   function Named (S : String) return Quorum.Name is
      N : Quorum.Name;
   begin
      N.Len := S'Length;
      N.Text (1 .. S'Length) := S;
      return N;
   end Named;

   function Roster_Of (A, B, C : String) return Roster is
      R : Roster;
   begin
      R.Count := 3;
      R.Names (1) := Named (A);
      R.Names (2) := Named (B);
      R.Names (3) := Named (C);
      return R;
   end Roster_Of;

   Trio : constant Roster :=
     Roster_Of ("swayam@ns.com", "archit@ns.com", "malek@ns.com");

   Two_Of : constant Signer_Set := [2 => True, 3 => True, others => False];
   One_Of : constant Signer_Set := [3 => True, others => False];
   With_Author : constant Signer_Set := [1 => True, 2 => True, others => False];

   T_Sign : constant Timestamp := (2026, 9, 1, 9, 0, 0);
   T_Exec : constant Timestamp := (2026, 9, 2, 9, 0, 0);
   T_Exp  : constant Timestamp := (2026, 9, 5, 9, 0, 0);

   Good : constant Manifest :=
     (Commit => Hex40, Digest => Hex64, Target => "P1",
      Author => Named ("swayam@ns.com"),
      Signed_At => T_Sign, Execute_After => T_Exec, Expires_At => T_Exp);

   function Verdict_Of
     (M : Manifest := Good;
      V : Signer_Set := Two_Of;
      R : Roster := Trio;
      Now : Timestamp := (2026, 9, 3, 9, 0, 0);
      Revoked : Boolean := False) return Verdict
   is (Decide (M, R, V, Now, Revoked));

   function Roster_Ok (Raw : String) return Boolean is
      R  : Roster;
      Ok : Boolean;
   begin
      if Raw'Length > Max_Roster then
         return False;
      end if;
      Parse_Roster (Raw, R, Ok);
      return Ok;
   end Roster_Ok;

   Key_A : constant String :=
     "swayam@ns.com sk-ssh-ed25519@openssh.com "
     & "AAAAGnNrLXNzaC1lZDI1NTE5QG9wZW5zc2guY29tAAAAIB0000000000000000";
   Key_B : constant String :=
     "archit@ns.com sk-ecdsa-sha2-nistp256@openssh.com "
     & "AAAAInNrLWVjZHNhLXNoYTItbmlzdHAyNTZAb3BlbnNzaC5jb20AAAAIbmlzdA";
   Key_C : constant String :=
     "malek@ns.com sk-ssh-ed25519@openssh.com "
     & "AAAAGnNrLXNzaC1lZDI1NTE5QG9wZW5zc2guY29tAAAAIC1111111111111111";
   Soft  : constant String :=
     "prince@ns.com ssh-ed25519 "
     & "AAAAC3NzaC1lZDI1NTE5AAAAIGxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";

   --  The principals in the fixture roster that run.sh writes.
   Real_Trio : constant Roster :=
     Roster_Of ("alice@ns.com", "bob@ns.com", "carol@ns.com");

   --  Fixed, so no test depends on the wall clock.
   Test_Now : constant Timestamp := (2026, 9, 3, 9, 0, 0);

   --  Read a file and seal exactly the bytes that were read, which is what
   --  main does. Returns an unset seal on any failure, and an unset seal makes
   --  every verification refuse.
   function Sealed_File (Path : String) return Edge.Sealed is
      Buf   : String (1 .. Max_Roster);
      Bytes : Natural;
      Ok    : Boolean;
      S     : Edge.Sealed;
   begin
      Edge.Read_File (Path, Buf, Bytes, Ok);
      if not Ok then
         return S;
      end if;
      Edge.Seal (Buf (1 .. Bytes), S, Ok);
      return S;
   end Sealed_File;

   procedure Plumbing (Dir : String) is
      Ok       : Boolean;
      Roster_S : Edge.Sealed := Sealed_File (Dir & "/roster");
      Msg_S    : Edge.Sealed := Sealed_File (Dir & "/manifest");
      Tamp_S   : Edge.Sealed := Sealed_File (Dir & "/tampered");
      Unset    : Edge.Sealed;
   begin
      --  Audit R3. The child inherits our environment, so there must not be
      --  one by the time a child exists: on Linux a single inherited
      --  LD_PRELOAD would replace ssh-keygen's behaviour outright.
      Check ("environment: the process starts with an environment",
             Ada.Environment_Variables.Exists ("PATH"));

      Edge.Verify (Dir & "/sig.alice", Roster_S, Msg_S, "alice@ns.com", Ok);
      Check ("openssh: a genuine signature verifies", Ok);

      Check ("environment: emptied before any child is spawned",
             not Ada.Environment_Variables.Exists ("PATH")
             and then not Ada.Environment_Variables.Exists ("HOME"));

      Edge.Verify (Dir & "/sig.alice", Roster_S, Tamp_S, "alice@ns.com", Ok);
      Check ("openssh: a tampered manifest does not verify", not Ok);

      Edge.Verify (Dir & "/sig.alice", Roster_S, Msg_S, "bob@ns.com", Ok);
      Check ("openssh: a signature is not attributed to another principal",
             not Ok);

      Edge.Verify (Dir & "/sig.otherns", Roster_S, Msg_S, "alice@ns.com", Ok);
      Check ("openssh: a signature made in another namespace is refused",
             not Ok);

      Edge.Verify (Dir & "/sig.alice", Roster_S, Unset, "alice@ns.com", Ok);
      Check ("openssh: an unsealed message fails closed", not Ok);

      Edge.Verify (Dir & "/sig.alice", Unset, Msg_S, "alice@ns.com", Ok);
      Check ("openssh: an unsealed roster fails closed", not Ok);

      --  The descriptors are reused, so a second call after the first must
      --  still see the sealed bytes from byte zero.
      Edge.Verify (Dir & "/sig.alice", Roster_S, Msg_S, "alice@ns.com", Ok);
      Check ("openssh: a sealed descriptor is reusable", Ok);

      Edge.Unseal (Roster_S);
      Edge.Unseal (Msg_S);
      Edge.Unseal (Tamp_S);
      Edge.Verify (Dir & "/sig.alice", Roster_S, Msg_S, "alice@ns.com", Ok);
      Check ("openssh: an unsealed descriptor fails closed", not Ok);
   end Plumbing;

   --  The whole pipeline, as main runs it: read the manifest, parse it,
   --  attribute each real signature to at most one enrolled slot, decide.
   procedure Run_Pipeline
     (Dir, Msg : String;
      S1, S2, S3 : String := "";
      Result : out Verdict;
      Signers : out Signer_Count)
   is
      Buf  : String (1 .. Max_Manifest);
      Last : Natural;
      Ok   : Boolean;
      M    : Manifest;
      V    : Signer_Set := Nobody;
   begin
      Result  := Refuse_Manifest;
      Signers := 0;
      Edge.Read_File (Dir & "/manifest", Buf, Last, Ok);
      if not Ok then
         return;
      end if;
      Parse_Manifest (Buf (1 .. Last), M, Ok);
      if not Ok then
         return;
      end if;
      declare
         Roster_S : Edge.Sealed := Sealed_File (Dir & "/roster");
         Msg_S    : Edge.Sealed := Sealed_File (Dir & "/" & Msg);
      begin
         if S1 /= "" then
            Edge.Attribute_One (Real_Trio, Roster_S, Msg_S, Dir & "/" & S1, V);
         end if;
         if S2 /= "" then
            Edge.Attribute_One (Real_Trio, Roster_S, Msg_S, Dir & "/" & S2, V);
         end if;
         if S3 /= "" then
            Edge.Attribute_One (Real_Trio, Roster_S, Msg_S, Dir & "/" & S3, V);
         end if;
         Edge.Unseal (Roster_S);
         Edge.Unseal (Msg_S);
      end;
      Signers := Members (V);
      Result  := Decide (M, Real_Trio, V, Test_Now, Revoked => False);
   end Run_Pipeline;

   procedure Two_Of_Three (Dir : String) is
      R : Verdict;
      N : Signer_Count;
   begin
      Run_Pipeline (Dir, "manifest", "sig.alice", "sig.carol",
                    Result => R, Signers => N);
      Check ("2-of-3: alice and carol authorise the deploy",
             R = Allow and then N = 2);

      Run_Pipeline (Dir, "manifest", "sig.alice", "sig.alice2",
                    Result => R, Signers => N);
      Check ("2-of-3: one holder signing twice is one signer, not two",
             R = Refuse_Quorum and then N = 1);

      Run_Pipeline (Dir, "manifest", "sig.dave", "sig.erin",
                    Result => R, Signers => N);
      Check ("2-of-3: keys outside the roster authorise nothing",
             R = Refuse_Quorum and then N = 0);

      Run_Pipeline (Dir, "manifest", "sig.alice", "sig.dave",
                    Result => R, Signers => N);
      Check ("2-of-3: one enrolled plus one stranger is still one signer",
             R = Refuse_Quorum and then N = 1);

      Run_Pipeline (Dir, "manifest", "sig.alice", "sig.bob",
                    Result => R, Signers => N);
      Check ("2-of-3: the author's own key does not complete the pair",
             R = Refuse_Author and then N = 2);

      Run_Pipeline (Dir, "manifest", "sig.alice", "sig.bob", "sig.carol",
                    Result => R, Signers => N);
      Check ("2-of-3: three signatures including the author are refused",
             R = Refuse_Author and then N = 3);

      Run_Pipeline (Dir, "tampered", "sig.alice", "sig.carol",
                    Result => R, Signers => N);
      Check ("2-of-3: signatures over a different manifest authorise nothing",
                R = Refuse_Quorum and then N = 0);
   end Two_Of_Three;

   --  The audit's finding A1, as a regression test. Parse the roster and the
   --  manifest, seal exactly those bytes, then replace both files on disk
   --  before verification. Before the fix, ssh-keygen reopened the paths and
   --  credited attacker keys to roster slots; now it never sees a path.
   procedure Reopen_Race (Dir : String) is
      Buf        : String (1 .. Max_Manifest);
      Roster_Buf : String (1 .. Max_Roster);
      Bytes      : Natural;
      Ok         : Boolean;
      M          : Manifest;
      R          : Roster;
      V          : Signer_Set := Nobody;
      Result     : Verdict;
   begin
      Edge.Read_File (Dir & "/race-manifest", Buf, Bytes, Ok);
      Check ("race: manifest fixture is readable", Ok);
      Parse_Manifest (Buf (1 .. Bytes), M, Ok);
      Check ("race: manifest fixture is valid", Ok);

      Edge.Read_File (Dir & "/race-roster", Roster_Buf, Bytes, Ok);
      Check ("race: roster fixture is readable", Ok);
      Parse_Roster (Roster_Buf (1 .. Bytes), R, Ok);
      Check ("race: roster fixture is valid", Ok);

      declare
         --  Sealed from the parsed bytes, exactly as main does it.
         Roster_S : Edge.Sealed;
         Msg_S    : Edge.Sealed;
         Fine     : Boolean;
      begin
         Edge.Seal (Roster_Buf (1 .. Bytes), Roster_S, Fine);
         Check ("race: the parsed roster seals", Fine);
         Edge.Read_File (Dir & "/race-manifest", Buf, Bytes, Ok);
         Edge.Seal (Buf (1 .. Bytes), Msg_S, Fine);
         Check ("race: the parsed manifest seals", Fine);

         --  The attacker now swaps both files. Same principal names, software
         --  keys they hold, and a different manifest.
         Ada.Directories.Copy_File (Dir & "/attacker-roster", Dir & "/race-roster");
         Ada.Directories.Copy_File (Dir & "/tampered", Dir & "/race-manifest");

         Edge.Attribute_One (R, Roster_S, Msg_S, Dir & "/sig.dave", V);
         Edge.Attribute_One (R, Roster_S, Msg_S, Dir & "/sig.erin", V);
         Result := Decide (M, R, V, Test_Now, Revoked => False);
         Check ("race: a swapped roster does not enrol attacker keys",
                Result /= Allow and then Members (V) = 0);
      end;
   end Reopen_Race;

   --  The manifest race in the direction that actually pays, which the audit's
   --  version had the wrong way round: parse the manifest the attacker wants
   --  shipped, then let verification see the one that really was signed. Before
   --  the fix this returned Allow with no attacker key material at all.
   procedure Manifest_Race (Dir : String) is
      Buf      : String (1 .. Max_Manifest);
      Bytes    : Natural;
      Ok       : Boolean;
      M        : Manifest;
      V        : Signer_Set := Nobody;
      Result   : Verdict;
      Roster_S : constant Edge.Sealed := Sealed_File (Dir & "/roster");
      Msg_S    : Edge.Sealed;
   begin
      --  1. The path holds the manifest the attacker wants authorised.
      Ada.Directories.Copy_File (Dir & "/tampered", Dir & "/race2");
      Edge.Read_File (Dir & "/race2", Buf, Bytes, Ok);
      Check ("race2: fixture is readable", Ok);
      Parse_Manifest (Buf (1 .. Bytes), M, Ok);
      Check ("race2: fixture parses", Ok);
      Edge.Seal (Buf (1 .. Bytes), Msg_S, Ok);
      Check ("race2: the parsed manifest seals", Ok);

      --  2. Before verification, the path is swapped to the manifest that two
      --     enrolled holders really did sign.
      Ada.Directories.Copy_File (Dir & "/manifest", Dir & "/race2");
      Edge.Attribute_One (Real_Trio, Roster_S, Msg_S, Dir & "/sig.alice", V);
      Edge.Attribute_One (Real_Trio, Roster_S, Msg_S, Dir & "/sig.carol", V);

      --  3. Nobody signed the manifest in M. It must not be authorised.
      Result := Decide (M, Real_Trio, V, Test_Now, Revoked => False);
      Check ("race2: a manifest nobody signed is not authorised",
             Result /= Allow and then Members (V) = 0);
   end Manifest_Race;

   --  The audit's findings A2 and A3. The fence is the next eight bytes of the
   --  same String, and slices of a String are contiguous by definition, so
   --  this witnesses the out-of-bounds write directly rather than depending on
   --  where the compiler happened to place two locals.
   procedure Redzone (Dir : String) is
      Fence : constant String := "########";
      Arena : String (1 .. Max_Roster + Fence'Length);
      Bytes : Natural;
      Ok    : Boolean;
   begin
      Arena := [others => '#'];
      Edge.Read_File (Dir & "/roster-4097", Arena (1 .. Max_Roster), Bytes, Ok);
      Check ("redzone: a 4097-byte roster is refused", not Ok);
      Check ("redzone: nothing is written past the roster buffer",
             Arena (Max_Roster + 1 .. Arena'Last) = Fence);

      Arena := [others => '#'];
      Edge.Read_File (Dir & "/cancelled-4097", Arena (1 .. Max_Revoked), Bytes, Ok);
      Check ("redzone: a 4097-byte cancellation list is refused", not Ok);
      Check ("redzone: nothing is written past the cancellation buffer",
             Arena (Max_Revoked + 1 .. Arena'Last) = Fence);

      --  And the probe must not reject a file that fits exactly.
      Arena := [others => '#'];
      Edge.Read_File (Dir & "/roster-4096", Arena (1 .. Max_Roster), Bytes, Ok);
      Check ("redzone: a file of exactly the buffer size is accepted",
             Ok and then Bytes = Max_Roster);
      Check ("redzone: and an exact fit writes nothing past the buffer",
             Arena (Max_Roster + 1 .. Arena'Last) = Fence);
   end Redzone;

begin
   ------------------------------------------------------- manifest grammar --
   Check ("manifest: accepts the canonical form", Parses (Build));
   Check ("manifest: rejects a truncated author",
          not Parses (Build (Author => "ab")));
   Check ("manifest: rejects an over-long author",
          not Parses (Build (Author => [1 .. 65 => 'a'])));
   Check ("manifest: rejects CRLF line endings",
          not Parses ("ns-release-manifest v1" & Character'Val (13) & LF));
   Check ("manifest: rejects a wrong header",
          not Parses ("ns-release-manifest v2" & LF
                      & Build (Author => "a.b")));
   Check ("manifest: rejects upper-case hex in the commit",
          not Parses (Build (Commit => "4BFC31F51E0000000000000000000000000000AB")));
   Check ("manifest: rejects a short commit",
          not Parses (Build (Commit => "4bfc31f")));
   Check ("manifest: rejects target P0",
          not Parses (Build (Target => "0")));
   Check ("manifest: rejects a non-ASCII author",
          not Parses (Build (Author => "sway" & Character'Val (200) & "m")));
   Check ("manifest: rejects an upper-case author",
          not Parses (Build (Author => "Swayam@ns.com")));
   Check ("manifest: rejects a space in the author",
          not Parses (Build (Author => "swayam ns")));
   Check ("manifest: rejects 2026-02-31",
          not Parses (Build (Signed => "2026-02-31T09:00:00Z")));
   Check ("manifest: accepts 2028-02-29 in a leap year",
          Parses (Build (Signed => "2028-02-29T09:00:00Z",
                         Exec   => "2028-03-01T09:00:00Z",
                         Expiry => "2028-03-05T09:00:00Z")));
   Check ("manifest: rejects 2027-02-29 in a common year",
          not Parses (Build (Signed => "2027-02-29T09:00:00Z")));
   Check ("manifest: rejects a year before 2000",
          not Parses (Build (Signed => "1999-09-01T09:00:00Z")));
   Check ("manifest: rejects a leap second",
          not Parses (Build (Signed => "2026-09-01T23:59:60Z")));
   Check ("manifest: rejects a local-time offset",
          not Parses (Build (Signed => "2026-09-01T09:00:00+")));
   Check ("manifest: rejects trailing bytes after the author line",
          not Parses (Build & "extra" & LF));
   Check ("manifest: rejects a missing final line feed",
          not Parses ("ns-release-manifest v1" & LF & "commit: " & Hex40));

   --------------------------------------------------------- roster grammar --
   Check ("roster: accepts three enrolled hardware keys",
          Roster_Ok (Key_A & LF & Key_B & LF & Key_C & LF));
   Check ("roster: rejects a software key",
          not Roster_Ok (Key_A & LF & Key_B & LF & Soft & LF));
   Check ("roster: rejects two enrolled keys",
          not Roster_Ok (Key_A & LF & Key_B & LF));
   Check ("roster: rejects the same principal twice",
          not Roster_Ok (Key_A & LF & Key_B & LF & Key_A & LF));
   Check ("roster: rejects a trailing comment field",
          not Roster_Ok (Key_A & " comment" & LF & Key_B & LF & Key_C & LF));
   Check ("roster: rejects an options field",
          not Roster_Ok ("cert-authority " & Key_A & LF & Key_B & LF
                         & Key_C & LF));
   Check ("roster: rejects a missing final line feed",
          not Roster_Ok (Key_A & LF & Key_B & LF & Key_C));
   Check ("roster: rejects an empty file", not Roster_Ok (""));

   ---------------------------------------------------------- cancel list ----
   Check ("cancel: matches the queued digest",
          Is_Revoked (Hex64 & LF, Hex64));
   Check ("cancel: ignores an unrelated digest",
          not Is_Revoked ([1 .. 64 => 'b'] & LF, Hex64));
   Check ("cancel: an empty list cancels nothing", not Is_Revoked ("", Hex64));
   Check ("cancel: an unparseable list counts as a cancellation",
          Is_Revoked ("not-a-digest" & LF, Hex64));
   Check ("cancel: a list without a final line feed counts as a cancellation",
          Is_Revoked (Hex64, Hex64));

   -------------------------------------------------------------- decision ----
   Check ("decide: allows two distinct hardware signers after the delay",
          Verdict_Of = Allow);
   Check ("decide: refuses one signature",
          Verdict_Of (V => One_Of) = Refuse_Quorum);
   Check ("decide: refuses no signatures",
          Verdict_Of (V => Nobody) = Refuse_Quorum);
   Check ("decide: refuses when a signer is the commit author",
          Verdict_Of (V => With_Author) = Refuse_Author);
   Check ("decide: refuses a window shorter than 24h",
          Verdict_Of (M => (Good with delta
                              Execute_After => (2026, 9, 1, 20, 0, 0)))
            = Refuse_Delay);
   Check ("decide: allows a window of exactly 24h",
          Verdict_Of (M => (Good with delta
                              Execute_After => (2026, 9, 2, 9, 0, 0))) = Allow);
   Check ("decide: refuses one second short of 24h",
          Verdict_Of (M => (Good with delta
                              Execute_After => (2026, 9, 2, 8, 59, 59)))
            = Refuse_Delay);
   Check ("decide: refuses before the queue delay has elapsed",
          Verdict_Of (Now => (2026, 9, 2, 8, 59, 59)) = Refuse_Early);
   Check ("decide: allows at the instant the delay elapses",
          Verdict_Of (Now => (2026, 9, 2, 9, 0, 0)) = Allow);
   Check ("decide: refuses after expiry",
          Verdict_Of (Now => (2026, 9, 5, 9, 0, 0)) = Refuse_Expired);
   Check ("decide: refuses a cancelled release inside the window",
          Verdict_Of (Revoked => True) = Refuse_Revoked);
   Check ("decide: refuses when only two keys are enrolled",
          Verdict_Of (R => (Names => Trio.Names, Count => 2),
                      V => [1 => True, 2 => True, others => False])
            = Refuse_Enrolment);
   Check ("decide: counts a set, so one holder cannot be two signers",
          Members (One_Of) = 1 and then Members (Two_Of) = 2);
   Check ("decide: refuses across a year boundary without 24h",
          Verdict_Of (M => (Good with delta
                              Signed_At     => (2026, 12, 31, 23, 0, 0),
                              Execute_After => (2027, 1, 1, 12, 0, 0),
                              Expires_At    => (2027, 1, 9, 0, 0, 0)),
                      Now => (2027, 1, 2, 0, 0, 0)) = Refuse_Delay);

   ------------------------------------- real signatures, whole pipeline -----
   --  run.sh passes one fixture directory holding real Ed25519 keys and real
   --  ssh-keygen signatures. Everything below is genuine cryptography: the
   --  only step not exercised is Parse_Roster's sk-* algorithm gate, because
   --  a genuine sk-* signature needs a physical touch (see README).
   if Argument_Count = 1 then
      Plumbing (Argument (1));
      Two_Of_Three (Argument (1));
      Manifest_Race (Argument (1));
      Reopen_Race (Argument (1));
      Redzone (Argument (1));
   else
      Put_Line (Standard_Error,
                "note: signature tests skipped (run via test/run.sh)");
   end if;

   New_Line;
   Put_Line (Passed'Image & " passed," & Failed'Image & " failed");
   Set_Exit_Status (if Failed = 0 then Success else Failure);
end Harness;
