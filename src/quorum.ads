--  The decision: may this release execute now?
--
--  No I/O, no clock, no environment, no allocation, no recursion. Everything
--  here is proved by GNATprove; the untrusted world is in Edge.

package Quorum with SPARK_Mode is

   Threshold       : constant := 2;    --  signatures required, distinct humans
   Min_Enrolled    : constant := 3;    --  2-of-2 blocks every release on one lost key
   Min_Delay_Hours : constant := 24;   --  the queue delay. Not caller-supplied.
   Max_Enrolled    : constant := 8;
   Max_Name        : constant := 64;
   Max_Manifest    : constant := 512;
   Max_Roster      : constant := 4096;
   Max_Revoked     : constant := 4096;

   type Verdict is
     (Allow,
      Refuse_Manifest,     --  manifest is not exactly the accepted grammar
      Refuse_Roster,       --  roster is not exactly the accepted grammar
      Refuse_Enrolment,    --  fewer than Min_Enrolled hardware keys enrolled
      Refuse_Quorum,       --  fewer than Threshold distinct signatures verified
      Refuse_Author,       --  a signature came from the author of the commit
      Refuse_Delay,        --  the signed window is shorter than Min_Delay_Hours
      Refuse_Early,        --  the queue delay has not elapsed
      Refuse_Expired,      --  the authorisation has expired
      Refuse_Revoked);     --  a quorum member cancelled it during the delay

   ---------------------------------------------------------------- names ----

   subtype Name_Length is Natural range 0 .. Max_Name;

   type Name is record
      Text : String (1 .. Max_Name) := [others => ' '];
      Len  : Name_Length            := 0;
   end record;

   function "=" (L, R : Name) return Boolean is
     (L.Len = R.Len and then L.Text (1 .. L.Len) = R.Text (1 .. R.Len));

   ----------------------------------------------------------------- time ----

   subtype Year_Num   is Integer range 2000 .. 2099;
   subtype Month_Num  is Integer range 1 .. 12;
   subtype Day_Num    is Integer range 1 .. 31;
   subtype Hour_Num   is Integer range 0 .. 23;
   subtype Minute_Num is Integer range 0 .. 59;
   subtype Second_Num is Integer range 0 .. 59;

   type Timestamp is record
      Year   : Year_Num   := 2000;
      Month  : Month_Num  := 1;
      Day    : Day_Num    := 1;
      Hour   : Hour_Num   := 0;
      Minute : Minute_Num := 0;
      Second : Second_Num := 0;
   end record;

   function Month_Days (Y : Year_Num; M : Month_Num) return Day_Num;
   --  2000 .. 2099 has no century exception: every year divisible by 4 is leap.

   function Valid (T : Timestamp) return Boolean is
     (T.Day <= Month_Days (T.Year, T.Month));
   --  Rejects 2026-02-31. All ordering below is by Epoch, so no lemma about
   --  the ordering of the record components is needed anywhere.

   Epoch_Last : constant := 3_155_760_000;

   function Epoch (T : Timestamp) return Long_Integer
   with Pre  => Valid (T),
        Post => Epoch'Result in 0 .. Epoch_Last;
   --  Seconds since 2000-01-01T00:00:00Z.

   -------------------------------------------------------------- signers ----

   subtype Signer_Index is Positive range 1 .. Max_Enrolled;
   subtype Signer_Count is Natural range 0 .. Max_Enrolled;

   type Signer_Set  is array (Signer_Index) of Boolean;
   type Name_Array  is array (Signer_Index) of Name;

   Nobody : constant Signer_Set := [others => False];

   type Roster is record
      Names : Name_Array;
      Count : Signer_Count := 0;
   end record;
   --  A set indexed by enrolment slot, so "distinct signers" holds by
   --  construction: one holder cannot be counted twice, whatever they sign.

   function Members (S : Signer_Set) return Signer_Count;

   function Consistent (R : Roster; V : Signer_Set) return Boolean is
     (for all I in Signer_Index => (if V (I) then I <= R.Count));
   --  Checked explicitly by the caller, so Decide needs no trust in the glue.

   function Signed_By_Author (M_Author : Name; R : Roster; V : Signer_Set)
     return Boolean
   is (for some I in Signer_Index =>
          I <= R.Count and then V (I) and then R.Names (I) = M_Author);

   ------------------------------------------------------------- manifest ----

   type Manifest is record
      Commit        : String (1 .. 40)  := [others => '0'];
      Digest        : String (1 .. 64)  := [others => '0'];
      Target        : String (1 .. 2)   := "P0";
      Author        : Name;
      Signed_At     : Timestamp;
      Execute_After : Timestamp;
      Expires_At    : Timestamp;
   end record;

   function Well_Formed (M : Manifest) return Boolean is
     (Valid (M.Signed_At) and then Valid (M.Execute_After)
      and then Valid (M.Expires_At));

   procedure Parse_Manifest (Raw : String; M : out Manifest; Ok : out Boolean)
   with Pre  => Raw'First = 1 and then Raw'Last <= Max_Manifest,
        Post => (if Ok then Well_Formed (M));
   --  Eight lines, fixed order, fixed prefixes, ASCII, LF-terminated. A fixed
   --  order removes duplicate-key and field-reordering attacks by construction.

   procedure Parse_Roster (Raw : String; R : out Roster; Ok : out Boolean)
   with Pre  => Raw'First = 1 and then Raw'Last <= Max_Roster,
        Post => (if Ok then R.Count >= Min_Enrolled);
   --  Every line must be exactly "principal sk-keytype base64". Only the two
   --  FIDO2 algorithms are accepted, so a verified signer is necessarily a
   --  hardware key: no signature blob needs parsing to establish that.

   function Is_Revoked (Raw : String; Digest : String) return Boolean
   with Pre => Raw'First = 1 and then Raw'Last <= Max_Revoked
               and then Digest'Length = 64;

   --------------------------------------------------------------- decide ----

   function Decide
     (M        : Manifest;
      R        : Roster;
      Verified : Signer_Set;
      Now      : Timestamp;
      Revoked  : Boolean) return Verdict
   with
     Pre  => Well_Formed (M) and then Valid (Now)
             and then Consistent (R, Verified),
     Post =>
       (if Decide'Result = Allow then
          R.Count >= Min_Enrolled
          and then Members (Verified) >= Threshold
          and then not Signed_By_Author (M.Author, R, Verified)
          and then Epoch (M.Execute_After) - Epoch (M.Signed_At)
                     >= Min_Delay_Hours * 3600
          and then Epoch (Now) >= Epoch (M.Execute_After)
          and then Epoch (Now) < Epoch (M.Expires_At)
          and then not Revoked);
   --  The security theorem. It is stated in one direction on purpose: nothing
   --  is allowed unless all seven hold. The reverse direction would only
   --  restate the body, and a control that fails closed is the property worth
   --  proving.

end Quorum;
