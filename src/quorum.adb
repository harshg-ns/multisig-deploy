package body Quorum with SPARK_Mode is

   LF : constant Character := Character'Val (10);

   --  The manifest is a fixed layout. Every line but the last has a fixed
   --  width, so the whole grammar is index arithmetic: no line splitting, no
   --  key lookup, no duplicate-key or reordering case to consider.
   --
   --    1 ..  23  "ns-release-manifest v1" LF
   --   24 ..  72  "commit: "        40 hex      LF
   --   73 .. 152  "digest: sha256:" 64 hex      LF
   --  153 .. 163  "target: P"       1 digit     LF
   --  164 .. 195  "signed_at: "     20 char ts  LF
   --  196 .. 231  "execute_after: " 20 char ts  LF
   --  232 .. 264  "expires_at: "    20 char ts  LF
   --  265 ..      "author: "        3-64 char   LF

   Head   : constant String := "ns-release-manifest v1";
   K_Comm : constant String := "commit: ";
   K_Dig  : constant String := "digest: sha256:";
   K_Targ : constant String := "target: P";
   K_Sign : constant String := "signed_at: ";
   K_Exec : constant String := "execute_after: ";
   K_Exp  : constant String := "expires_at: ";
   K_Auth : constant String := "author: ";

   Fixed_Part : constant := 264;  --  through the expires_at line feed
   Author_At  : constant := 273;  --  first character of the author name

   Ed25519_SK : constant String := "sk-ssh-ed25519@openssh.com";
   Ecdsa_SK   : constant String := "sk-ecdsa-sha2-nistp256@openssh.com";

   function Is_Hex (C : Character) return Boolean is
     (C in '0' .. '9' | 'a' .. 'f');

   function Is_Digit (C : Character) return Boolean is (C in '0' .. '9');

   function Is_Name_Char (C : Character) return Boolean is
     (C in 'a' .. 'z' | '0' .. '9' | '.' | '_' | '-' | '@');

   function Is_B64_Char (C : Character) return Boolean is
     (C in 'a' .. 'z' | 'A' .. 'Z' | '0' .. '9' | '+' | '/' | '=');

   function Digits_Ok (S : String) return Boolean is
     (for all C of S => Is_Digit (C));

   function Value_2 (S : String) return Natural
   with Pre  => S'Length = 2 and then Digits_Ok (S),
        Post => Value_2'Result <= 99;

   function Value_4 (S : String) return Natural
   with Pre  => S'Length = 4 and then Digits_Ok (S),
        Post => Value_4'Result <= 9999;

   procedure Parse_TS (S : String; T : out Timestamp; Ok : out Boolean)
   with Pre  => S'Length = 20,
        Post => (if Ok then Valid (T));

   procedure Parse_Roster_Line (S : String; N : out Name; Ok : out Boolean)
   with Post => (if Ok then N.Len in 3 .. Max_Name);

   ---------------------------------------------------------------- Value ----

   function Value_2 (S : String) return Natural is
     ((Character'Pos (S (S'First)) - 48) * 10
      + (Character'Pos (S (S'First + 1)) - 48));

   function Value_4 (S : String) return Natural is
     ((Character'Pos (S (S'First)) - 48) * 1000
      + (Character'Pos (S (S'First + 1)) - 48) * 100
      + (Character'Pos (S (S'First + 2)) - 48) * 10
      + (Character'Pos (S (S'First + 3)) - 48));

   ----------------------------------------------------------- Month_Days ----

   function Month_Days (Y : Year_Num; M : Month_Num) return Day_Num is
   begin
      case M is
         when 1 | 3 | 5 | 7 | 8 | 10 | 12 => return 31;
         when 4 | 6 | 9 | 11              => return 30;
         when 2 => return (if Y mod 4 = 0 then 29 else 28);
      end case;
   end Month_Days;

   ---------------------------------------------------------------- Epoch ----

   type Cumulative_Table is array (Month_Num) of Natural;

   Before_Month : constant Cumulative_Table :=
     [0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334];

   function Epoch (T : Timestamp) return Long_Integer is
      Leaps : constant Natural := (T.Year - 2000 + 3) / 4;
      Days  : Natural :=
        (T.Year - 2000) * 365 + Leaps + Before_Month (T.Month) + (T.Day - 1);
   begin
      if T.Month > 2 and then T.Year mod 4 = 0 then
         Days := Days + 1;
      end if;
      pragma Assert (Days <= 36_524);
      return Long_Integer (Days) * 86_400
             + Long_Integer (T.Hour) * 3_600
             + Long_Integer (T.Minute) * 60
             + Long_Integer (T.Second);
   end Epoch;

   -------------------------------------------------------------- Members ----

   function Members (S : Signer_Set) return Signer_Count is
      N : Signer_Count := 0;
   begin
      for I in Signer_Index loop
         if S (I) then
            N := N + 1;
         end if;
         pragma Loop_Invariant (N <= I);
      end loop;
      return N;
   end Members;

   ------------------------------------------------------------- Parse_TS ----

   procedure Parse_TS (S : String; T : out Timestamp; Ok : out Boolean) is
      F : constant Positive := S'First;
      Y, Mo, D, H, Mi, Se : Natural;
   begin
      T  := (others => <>);
      Ok := False;

      if S (F + 4) /= '-' or else S (F + 7) /= '-'
        or else S (F + 10) /= 'T' or else S (F + 13) /= ':'
        or else S (F + 16) /= ':' or else S (F + 19) /= 'Z'
      then
         return;
      end if;

      if not Digits_Ok (S (F .. F + 3)) or else not Digits_Ok (S (F + 5 .. F + 6))
        or else not Digits_Ok (S (F + 8 .. F + 9))
        or else not Digits_Ok (S (F + 11 .. F + 12))
        or else not Digits_Ok (S (F + 14 .. F + 15))
        or else not Digits_Ok (S (F + 17 .. F + 18))
      then
         return;
      end if;

      Y  := Value_4 (S (F .. F + 3));
      Mo := Value_2 (S (F + 5 .. F + 6));
      D  := Value_2 (S (F + 8 .. F + 9));
      H  := Value_2 (S (F + 11 .. F + 12));
      Mi := Value_2 (S (F + 14 .. F + 15));
      Se := Value_2 (S (F + 17 .. F + 18));

      if Y not in 2000 .. 2099 or else Mo not in 1 .. 12
        or else D not in 1 .. 31 or else H > 23 or else Mi > 59 or else Se > 59
      then
         return;
      end if;

      --  No leap seconds: 23:59:60 is refused above, which is correct for a
      --  policy clock and avoids an entire class of arithmetic special case.
      if D > Month_Days (Y, Mo) then
         return;
      end if;

      T  := (Year => Y, Month => Mo, Day => D,
             Hour => H, Minute => Mi, Second => Se);
      Ok := True;
   end Parse_TS;

   ------------------------------------------------------- Parse_Manifest ----

   procedure Parse_Manifest (Raw : String; M : out Manifest; Ok : out Boolean) is
      Name_Len : Natural;
      T1, T2, T3 : Timestamp;
      Ok1, Ok2, Ok3 : Boolean;
   begin
      M  := (others => <>);
      Ok := False;

      --  Length pins the whole layout: the only variable field is the author,
      --  and it is last.
      if Raw'Last < Author_At + 3 or else Raw'Last > Author_At + Max_Name then
         return;
      end if;
      Name_Len := Raw'Last - Author_At;

      if Raw (Raw'Last) /= LF
        or else Raw (1 .. 22) /= Head
        or else Raw (23) /= LF
        or else Raw (24 .. 31) /= K_Comm
        or else Raw (72) /= LF
        or else Raw (73 .. 87) /= K_Dig
        or else Raw (152) /= LF
        or else Raw (153 .. 161) /= K_Targ
        or else Raw (163) /= LF
        or else Raw (164 .. 174) /= K_Sign
        or else Raw (195) /= LF
        or else Raw (196 .. 210) /= K_Exec
        or else Raw (231) /= LF
        or else Raw (232 .. 243) /= K_Exp
        or else Raw (Fixed_Part) /= LF
        or else Raw (265 .. 272) /= K_Auth
      then
         return;
      end if;

      if (for some C of Raw (32 .. 71) => not Is_Hex (C))
        or else (for some C of Raw (88 .. 151) => not Is_Hex (C))
        or else not Is_Digit (Raw (162)) or else Raw (162) = '0'
        or else (for some C of Raw (Author_At .. Raw'Last - 1) =>
                   not Is_Name_Char (C))
      then
         return;
      end if;

      Parse_TS (Raw (175 .. 194), T1, Ok1);
      Parse_TS (Raw (211 .. 230), T2, Ok2);
      Parse_TS (Raw (244 .. 263), T3, Ok3);
      if not (Ok1 and Ok2 and Ok3) then
         return;
      end if;

      M.Commit := Raw (32 .. 71);
      M.Digest := Raw (88 .. 151);
      M.Target := "P" & Raw (162);
      M.Author.Text (1 .. Name_Len) := Raw (Author_At .. Raw'Last - 1);
      M.Author.Len := Name_Len;
      M.Signed_At := T1;
      M.Execute_After := T2;
      M.Expires_At := T3;
      Ok := True;
   end Parse_Manifest;

   --------------------------------------------------- Parse_Roster_Line ----

   procedure Parse_Roster_Line (S : String; N : out Name; Ok : out Boolean) is
      Sp1, Sp2 : Natural := 0;
      Spaces   : Natural := 0;
   begin
      N  := (others => <>);
      Ok := False;

      if S'Length < 3 then
         return;
      end if;

      for I in S'Range loop
         if S (I) = ' ' then
            Spaces := Spaces + 1;
            if Spaces = 1 then
               Sp1 := I;
            elsif Spaces = 2 then
               Sp2 := I;
            else
               return;  --  a third space means options or a comment field
            end if;
         end if;
         pragma Loop_Invariant (Spaces <= 2);
         pragma Loop_Invariant (if Spaces >= 1 then Sp1 in S'First .. I);
         pragma Loop_Invariant (if Spaces = 2 then Sp2 in Sp1 + 1 .. I);
      end loop;

      if Spaces /= 2 then
         return;
      end if;

      --  principal
      if Sp1 - S'First not in 3 .. Max_Name then
         return;
      end if;
      if (for some C of S (S'First .. Sp1 - 1) => not Is_Name_Char (C)) then
         return;
      end if;

      --  algorithm: only the two FIDO2 types. This is where "the key is
      --  hardware" is enforced, at the trust root, once.
      declare
         Alg : constant String := S (Sp1 + 1 .. Sp2 - 1);
      begin
         if Alg /= Ed25519_SK and then Alg /= Ecdsa_SK then
            return;
         end if;
      end;

      --  key material
      if Sp2 >= S'Last or else S'Last - Sp2 < 40
        or else (for some C of S (Sp2 + 1 .. S'Last) => not Is_B64_Char (C))
      then
         return;
      end if;

      N.Len := Sp1 - S'First;
      N.Text (1 .. N.Len) := S (S'First .. Sp1 - 1);
      Ok := True;
   end Parse_Roster_Line;

   --------------------------------------------------------- Parse_Roster ----

   procedure Parse_Roster (Raw : String; R : out Roster; Ok : out Boolean) is
      Start : Positive := 1;
      Line  : Name;
      Fine  : Boolean;
   begin
      R  := (Names => [others => (others => <>)], Count => 0);
      Ok := False;

      if Raw'Length = 0 or else Raw (Raw'Last) /= LF then
         return;
      end if;

      for I in Raw'Range loop
         if Raw (I) = LF then
            if R.Count = Max_Enrolled then
               return;
            end if;
            Parse_Roster_Line (Raw (Start .. I - 1), Line, Fine);
            if not Fine then
               return;
            end if;
            for K in 1 .. R.Count loop
               if R.Names (K) = Line then
                  return;  --  the same principal enrolled twice is not two humans
               end if;
            end loop;
            R.Count := R.Count + 1;
            R.Names (R.Count) := Line;
            Start := I + 1;
         end if;
         pragma Loop_Invariant (Start in 1 .. I + 1);
      end loop;

      Ok := R.Count >= Min_Enrolled;
   end Parse_Roster;

   ----------------------------------------------------------- Is_Revoked ----

   function Is_Revoked (Raw : String; Digest : String) return Boolean is
      Start : Positive := 1;
   begin
      if Raw'Length = 0 then
         return False;
      end if;
      if Raw (Raw'Last) /= LF then
         return True;   --  unparseable cancel list counts as a cancellation
      end if;
      for I in Raw'Range loop
         if Raw (I) = LF then
            if I - Start /= 64 then
               return True;
            end if;
            if (for some C of Raw (Start .. I - 1) => not Is_Hex (C)) then
               return True;
            end if;
            if Raw (Start .. I - 1) = Digest then
               return True;
            end if;
            Start := I + 1;
         end if;
         pragma Loop_Invariant (Start in 1 .. I + 1);
      end loop;
      return False;
   end Is_Revoked;

   --------------------------------------------------------------- Decide ----

   function Decide
     (M        : Manifest;
      R        : Roster;
      Verified : Signer_Set;
      Now      : Timestamp;
      Revoked  : Boolean) return Verdict
   is
   begin
      if R.Count < Min_Enrolled then
         return Refuse_Enrolment;
      end if;
      if Members (Verified) < Threshold then
         return Refuse_Quorum;
      end if;
      if Signed_By_Author (M.Author, R, Verified) then
         return Refuse_Author;
      end if;
      if Epoch (M.Execute_After) - Epoch (M.Signed_At)
           < Min_Delay_Hours * 3600
      then
         return Refuse_Delay;
      end if;
      if Epoch (Now) < Epoch (M.Execute_After) then
         return Refuse_Early;
      end if;
      if Epoch (Now) >= Epoch (M.Expires_At) then
         return Refuse_Expired;
      end if;
      if Revoked then
         return Refuse_Revoked;
      end if;
      return Allow;
   end Decide;

end Quorum;
