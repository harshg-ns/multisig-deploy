with Ada.Calendar;
with Ada.Calendar.Formatting;
with GNAT.OS_Lib;
with System;

package body Edge with SPARK_Mode => Off is

   use GNAT.OS_Lib;

   --  Bound straight to libc rather than taking on a dependency for five
   --  syscalls GNAT.OS_Lib does not expose.
   function C_Dup (Fd : Integer) return Integer
     with Import, Convention => C, External_Name => "dup";

   function C_Dup2 (Old_Fd, New_Fd : Integer) return Integer
     with Import, Convention => C, External_Name => "dup2";

   function C_Mkstemp (Template : System.Address) return Integer
     with Import, Convention => C, External_Name => "mkstemp";

   function C_Unlink (Path : System.Address) return Integer
     with Import, Convention => C, External_Name => "unlink";

   function C_Lseek
     (Fd : Integer; Offset : Long_Integer; Whence : Integer) return Long_Integer
     with Import, Convention => C, External_Name => "lseek";

   Seek_Set : constant := 0;

   --  GNAT.OS_Lib.Spawn execs with the caller's environment, and the threat
   --  model grants the attacker that environment. On Linux a single inherited
   --  LD_PRELOAD would let an attacker replace ssh-keygen's behaviour without
   --  touching OpenSSH at all, which is a complete bypass of the verifier.
   --  So the environment is emptied before any child can exist. This program
   --  reads no environment variable, so there is nothing to preserve.
   --
   --  Replacing `environ` is what execv passes to execve, on both glibc and
   --  Darwin. Apple's runtime hardening already blocks library injection into
   --  a signed /usr/bin/ssh-keygen, but that is a property of the platform,
   --  not of this program.
   --
   --  DELIBERATELY IRREVERSIBLE, AND DO NOT ADD A RESTORE. The invariant is
   --  "no child of this process ever receives an environment", and it is
   --  global and unconditional. Saving `environ` and putting it back after
   --  each spawn would keep that guarantee only for the spawns this package
   --  performs today, and would leave a window in which any later code path —
   --  a future addition, an exception path, a library — spawns with the
   --  attacker's environment intact. The failure mode of clearing permanently
   --  is that a host application embedding Edge loses its environment: loud,
   --  immediate, and caught the first time anyone tries it. The failure mode
   --  of restoring is a silent bypass. Between a loud availability failure in
   --  a reuse that does not exist and a silent security failure in a plausible
   --  edit, take the loud one. Recorded as SPEC.md G18.
   type Env_Block is array (1 .. 1) of System.Address;
   Empty_Env : aliased Env_Block := [1 => System.Null_Address];

   Environ : System.Address
     with Import, Convention => C, External_Name => "environ";

   procedure Drop_Environment is
   begin
      Environ := Empty_Env'Address;
   end Drop_Environment;

   Keygen    : constant String := "/usr/bin/ssh-keygen";
   Namespace : constant String := "ns-release";
   Devnull   : constant String := "/dev/null";

   NUL : constant Character := Character'Val (0);

   ------------------------------------------------------------ Read_File ----

   procedure Read_File
     (Path : String; Buf : out String; Last : out Natural; Ok : out Boolean)
   is
      Fd    : File_Descriptor;
      N     : Integer := 0;
      Total : Natural := 0;
      Bad   : Boolean := False;
   begin
      Buf  := [others => ' '];
      Last := Buf'First - 1;
      Ok   := False;

      if Is_Symbolic_Link (Path) or else not Is_Regular_File (Path) then
         return;
      end if;

      Fd := Open_Read (Path, Binary);
      if Fd = Invalid_FD then
         return;
      end if;

      --  read(2) is never given a count larger than the buffer. The loop is
      --  needed because a short read is legal.
      while Total < Buf'Length loop
         N := Read (Fd, Buf (Buf'First + Total)'Address, Buf'Length - Total);
         exit when N <= 0;
         Total := Total + N;
      end loop;
      if N < 0 then
         Bad := True;
      end if;

      --  Oversize is detected with a one-byte read into a separate variable.
      --  Asking read(2) for Buf'Length + 1 would let the kernel write one byte
      --  past the end of the buffer, which is what the audit found.
      if not Bad and then Total = Buf'Length then
         declare
            Probe : String (1 .. 1) := " ";
         begin
            if Read (Fd, Probe'Address, 1) /= 0 then
               Bad := True;   --  the file is larger than the buffer
            end if;
         end;
      end if;

      Close (Fd);
      if Bad then
         return;
      end if;

      Last := Buf'First + Total - 1;
      Ok   := True;
   end Read_File;

   -------------------------------------------------------------- Get_Now ----

   procedure Get_Now (T : out Quorum.Timestamp; Ok : out Boolean) is
      Y  : Ada.Calendar.Year_Number;
      Mo : Ada.Calendar.Month_Number;
      D  : Ada.Calendar.Day_Number;
      H  : Ada.Calendar.Formatting.Hour_Number;
      Mi : Ada.Calendar.Formatting.Minute_Number;
      S  : Ada.Calendar.Formatting.Second_Number;
      Ss : Ada.Calendar.Formatting.Second_Duration;
   begin
      T  := (others => <>);
      Ok := False;
      Ada.Calendar.Formatting.Split
        (Ada.Calendar.Clock, Y, Mo, D, H, Mi, S, Ss, Time_Zone => 0);
      if Y not in 2000 .. 2099 then
         return;   --  a clock outside the supported century is refused, not clamped
      end if;
      T  := (Year   => Y, Month  => Mo, Day    => D,
             Hour   => H, Minute => Mi, Second => S);
      Ok := Quorum.Valid (T);
   end Get_Now;

   ----------------------------------------------------------------- Seal ----

   procedure Seal (Content : String; S : out Sealed; Ok : out Boolean) is
      --  mkstemp creates with O_CREAT | O_EXCL and mode 0600, so an attacker
      --  cannot pre-create the path, and cannot pre-point it at anything else.
      Template : String (1 .. 20) := "/tmp/.quorum-XXXXXX" & NUL;
      Fd       : Integer;
   begin
      S  := (Fd => -1);
      Ok := False;

      Fd := C_Mkstemp (Template'Address);
      if Fd < 0 then
         return;
      end if;

      --  Unlinked immediately: from here on no path in the filesystem names
      --  these bytes, so nothing can substitute them. The descriptor is the
      --  only reference, and this program never writes to it again.
      if C_Unlink (Template'Address) /= 0 then
         Close (File_Descriptor (Fd));
         return;
      end if;

      if Content'Length > 0
        and then Write (File_Descriptor (Fd), Content'Address, Content'Length)
                   /= Content'Length
      then
         Close (File_Descriptor (Fd));
         return;
      end if;

      S  := (Fd => Fd);
      Ok := True;
   end Seal;

   --------------------------------------------------------------- Unseal ----

   procedure Unseal (S : in out Sealed) is
   begin
      if S.Fd >= 0 then
         Close (File_Descriptor (S.Fd));
         S.Fd := -1;
      end if;
   end Unseal;

   --------------------------------------------------------------- Verify ----

   procedure Verify
     (Sig_Path  : String;
      Roster    : Sealed;
      Message   : Sealed;
      Principal : String;
      Ok        : out Boolean)
   is
      Args     : Argument_List (1 .. 10);
      Saved_In : Integer;
      Sink     : File_Descriptor;
      Code     : Integer;
      Img      : constant String := Integer'Image (Roster.Fd);
      Ref      : constant String := "/dev/fd/" & Img (2 .. Img'Last);

      procedure Release is
      begin
         for A of Args loop
            Free (A);
         end loop;
      end Release;
   begin
      Ok := False;

      --  Before the first child exists, and idempotent afterwards, so no
      --  caller can forget it. See the note on Drop_Environment: this is not
      --  undone, on purpose.
      Drop_Environment;

      if Roster.Fd < 0 or else Message.Fd < 0 then
         return;
      end if;
      if Is_Symbolic_Link (Keygen) or else not Is_Regular_File (Keygen) then
         return;
      end if;

      --  Both descriptors are reused across principals and across signatures,
      --  so each use starts from the beginning of the sealed bytes.
      if C_Lseek (Roster.Fd, 0, Seek_Set) /= 0
        or else C_Lseek (Message.Fd, 0, Seek_Set) /= 0
      then
         return;
      end if;

      Sink := Open_Read_Write (Devnull, Binary);
      if Sink = Invalid_FD then
         return;
      end if;

      Args (1)  := new String'("-Y");
      Args (2)  := new String'("verify");
      Args (3)  := new String'("-f");
      Args (4)  := new String'(Ref);
      Args (5)  := new String'("-I");
      Args (6)  := new String'(Principal);
      Args (7)  := new String'("-n");
      Args (8)  := new String'(Namespace);
      Args (9)  := new String'("-s");
      Args (10) := new String'(Sig_Path);

      --  The signed bytes arrive on standard input from the sealed copy, and
      --  the roster is named by descriptor, so neither can be swapped between
      --  the parse and this verification.
      Saved_In := C_Dup (Integer (Standin));
      if Saved_In < 0 then
         Close (Sink);
         Release;
         return;
      end if;

      if C_Dup2 (Message.Fd, Integer (Standin)) < 0 then
         Close (File_Descriptor (Saved_In));
         Close (Sink);
         Release;
         return;
      end if;

      --  The invariant, checked at the only point it can be violated. This
      --  holds independently of the test suite, so deleting the test cannot
      --  quietly remove the guarantee — though a build without -gnata drops
      --  the check while keeping the fix.
      pragma Assert (System."=" (Environ, Empty_Env'Address));

      Spawn (Keygen, Args, Sink, Code, Err_To_Out => True);

      if C_Dup2 (Saved_In, Integer (Standin)) < 0 then
         Code := -1;   --  standard input not restored: refuse rather than continue
      end if;

      Close (File_Descriptor (Saved_In));
      Close (Sink);
      Release;

      Ok := Code = 0;
   end Verify;

   -------------------------------------------------------- Attribute_One ----

   procedure Attribute_One
     (R        : Quorum.Roster;
      Roster   : Sealed;
      Message  : Sealed;
      Sig_Path : String;
      V        : in out Quorum.Signer_Set)
   is
      Ok : Boolean;
   begin
      for I in 1 .. R.Count loop
         Verify
           (Sig_Path  => Sig_Path,
            Roster    => Roster,
            Message   => Message,
            Principal => R.Names (I).Text (1 .. R.Names (I).Len),
            Ok        => Ok);
         if Ok then
            V (I) := True;
            exit;   --  one signature credits one slot, never two
         end if;
      end loop;
   end Attribute_One;

end Edge;
