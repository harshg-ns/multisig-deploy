--  quorum MANIFEST ROSTER CANCELLED SIG [SIG ...]
--
--  There are no flags. A control whose behaviour can be changed from the
--  command line is a control an attacker can reconfigure, and every flag is a
--  chance to add one.

with Ada.Command_Line; use Ada.Command_Line;
with Ada.Text_IO;      use Ada.Text_IO;
with Quorum;
with Edge;

procedure Main is

   Manifest_Buf : String (1 .. Quorum.Max_Manifest);
   Roster_Buf   : String (1 .. Quorum.Max_Roster);
   Cancel_Buf   : String (1 .. Quorum.Max_Revoked);
   M_Last, R_Last, C_Last : Natural;

   M   : Quorum.Manifest;
   R   : Quorum.Roster;
   V   : Quorum.Signer_Set := Quorum.Nobody;
   Now : Quorum.Timestamp;
   Ok  : Boolean;

   Manifest_Seal, Roster_Seal : Edge.Sealed;

   procedure Refuse (Msg : String) is
   begin
      Put_Line (Standard_Error, "REFUSED: " & Msg);
      Set_Exit_Status (Failure);
   end Refuse;

begin
   Set_Exit_Status (Failure);   --  the default outcome is refusal

   if Argument_Count < 4
     or else Argument_Count > 3 + Quorum.Max_Enrolled
   then
      Refuse ("usage: quorum MANIFEST ROSTER CANCELLED SIG [SIG ...]");
      return;
   end if;

   Edge.Read_File (Argument (1), Manifest_Buf, M_Last, Ok);
   if not Ok then
      Refuse ("manifest unreadable, oversized, or not a regular file");
      return;
   end if;

   Edge.Read_File (Argument (2), Roster_Buf, R_Last, Ok);
   if not Ok then
      Refuse ("roster unreadable, oversized, or not a regular file");
      return;
   end if;

   Edge.Read_File (Argument (3), Cancel_Buf, C_Last, Ok);
   if not Ok then
      Refuse ("cancellation list unreadable; an absent list is not an empty one");
      return;
   end if;

   Quorum.Parse_Manifest (Manifest_Buf (1 .. M_Last), M, Ok);
   if not Ok then
      Put_Line (Standard_Error, "REFUSED: " & Quorum.Refuse_Manifest'Image);
      return;
   end if;

   Quorum.Parse_Roster (Roster_Buf (1 .. R_Last), R, Ok);
   if not Ok then
      Put_Line (Standard_Error, "REFUSED: " & Quorum.Refuse_Roster'Image);
      return;
   end if;

   --  Seal the exact slices that were just parsed, from the same buffers.
   --  OpenSSH is given these bytes and never the caller's paths, so the bytes
   --  it verifies are the bytes Decide judges. Re-reading either path here
   --  would reintroduce the race.
   Edge.Seal (Manifest_Buf (1 .. M_Last), Manifest_Seal, Ok);
   if not Ok then
      Refuse ("could not seal the manifest bytes");
      return;
   end if;

   Edge.Seal (Roster_Buf (1 .. R_Last), Roster_Seal, Ok);
   if not Ok then
      Refuse ("could not seal the roster bytes");
      return;
   end if;

   Edge.Get_Now (Now, Ok);
   if not Ok then
      Refuse ("system clock outside 2000-2099");
      return;
   end if;

   --  The set is indexed by enrolment slot, so one holder's two signatures
   --  cannot count twice however they are presented.
   for A in 4 .. Argument_Count loop
      Edge.Attribute_One
        (R        => R,
         Roster   => Roster_Seal,
         Message  => Manifest_Seal,
         Sig_Path => Argument (A),
         V        => V);
   end loop;

   if not Quorum.Consistent (R, V) then
      Refuse ("internal: signer set inconsistent with roster");
      return;
   end if;

   declare
      Result : constant Quorum.Verdict :=
        Quorum.Decide
          (M        => M,
           R        => R,
           Verified => V,
           Now      => Now,
           Revoked  => Quorum.Is_Revoked (Cancel_Buf (1 .. C_Last), M.Digest));
   begin
      Edge.Unseal (Manifest_Seal);
      Edge.Unseal (Roster_Seal);

      if Quorum."=" (Result, Quorum.Allow) then
         Put_Line
           ("ALLOW " & M.Target & " commit=" & M.Commit
            & " digest=sha256:" & M.Digest
            & " signers=" & Quorum.Members (V)'Image);
         Set_Exit_Status (Success);
      else
         Put_Line (Standard_Error, "REFUSED: " & Result'Image);
      end if;
   end;
end Main;
