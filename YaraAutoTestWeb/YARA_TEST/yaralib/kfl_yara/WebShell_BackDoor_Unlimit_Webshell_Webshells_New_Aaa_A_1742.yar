rule WebShell_BackDoor_Unlimit_Webshell_Webshells_New_Aaa_A_1742 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/03/28"
    description = "Web shells - generated from file aaa.asp"
    family = "Webshell"
    hacker = "None"
    hash = "68483788ab171a155db5266310c852b2"
    judge = "unknown"
    reference = "None"
    score = 70
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Webshells.New.Aaa.A"
    threattype = "BackDoor"
  strings:
    $s0 = "Function fvm(jwv):If jwv=\"\"Then:fvm=jwv:Exit Function:End If:Dim tt,sru:tt=\""
    $s5 = "<option value=\"\"DROP TABLE [jnc];exec mast\"&kvp&\"er..xp_regwrite 'HKEY_LOCAL"
    $s17 = "if qpv=\"\" then qpv=\"x:\\Program Files\\MySQL\\MySQL Server 5.0\\my.ini\"&br&"
  condition:
    1 of them
}