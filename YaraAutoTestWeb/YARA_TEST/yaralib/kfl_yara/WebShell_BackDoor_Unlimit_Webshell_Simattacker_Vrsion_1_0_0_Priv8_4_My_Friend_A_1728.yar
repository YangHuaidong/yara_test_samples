rule WebShell_BackDoor_Unlimit_Webshell_Simattacker_Vrsion_1_0_0_Priv8_4_My_Friend_A_1728 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file SimAttacker - Vrsion 1.0.0 - priv8 4 My friend.php"
    family = "Webshell"
    hacker = "None"
    hash = "089ff24d978aeff2b4b2869f0c7d38a3"
    judge = "unknown"
    reference = "None"
    score = 70
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Simattacker.Vrsion.1.0.0.Priv8.4.My.Friend.A"
    threattype = "BackDoor"
  strings:
    $s2 = "echo \"<a href='?id=fm&fchmod=$dir$file'><span style='text-decoration: none'><fo"
    $s3 = "fputs ($fp ,\"\\n*********************************************\\nWelcome T0 Sim"
  condition:
    1 of them
}