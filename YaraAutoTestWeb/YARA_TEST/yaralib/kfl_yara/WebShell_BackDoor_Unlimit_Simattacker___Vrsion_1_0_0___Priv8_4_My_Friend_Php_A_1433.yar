rule WebShell_BackDoor_Unlimit_Simattacker___Vrsion_1_0_0___Priv8_4_My_Friend_Php_A_1433 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Semi-Auto-generated  - file SimAttacker - Vrsion 1.0.0 - priv8 4 My friend.php.txt"
    family = "Simattacker"
    hacker = "None"
    hash = "089ff24d978aeff2b4b2869f0c7d38a3"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Simattacker...Vrsion.1.0.0...Priv8.4.My.Friend.Php.A"
    threattype = "BackDoor"
  strings:
    $s0 = "SimAttacker - Vrsion : 1.0.0 - priv8 4 My friend"
    $s3 = " fputs ($fp ,\"\\n*********************************************\\nWelcome T0 Sim"
    $s4 = "echo \"<a target='_blank' href='?id=fm&fedit=$dir$file'><span style='text-decora"
  condition:
    1 of them
}