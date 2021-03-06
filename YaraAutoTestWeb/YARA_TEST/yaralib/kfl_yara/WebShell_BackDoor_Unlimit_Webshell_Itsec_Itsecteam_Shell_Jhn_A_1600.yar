rule WebShell_BackDoor_Unlimit_Webshell_Itsec_Itsecteam_Shell_Jhn_A_1600 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - from files itsec.php, itsecteam_shell.php, jHn.php"
    family = "Webshell"
    hacker = "None"
    hash0 = "8ae9d2b50dc382f0571cd7492f079836"
    hash1 = "bd6d3b2763c705a01cc2b3f105a25fa4"
    hash2 = "40c6ecf77253e805ace85f119fe1cebb"
    judge = "unknown"
    reference = "None"
    score = 70
    super_rule = 1
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Itsec.Itsecteam.Shell.Jhn.A"
    threattype = "BackDoor"
  strings:
    $s4 = "echo $head.\"<font face='Tahoma' size='2'>Operating System : \".php_uname().\"<b"
    $s5 = "echo \"<center><form name=client method='POST' action='$_SERVER[PHP_SELF]?do=db'"
  condition:
    all of them
}