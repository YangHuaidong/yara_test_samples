rule WebShell_BackDoor_Unlimit_Webshell_Phpjackal_V1_5_A_1691 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file PHPJackal v1.5.php"
    family = "Webshell"
    hacker = "None"
    hash = "d76dc20a4017191216a0315b7286056f"
    judge = "unknown"
    reference = "None"
    score = 70
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Phpjackal.V1.5.A"
    threattype = "BackDoor"
  strings:
    $s7 = "echo \"<center>${t}MySQL cilent:</td><td bgcolor=\\\"#333333\\\"></td></tr><form"
    $s8 = "echo \"<center>${t}Wordlist generator:</td><td bgcolor=\\\"#333333\\\"></td></tr"
  condition:
    all of them
}