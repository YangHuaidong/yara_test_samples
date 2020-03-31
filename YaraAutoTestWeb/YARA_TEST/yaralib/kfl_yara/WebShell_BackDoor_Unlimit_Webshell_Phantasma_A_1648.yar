rule WebShell_BackDoor_Unlimit_Webshell_Phantasma_A_1648 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "PHP Webshells Github Archive - file PHANTASMA.php"
    family = "Webshell"
    hacker = "None"
    hash = "cd12d42abf854cd34ff9e93a80d464620af6d75e"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Phantasma.A"
    threattype = "BackDoor"
  strings:
    $s12 = "\"    printf(\\\"Usage: %s [Host] <port>\\\\n\\\", argv[0]);\\n\" ." fullword
    $s15 = "if ($portscan != \"\") {" fullword
    $s16 = "echo \"<br>Banner: $get <br><br>\";" fullword
    $s20 = "$dono = get_current_user( );" fullword
  condition:
    3 of them
}