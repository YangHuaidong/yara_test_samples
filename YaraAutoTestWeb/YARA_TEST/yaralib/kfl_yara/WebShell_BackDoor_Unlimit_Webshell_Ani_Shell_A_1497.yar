rule WebShell_BackDoor_Unlimit_Webshell_Ani_Shell_A_1497 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file Ani-Shell.php"
    family = "Webshell"
    hacker = "None"
    hash = "889bfc9fbb8ee7832044fc575324d01a"
    judge = "unknown"
    reference = "None"
    score = 70
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Ani.Shell.A"
    threattype = "BackDoor"
  strings:
    $s0 = "$Python_CODE = \"I"
    $s6 = "$passwordPrompt = \"\\n================================================="
    $s7 = "fputs ($sockfd ,\"\\n==============================================="
  condition:
    1 of them
}