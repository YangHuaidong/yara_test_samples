rule WebShell_BackDoor_Unlimit_Webshell_R57_1_4_0_A_1704 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file r57.1.4.0.php"
    family = "Webshell"
    hacker = "None"
    hash = "574f3303e131242568b0caf3de42f325"
    judge = "unknown"
    reference = "None"
    score = 70
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.R57.1.4.0.A"
    threattype = "BackDoor"
  strings:
    $s4 = "@ini_set('error_log',NULL);" fullword
    $s6 = "$pass='abcdef1234567890abcdef1234567890';" fullword
    $s7 = "@ini_restore(\"disable_functions\");" fullword
    $s9 = "@ini_restore(\"safe_mode_exec_dir\");" fullword
  condition:
    all of them
}