rule WebShell_BackDoor_Unlimit_Webshell_Ayyildiz_Tim___Ayt__Shell_V_2_1_Biz_A_1521 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "PHP Webshells Github Archive - file Ayyildiz Tim  -AYT- Shell v 2.1 Biz.php"
    family = "Webshell"
    hacker = "None"
    hash = "5fe8c1d01dc5bc70372a8a04410faf8fcde3cb68"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Ayyildiz.Tim...Ayt..Shell.V.2.1.Biz.A"
    threattype = "BackDoor"
  strings:
    $s7 = "<meta name=\"Copyright\" content=TouCh By iJOo\">" fullword
    $s11 = "directory... Trust me - it works :-) */" fullword
    $s15 = "/* ls looks much better with ' -F', IMHO. */" fullword
    $s16 = "} else if ($command == 'ls') {" fullword
  condition:
    3 of them
}