rule WebShell_BackDoor_Unlimit_Pws_Php_Php_A_1395 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Semi-Auto-generated  - file pws.php.php.txt"
    family = "Pws"
    hacker = "None"
    hash = "ecdc6c20f62f99fa265ec9257b7bf2ce"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Pws.Php.Php.A"
    threattype = "BackDoor"
  strings:
    $s0 = "<div align=\"left\"><font size=\"1\">Input command :</font></div>" fullword
    $s1 = "<input type=\"text\" name=\"cmd\" size=\"30\" class=\"input\"><br>" fullword
    $s4 = "<input type=\"text\" name=\"dir\" size=\"30\" value=\"<? passthru(\"pwd\"); ?>"
  condition:
    2 of them
}