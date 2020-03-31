rule WebShell_BackDoor_Unlimit_Hidshell_Php_Php_A_1275 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Semi-Auto-generated  - file hidshell.php.php.txt"
    family = "Hidshell"
    hacker = "None"
    hash = "c2f3327d60884561970c63ffa09439a4"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Hidshell.Php.Php.A"
    threattype = "BackDoor"
  strings:
    $s0 = "<?$d='G7mHWQ9vvXiL/QX2oZ2VTDpo6g3FYAa6X+8DMIzcD0eHZaBZH7jFpZzUz7XNenxSYvBP2Wy36U"
  condition:
    all of them
}