rule WebShell_BackDoor_Unlimit_Worse_Linux_Shell_Php_A_1773 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Semi-Auto-generated  - file Worse Linux Shell.php.txt"
    family = "Worse"
    hacker = "None"
    hash = "8338c8d9eab10bd38a7116eb534b5fa2"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Worse.Linux.Shell.Php.A"
    threattype = "BackDoor"
  strings:
    $s1 = "print \"<tr><td><b>Server is:</b></td><td>\".$_SERVER['SERVER_SIGNATURE'].\"</td"
    $s2 = "print \"<tr><td><b>Execute command:</b></td><td><input size=100 name=\\\"_cmd"
  condition:
    1 of them
}