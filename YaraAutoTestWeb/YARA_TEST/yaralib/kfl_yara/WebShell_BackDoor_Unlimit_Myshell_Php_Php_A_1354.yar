rule WebShell_BackDoor_Unlimit_Myshell_Php_Php_A_1354 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Semi-Auto-generated  - file myshell.php.php.txt"
    family = "Myshell"
    hacker = "None"
    hash = "62783d1db52d05b1b6ae2403a7044490"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Myshell.Php.Php.A"
    threattype = "BackDoor"
  strings:
    $s0 = "@chdir($work_dir) or ($shellOutput = \"MyShell: can't change directory."
    $s1 = "echo \"<font color=$linkColor><b>MyShell file editor</font> File:<font color"
    $s2 = " $fileEditInfo = \"&nbsp;&nbsp;:::::::&nbsp;&nbsp;Owner: <font color=$"
  condition:
    2 of them
}