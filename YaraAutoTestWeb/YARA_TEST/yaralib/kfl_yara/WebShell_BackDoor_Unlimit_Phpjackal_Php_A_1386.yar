rule WebShell_BackDoor_Unlimit_Phpjackal_Php_A_1386 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Semi-Auto-generated  - file phpjackal.php.txt"
    family = "Phpjackal"
    hacker = "None"
    hash = "ab230817bcc99acb9bdc0ec6d264d76f"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Phpjackal.Php.A"
    threattype = "BackDoor"
  strings:
    $s3 = "$dl=$_REQUEST['downloaD'];"
    $s4 = "else shelL(\"perl.exe $name $port\");"
  condition:
    1 of them
}