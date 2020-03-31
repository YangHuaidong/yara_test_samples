rule WebShell_BackDoor_Unlimit_Sh_Php_Php_A_1421 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Semi-Auto-generated  - file sh.php.php.txt"
    family = "Sh"
    hacker = "None"
    hash = "330af9337ae51d0bac175ba7076d6299"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Sh.Php.Php.A"
    threattype = "BackDoor"
  strings:
    $s1 = "$ar_file=array('/etc/passwd','/etc/shadow','/etc/master.passwd','/etc/fstab','/e"
    $s2 = "Show <input type=text size=5 value=\".((isset($_POST['br_st']))?$_POST['br_st']:"
  condition:
    1 of them
}