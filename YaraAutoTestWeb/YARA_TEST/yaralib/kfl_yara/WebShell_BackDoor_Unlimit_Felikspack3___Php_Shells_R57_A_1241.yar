rule WebShell_BackDoor_Unlimit_Felikspack3___Php_Shells_R57_A_1241 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file r57.php"
    family = "Felikspack3"
    hacker = "None"
    hash = "903908b77a266b855262cdbce81c3f72"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Felikspack3...Php.Shells.R57.A"
    threattype = "BackDoor"
  strings:
    $s1 = "$sql = \"LOAD DATA INFILE \\\"\".$_POST['test3_file']."
  condition:
    all of them
}