rule WebShell_BackDoor_Unlimit_Webshell_Webshells_New_Php5_A_1755 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/03/28"
    description = "Web shells - generated from file php5.php"
    family = "Webshell"
    hacker = "None"
    hash = "cf2ab009cbd2576a806bfefb74906fdf"
    judge = "unknown"
    reference = "None"
    score = 70
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Webshells.New.Php5.A"
    threattype = "BackDoor"
  strings:
    $s0 = "<?$_uU=chr(99).chr(104).chr(114);$_cC=$_uU(101).$_uU(118).$_uU(97).$_uU(108).$_u"
  condition:
    all of them
}