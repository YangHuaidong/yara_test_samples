rule WebShell_BackDoor_Unlimit_Webshell_Webshells_New_Php1_A_1753 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/03/28"
    description = "Web shells - generated from file PHP1.php"
    family = "Webshell"
    hacker = "None"
    hash = "14c7281fdaf2ae004ca5fec8753ce3cb"
    judge = "unknown"
    reference = "None"
    score = 70
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Webshells.New.Php1.A"
    threattype = "BackDoor"
  strings:
    $s0 = "<[url=mailto:?@array_map($_GET[]?@array_map($_GET['f'],$_GET[/url]);?>" fullword
    $s2 = ":https://forum.90sec.org/forum.php?mod=viewthread&tid=7316" fullword
    $s3 = "@preg_replace(\"/f/e\",$_GET['u'],\"fengjiao\"); " fullword
  condition:
    1 of them
}