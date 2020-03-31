rule WebShell_BackDoor_Unlimit_Webshell_Ph_Vayv_Ph_Vayv_A_1647 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file PH Vayv.php"
    family = "Webshell"
    hacker = "None"
    hash = "35fb37f3c806718545d97c6559abd262"
    judge = "unknown"
    reference = "None"
    score = 70
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Ph.Vayv.Ph.Vayv.A"
    threattype = "BackDoor"
  strings:
    $s0 = "style=\"BACKGROUND-COLOR: #eae9e9; BORDER-BOTTOM: #000000 1px in"
    $s4 = "<font color=\"#858585\">SHOPEN</font></a></font><font face=\"Verdana\" style"
  condition:
    1 of them
}