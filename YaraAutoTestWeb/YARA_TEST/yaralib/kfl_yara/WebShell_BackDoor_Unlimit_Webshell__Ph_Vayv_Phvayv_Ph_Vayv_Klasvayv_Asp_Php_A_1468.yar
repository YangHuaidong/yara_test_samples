rule WebShell_BackDoor_Unlimit_Webshell__Ph_Vayv_Phvayv_Ph_Vayv_Klasvayv_Asp_Php_A_1468 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "PHP Webshells Github Archive - from files PH Vayv.php, PHVayv.php, PH_Vayv.php, klasvayv.asp.php.txt"
    family = "Webshell"
    hacker = "None"
    hash0 = "b51962a1ffa460ec793317571fc2f46042fd13ee"
    hash1 = "408ac9ca3d435c0f78bda370b33e84ba25afc357"
    hash2 = "4003ae289e3ae036755976f8d2407c9381ff5653"
    hash3 = "4f83bc2836601225a115b5ad54496428a507a361"
    judge = "unknown"
    reference = "None"
    super_rule = 1
    threatname = "WebShell[BackDoor]/Unlimit.Webshell..Ph.Vayv.Phvayv.Ph.Vayv.Klasvayv.Asp.Php.A"
    threattype = "BackDoor"
  strings:
    $s1 = "<font color=\"#000000\">Sil</font></a></font></td>" fullword
    $s5 = "<td width=\"122\" height=\"17\" bgcolor=\"#9F9F9F\">" fullword
    $s6 = "onfocus=\"if (this.value == 'Kullan" fullword
    $s16 = "<img border=\"0\" src=\"http://www.aventgrup.net/arsiv/klasvayv/1.0/2.gif\">"
  condition:
    2 of them
}