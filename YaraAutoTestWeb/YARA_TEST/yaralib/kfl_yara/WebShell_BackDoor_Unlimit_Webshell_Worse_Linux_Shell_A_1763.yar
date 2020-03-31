rule WebShell_BackDoor_Unlimit_Webshell_Worse_Linux_Shell_A_1763 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "PHP Webshells Github Archive - file Worse Linux Shell.php"
    family = "Webshell"
    hacker = "None"
    hash = "64623ab1246bc8f7d256b25f244eb2b41f543e96"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Worse.Linux.Shell.A"
    threattype = "BackDoor"
  strings:
    $s4 = "if( $_POST['_act'] == \"Upload!\" ) {" fullword
    $s5 = "print \"<center><h1>#worst @dal.net</h1></center>\";" fullword
    $s7 = "print \"<center><h1>Linux Shells</h1></center>\";" fullword
    $s8 = "$currentCMD = \"ls -la\";" fullword
    $s14 = "print \"<tr><td><b>System type:</b></td><td>$UName</td></tr>\";" fullword
    $s19 = "$currentCMD = str_replace(\"\\\\\\\\\",\"\\\\\",$_POST['_cmd']);" fullword
  condition:
    2 of them
}