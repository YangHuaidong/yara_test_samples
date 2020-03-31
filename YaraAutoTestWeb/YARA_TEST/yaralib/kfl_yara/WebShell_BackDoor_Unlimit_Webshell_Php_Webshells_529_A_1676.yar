rule WebShell_BackDoor_Unlimit_Webshell_Php_Webshells_529_A_1676 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "PHP Webshells Github Archive - file 529.php"
    family = "Webshell"
    hacker = "None"
    hash = "ba3fb2995528307487dff7d5b624d9f4c94c75d3"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Php.Webshells.529.A"
    threattype = "BackDoor"
  strings:
    $s0 = "<p>More: <a href=\"/\">Md5Cracking.Com Crew</a> " fullword
    $s7 = "href=\"/\" title=\"Securityhouse\">Security House - Shell Center - Edited By Kin"
    $s9 = "echo '<PRE><P>This is exploit from <a " fullword
    $s10 = "This Exploit Was Edited By KingDefacer" fullword
    $s13 = "safe_mode and open_basedir Bypass PHP 5.2.9 " fullword
    $s14 = "$hardstyle = explode(\"/\", $file); " fullword
    $s20 = "while($level--) chdir(\"..\"); " fullword
  condition:
    2 of them
}