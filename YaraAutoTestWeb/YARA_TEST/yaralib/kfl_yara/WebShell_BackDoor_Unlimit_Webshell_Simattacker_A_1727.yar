rule WebShell_BackDoor_Unlimit_Webshell_Simattacker_A_1727 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "PHP Webshells Github Archive - file simattacker.php"
    family = "Webshell"
    hacker = "None"
    hash = "258297b62aeaf4650ce04642ad5f19be25ec29c9"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Simattacker.A"
    threattype = "BackDoor"
  strings:
    $s1 = "$from = rand (71,1020000000).\"@\".\"Attacker.com\";" fullword
    $s4 = "&nbsp;Turkish Hackers : WWW.ALTURKS.COM <br>" fullword
    $s5 = "&nbsp;Programer : SimAttacker - Edited By KingDefacer<br>" fullword
    $s6 = "//fake mail = Use victim server 4 DOS - fake mail " fullword
    $s10 = "&nbsp;e-mail : kingdefacer@msn.com<br>" fullword
    $s17 = "error_reporting(E_ERROR | E_WARNING | E_PARSE);" fullword
    $s18 = "echo \"<font size='1' color='#999999'>Dont in windows\";" fullword
    $s20 = "$Comments=$_POST['Comments'];" fullword
  condition:
    2 of them
}