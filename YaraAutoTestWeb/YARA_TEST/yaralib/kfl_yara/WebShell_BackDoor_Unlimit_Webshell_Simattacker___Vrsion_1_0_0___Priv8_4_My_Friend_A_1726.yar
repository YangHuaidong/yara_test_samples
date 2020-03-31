rule WebShell_BackDoor_Unlimit_Webshell_Simattacker___Vrsion_1_0_0___Priv8_4_My_Friend_A_1726 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "PHP Webshells Github Archive - file SimAttacker - Vrsion 1.0.0 - priv8 4 My friend.php"
    family = "Webshell"
    hacker = "None"
    hash = "6454cc5ab73143d72cf0025a81bd1fe710351b44"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Simattacker...Vrsion.1.0.0...Priv8.4.My.Friend.A"
    threattype = "BackDoor"
  strings:
    $s4 = "&nbsp;Iranian Hackers : WWW.SIMORGH-EV.COM <br>" fullword
    $s5 = "//fake mail = Use victim server 4 DOS - fake mail " fullword
    $s10 = "<a style=\"TEXT-DECORATION: none\" href=\"http://www.simorgh-ev.com\">" fullword
    $s16 = "error_reporting(E_ERROR | E_WARNING | E_PARSE);" fullword
    $s17 = "echo \"<font size='1' color='#999999'>Dont in windows\";" fullword
    $s19 = "$Comments=$_POST['Comments'];" fullword
    $s20 = "Victim Mail :<br><input type='text' name='to' ><br>" fullword
  condition:
    3 of them
}