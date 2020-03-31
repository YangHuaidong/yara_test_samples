rule WebShell_BackDoor_Unlimit_Webshell_Reader_Asp_Php_A_1709 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "PHP Webshells Github Archive - file reader.asp.php.txt"
    family = "Webshell"
    hacker = "None"
    hash = "70656f3495e2b3ad391a77d5208eec0fb9e2d931"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Reader.Asp.Php.A"
    threattype = "BackDoor"
  strings:
    $s5 = "ster\" name=submit> </Font> &nbsp; &nbsp; &nbsp; <a href=mailto:mailbomb@hotmail"
    $s12 = " HACKING " fullword
    $s16 = "FONT-WEIGHT: bold; BACKGROUND: #ffffff url('images/cellpic1.gif'); TEXT-INDENT: "
    $s20 = "PADDING-RIGHT: 8px; PADDING-LEFT: 8px; FONT-WEIGHT: bold; FONT-SIZE: 11px; BACKG"
  condition:
    3 of them
}