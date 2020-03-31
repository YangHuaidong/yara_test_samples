rule WebShell_BackDoor_Unlimit_Webshell_Zehir4_Asp_Php_A_1768 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "PHP Webshells Github Archive - file zehir4.asp.php.txt"
    family = "Webshell"
    hacker = "None"
    hash = "1d9b78b5b14b821139541cc0deb4cbbd994ce157"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Zehir4.Asp.Php.A"
    threattype = "BackDoor"
  strings:
    $s4 = "response.Write \"<title>zehir3 --> powered by zehir &lt;zehirhacker@hotmail.com&"
    $s11 = "frames.byZehir.document.execCommand("
    $s15 = "frames.byZehir.document.execCommand(co"
  condition:
    2 of them
}