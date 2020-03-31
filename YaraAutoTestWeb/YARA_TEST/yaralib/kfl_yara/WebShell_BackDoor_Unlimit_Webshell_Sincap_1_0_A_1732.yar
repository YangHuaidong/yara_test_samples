rule WebShell_BackDoor_Unlimit_Webshell_Sincap_1_0_A_1732 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "PHP Webshells Github Archive - file Sincap 1.0.php"
    family = "Webshell"
    hacker = "None"
    hash = "9b72635ff1410fa40c4e15513ae3a496d54f971c"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Sincap.1.0.A"
    threattype = "BackDoor"
  strings:
    $s4 = "</font></span><a href=\"mailto:shopen@aventgrup.net\">" fullword
    $s5 = "<title>:: AventGrup ::.. - Sincap 1.0 | Session(Oturum) B" fullword
    $s9 = "</span>Avrasya Veri ve NetWork Teknolojileri Geli" fullword
    $s12 = "while (($ekinci=readdir ($sedat))){" fullword
    $s19 = "$deger2= \"$ich[$tampon4]\";" fullword
  condition:
    2 of them
}