rule WebShell_BackDoor_Unlimit_Webshell_Metaslsoft_A_1634 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file metaslsoft.php"
    family = "Webshell"
    hacker = "None"
    hash = "aa328ed1476f4a10c0bcc2dde4461789"
    judge = "unknown"
    reference = "None"
    score = 70
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Metaslsoft.A"
    threattype = "BackDoor"
  strings:
    $s7 = "$buff .= \"<tr><td><a href=\\\"?d=\".$pwd.\"\\\">[ $folder ]</a></td><td>LINK</t"
  condition:
    all of them
}