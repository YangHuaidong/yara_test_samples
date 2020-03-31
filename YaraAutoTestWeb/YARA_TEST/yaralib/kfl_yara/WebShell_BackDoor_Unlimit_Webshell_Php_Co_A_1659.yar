rule WebShell_BackDoor_Unlimit_Webshell_Php_Co_A_1659 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file co.php"
    family = "Webshell"
    hacker = "None"
    hash = "62199f5ac721a0cb9b28f465a513874c"
    judge = "unknown"
    reference = "None"
    score = 70
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Php.Co.A"
    threattype = "BackDoor"
  strings:
    $s0 = "cGX6R9q733WvRRjISKHOp9neT7wa6ZAD8uthmVJV" fullword
    $s11 = "6Mk36lz/HOkFfoXX87MpPhZzBQH6OaYukNg1OE1j" fullword
  condition:
    all of them
}