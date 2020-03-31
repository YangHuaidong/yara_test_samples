rule WebShell_BackDoor_Unlimit_Webshell_Php_150_A_1650 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file 150.php"
    family = "Webshell"
    hacker = "None"
    hash = "400c4b0bed5c90f048398e1d268ce4dc"
    judge = "unknown"
    reference = "None"
    score = 70
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Php.150.A"
    threattype = "BackDoor"
  strings:
    $s0 = "HJ3HjqxclkZfp"
    $s1 = "<? eval(gzinflate(base64_decode('" fullword
  condition:
    all of them
}