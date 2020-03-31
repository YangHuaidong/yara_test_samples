rule WebShell_BackDoor_Unlimit_Webshell_Phpspy2010_A_1701 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file phpspy2010.php"
    family = "Webshell"
    hacker = "None"
    hash = "14ae0e4f5349924a5047fed9f3b105c5"
    judge = "unknown"
    reference = "None"
    score = 70
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Phpspy2010.A"
    threattype = "BackDoor"
  strings:
    $s3 = "eval(gzinflate(base64_decode("
    $s5 = "//angel" fullword
    $s8 = "$admin['cookiedomain'] = '';" fullword
  condition:
    all of them
}