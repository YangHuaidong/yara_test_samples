rule WebShell_BackDoor_Unlimit_Webshell_Php_G5_A_1663 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file G5.php"
    family = "Webshell"
    hacker = "None"
    hash = "95b4a56140a650c74ed2ec36f08d757f"
    judge = "unknown"
    reference = "None"
    score = 70
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Php.G5.A"
    threattype = "BackDoor"
  strings:
    $s3 = "echo \"Hacking Mode?<br><select name='htype'><option >--------SELECT--------</op"
  condition:
    all of them
}