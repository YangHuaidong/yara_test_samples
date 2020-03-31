rule WebShell_BackDoor_Unlimit_Php_Sh_A_1380 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file sh.php"
    family = "Php"
    hacker = "None"
    hash = "1e9e879d49eb0634871e9b36f99fe528"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Php.Sh.A"
    threattype = "BackDoor"
  strings:
    $s1 = "\"@$SERVER_NAME \".exec(\"pwd\")"
  condition:
    all of them
}