rule WebShell_BackDoor_Unlimit_Webshell_Php_Sh_Server_A_1672 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file server.php"
    family = "Webshell"
    hacker = "None"
    hash = "d87b019e74064aa90e2bb143e5e16cfa"
    judge = "unknown"
    reference = "None"
    score = 50
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Php.Sh.Server.A"
    threattype = "BackDoor"
  strings:
    $s0 = "eval(getenv('HTTP_CODE'));" fullword
  condition:
    all of them
}