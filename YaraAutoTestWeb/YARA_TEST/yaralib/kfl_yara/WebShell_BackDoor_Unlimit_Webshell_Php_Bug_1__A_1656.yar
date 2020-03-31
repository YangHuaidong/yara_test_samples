rule WebShell_BackDoor_Unlimit_Webshell_Php_Bug_1__A_1656 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file bug (1).php"
    family = "Webshell"
    hacker = "None"
    hash = "91c5fae02ab16d51fc5af9354ac2f015"
    judge = "unknown"
    reference = "None"
    score = 70
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Php.Bug.1..A"
    threattype = "BackDoor"
  strings:
    $s0 = "@include($_GET['bug']);" fullword
  condition:
    all of them
}