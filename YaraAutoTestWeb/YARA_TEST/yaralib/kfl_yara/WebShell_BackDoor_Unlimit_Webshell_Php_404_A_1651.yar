rule WebShell_BackDoor_Unlimit_Webshell_Php_404_A_1651 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file 404.php"
    family = "Webshell"
    hacker = "None"
    hash = "078c55ac475ab9e028f94f879f548bca"
    judge = "unknown"
    reference = "None"
    score = 70
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Php.404.A"
    threattype = "BackDoor"
  strings:
    $s4 = "<span>Posix_getpwuid (\"Read\" /etc/passwd)"
  condition:
    all of them
}