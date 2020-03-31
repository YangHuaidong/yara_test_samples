rule WebShell_BackDoor_Unlimit_Webshell_Php_List_A_1667 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file list.php"
    family = "Webshell"
    hacker = "None"
    hash = "922b128ddd90e1dc2f73088956c548ed"
    judge = "unknown"
    reference = "None"
    score = 70
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Php.List.A"
    threattype = "BackDoor"
  strings:
    $s1 = "// list.php = Directory & File Listing" fullword
    $s2 = "    echo \"( ) <a href=?file=\" . $fichero . \"/\" . $filename . \">\" . $filena"
    $s9 = "// by: The Dark Raver" fullword
  condition:
    1 of them
}