rule WebShell_BackDoor_Unlimit_Webshell_Jsp_Up_A_1622 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file up.jsp"
    family = "Webshell"
    hacker = "None"
    hash = "515a5dd86fe48f673b72422cccf5a585"
    judge = "unknown"
    reference = "None"
    score = 70
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Jsp.Up.A"
    threattype = "BackDoor"
  strings:
    $s9 = "// BUG: Corta el fichero si es mayor de 640Ks" fullword
  condition:
    all of them
}