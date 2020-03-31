rule WebShell_BackDoor_Unlimit_Backdoor__Fr__A {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file BackDooR (fr).php"
    family = "Backdoor"
    hacker = "None"
    hash = "a79cac2cf86e073a832aaf29a664f4be"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Backdoor..Fr..A"
    threattype = "BackDoor"
  strings:
    $s3 = "print(\"<p align=\\\"center\\\"><font size=\\\"5\\\">Exploit include "
  condition:
    all of them
}