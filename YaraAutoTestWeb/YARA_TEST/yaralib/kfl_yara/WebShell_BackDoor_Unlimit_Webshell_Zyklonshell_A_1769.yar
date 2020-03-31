rule WebShell_BackDoor_Unlimit_Webshell_Zyklonshell_A_1769 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "PHP Webshells Github Archive - file ZyklonShell.php"
    family = "Webshell"
    hacker = "None"
    hash = "3fa7e6f3566427196ac47551392e2386a038d61c"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Zyklonshell.A"
    threattype = "BackDoor"
  strings:
    $s0 = "The requested URL /Nemo/shell/zyklonshell.txt was not found on this server.<P>" fullword
    $s1 = "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">" fullword
    $s2 = "<TITLE>404 Not Found</TITLE>" fullword
    $s3 = "<H1>Not Found</H1>" fullword
  condition:
    all of them
}