rule WebShell_BackDoor_Unlimit_Webshell_Ftpsearch_A_1572 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "PHP Webshells Github Archive - file ftpsearch.php"
    family = "Webshell"
    hacker = "None"
    hash = "c945f597552ccb8c0309ad6d2831c8cabdf4e2d6"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Ftpsearch.A"
    threattype = "BackDoor"
  strings:
    $s0 = "echo \"[-] Error : coudn't read /etc/passwd\";" fullword
    $s9 = "@$ftp=ftp_connect('127.0.0.1');" fullword
    $s12 = "echo \"<title>Edited By KingDefacer</title><body>\";" fullword
    $s19 = "echo \"[+] Founded \".sizeof($users).\" entrys in /etc/passwd\\n\";" fullword
  condition:
    2 of them
}