rule WebShell_BackDoor_Unlimit_Webshell_Ntdaddy_V1_9_A_1646 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "PHP Webshells Github Archive - file NTDaddy v1.9.php"
    family = "Webshell"
    hacker = "None"
    hash = "79519aa407fff72b7510c6a63c877f2e07d7554b"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Ntdaddy.V1.9.A"
    threattype = "BackDoor"
  strings:
    $s2 = "|     -obzerve : mr_o@ihateclowns.com |" fullword
    $s6 = "szTempFile = \"C:\\\" & oFileSys.GetTempName( )" fullword
    $s13 = "<form action=ntdaddy.asp method=post>" fullword
    $s17 = "response.write(\"<ERROR: THIS IS NOT A TEXT FILE>\")" fullword
  condition:
    2 of them
}