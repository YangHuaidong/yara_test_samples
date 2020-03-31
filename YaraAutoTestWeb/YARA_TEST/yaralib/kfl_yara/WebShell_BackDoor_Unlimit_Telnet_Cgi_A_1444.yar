rule WebShell_BackDoor_Unlimit_Telnet_Cgi_A_1444 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Semi-Auto-generated  - file telnet.cgi.txt"
    family = "Telnet"
    hacker = "None"
    hash = "dee697481383052980c20c48de1598d1"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Telnet.Cgi.A"
    threattype = "BackDoor"
  strings:
    $s0 = "www.rohitab.com"
    $s1 = "W A R N I N G: Private Server"
    $s2 = "print \"Set-Cookie: SAVEDPWD=;\\n\"; # remove password cookie"
    $s3 = "$Prompt = $WinNT ? \"$CurrentDir> \" : \"[admin\\@$ServerName $C"
  condition:
    1 of them
}