rule WebShell_BackDoor_Unlimit_Asp_Dns_A_1180 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-22"
    description = "Laudanum Injector Tools - file dns.asp"
    family = "Asp"
    hacker = "None"
    hash = "5532154dd67800d33dace01103e9b2c4f3d01d51"
    judge = "unknown"
    reference = "http://laudanum.inguardians.com/"
    threatname = "WebShell[BackDoor]/Unlimit.Asp.Dns.A"
    threattype = "BackDoor"
  strings:
    $s1 = "command = \"nslookup -type=\" & qtype & \" \" & query " fullword ascii /* PEStudio Blacklist: strings */
    $s2 = "Set objCmd = objWShell.Exec(command)" fullword ascii /* PEStudio Blacklist: strings */
    $s3 = "Response.Write command & \"<br>\"" fullword ascii /* PEStudio Blacklist: strings */
    $s4 = "<form name=\"dns\" method=\"POST\">" fullword ascii /* PEStudio Blacklist: strings */
  condition:
    filesize < 21KB and all of them
}