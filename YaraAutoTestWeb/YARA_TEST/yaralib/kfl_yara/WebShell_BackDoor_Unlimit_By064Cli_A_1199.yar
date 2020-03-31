rule WebShell_BackDoor_Unlimit_By064Cli_A_1199 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file by064cli.exe"
    family = "By064Cli"
    hacker = "None"
    hash = "10e0dff366968b770ae929505d2a9885"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.By064Cli.A"
    threattype = "BackDoor"
  strings:
    $s7 = "packet dropped,redirecting"
    $s9 = "input the password(the default one is 'by')"
  condition:
    all of them
}