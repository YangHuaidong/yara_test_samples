rule WebShell_BackDoor_Unlimit_Dbgiis6Cli_A_1221 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file dbgiis6cli.exe"
    family = "Dbgiis6Cli"
    hacker = "None"
    hash = "3044dceb632b636563f66fee3aaaf8f3"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Dbgiis6Cli.A"
    threattype = "BackDoor"
  strings:
    $s0 = "User-Agent: Mozilla/4.0 (compatible; MSIE 5.01; Windows NT 5.0)"
    $s5 = "###command:(NO more than 100 bytes!)"
  condition:
    all of them
}