rule WebShell_BackDoor_Unlimit_By063Cli_A_1198 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file by063cli.exe"
    family = "By063Cli"
    hacker = "None"
    hash = "49ce26eb97fd13b6d92a5e5d169db859"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.By063Cli.A"
    threattype = "BackDoor"
  strings:
    $s2 = "#popmsghello,are you all right?"
    $s4 = "connect failed,check your network and remote ip."
  condition:
    all of them
}