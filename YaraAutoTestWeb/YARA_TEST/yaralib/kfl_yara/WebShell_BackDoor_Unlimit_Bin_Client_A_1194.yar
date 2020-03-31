rule WebShell_BackDoor_Unlimit_Bin_Client_A_1194 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file Client.exe"
    family = "Bin"
    hacker = "None"
    hash = "9f0a74ec81bc2f26f16c5c172b80eca7"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Bin.Client.A"
    threattype = "BackDoor"
  strings:
    $s0 = "=====Remote Shell Closed====="
    $s2 = "All Files(*.*)|*.*||"
    $s6 = "WSAStartup Error!"
    $s7 = "SHGetFileInfoA"
    $s8 = "CreateThread False!"
    $s9 = "Port Number Error"
  condition:
    4 of them
}