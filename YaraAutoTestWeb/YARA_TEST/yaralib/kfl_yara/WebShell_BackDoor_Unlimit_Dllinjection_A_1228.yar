rule WebShell_BackDoor_Unlimit_Dllinjection_A_1228 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file DllInjection.exe"
    family = "Dllinjection"
    hacker = "None"
    hash = "a7b92283a5102886ab8aee2bc5c8d718"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Dllinjection.A"
    threattype = "BackDoor"
  strings:
    $s0 = "\\BDoor\\DllInjecti"
  condition:
    all of them
}