rule WebShell_BackDoor_Unlimit_Hkdoordll_A_1276 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file hkdoordll.dll"
    family = "Hkdoordll"
    hacker = "None"
    hash = "b715c009d47686c0e62d0981efce2552"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Hkdoordll.A"
    threattype = "BackDoor"
  strings:
    $s6 = "Can't uninstall,maybe the backdoor is not installed or,the Password you INPUT is"
  condition:
    all of them
}