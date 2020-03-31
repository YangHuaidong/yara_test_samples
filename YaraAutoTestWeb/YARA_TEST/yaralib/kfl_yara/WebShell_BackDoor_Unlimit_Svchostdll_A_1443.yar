rule WebShell_BackDoor_Unlimit_Svchostdll_A_1443 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file svchostdll.dll"
    family = "Svchostdll"
    hacker = "None"
    hash = "0f6756c8cb0b454c452055f189e4c3f4"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Svchostdll.A"
    threattype = "BackDoor"
  strings:
    $s0 = "InstallService"
    $s1 = "RundllInstallA"
    $s2 = "UninstallService"
    $s3 = "&G3 Users In RegistryD"
    $s4 = "OL_SHUTDOWN;I"
    $s5 = "SvcHostDLL.dll"
    $s6 = "RundllUninstallA"
    $s7 = "InternetOpenA"
    $s8 = "Check Cloneomplete"
  condition:
    all of them
}