rule WebShell_BackDoor_Unlimit_Byshell063_Ntboot_A_1202 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file ntboot.exe"
    family = "Byshell063"
    hacker = "None"
    hash = "99b5f49db6d6d9a9faeffb29fd8e6d8c"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Byshell063.Ntboot.A"
    threattype = "BackDoor"
  strings:
    $s0 = "SYSTEM\\CurrentControlSet\\Services\\NtBoot"
    $s1 = "Failure ... Access is Denied !"
    $s2 = "Dumping Description to Registry..."
    $s3 = "Opening Service .... Failure !"
  condition:
    all of them
}