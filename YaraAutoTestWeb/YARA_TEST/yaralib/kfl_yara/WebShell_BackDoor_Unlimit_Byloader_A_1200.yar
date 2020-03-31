rule WebShell_BackDoor_Unlimit_Byloader_A_1200 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file byloader.exe"
    family = "Byloader"
    hacker = "None"
    hash = "0f0d6dc26055653f5844ded906ce52df"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Byloader.A"
    threattype = "BackDoor"
  strings:
    $s0 = "SYSTEM\\CurrentControlSet\\Services\\NtfsChk"
    $s1 = "Failure ... Access is Denied !"
    $s2 = "NTFS Disk Driver Checking Service"
    $s3 = "Dumping Description to Registry..."
    $s4 = "Opening Service .... Failure !"
  condition:
    all of them
}