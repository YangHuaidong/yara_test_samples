rule WebShell_BackDoor_Unlimit_Hxdef100_A_1281 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file hxdef100.exe"
    family = "Hxdef100"
    hacker = "None"
    hash = "55cc1769cef44910bd91b7b73dee1f6c"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Hxdef100.A"
    threattype = "BackDoor"
  strings:
    $s0 = "RtlAnsiStringToUnicodeString"
    $s8 = "SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\"
    $s9 = "\\\\.\\mailslot\\hxdef-rk100sABCDEFGH"
  condition:
    all of them
}