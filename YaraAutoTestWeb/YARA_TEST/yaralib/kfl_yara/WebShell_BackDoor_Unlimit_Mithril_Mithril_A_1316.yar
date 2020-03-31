rule WebShell_BackDoor_Unlimit_Mithril_Mithril_A_1316 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file Mithril.exe"
    family = "Mithril"
    hacker = "None"
    hash = "017191562d72ab0ca551eb89256650bd"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Mithril.Mithril.A"
    threattype = "BackDoor"
  strings:
    $s0 = "OpenProcess error!"
    $s1 = "WriteProcessMemory error!"
    $s4 = "GetProcAddress error!"
    $s5 = "HHt`HHt\\"
    $s6 = "Cmaudi0"
    $s7 = "CreateRemoteThread error!"
    $s8 = "Kernel32"
    $s9 = "VirtualAllocEx error!"
  condition:
    all of them
}