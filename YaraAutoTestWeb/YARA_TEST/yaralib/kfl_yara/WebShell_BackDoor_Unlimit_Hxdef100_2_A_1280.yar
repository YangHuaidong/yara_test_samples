rule WebShell_BackDoor_Unlimit_Hxdef100_2_A_1280 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file hxdef100.exe"
    family = "Hxdef100"
    hacker = "None"
    hash = "1b393e2e13b9c57fb501b7cd7ad96b25"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Hxdef100.2.A"
    threattype = "BackDoor"
  strings:
    $s0 = "\\\\.\\mailslot\\hxdef-rkc000"
    $s2 = "Shared Components\\On Access Scanner\\BehaviourBlo"
    $s6 = "SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\"
  condition:
    all of them
}