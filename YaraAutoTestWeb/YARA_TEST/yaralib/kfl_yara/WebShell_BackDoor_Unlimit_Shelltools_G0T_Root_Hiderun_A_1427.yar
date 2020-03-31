rule WebShell_BackDoor_Unlimit_Shelltools_G0T_Root_Hiderun_A_1427 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file HideRun.exe"
    family = "Shelltools"
    hacker = "None"
    hash = "45436d9bfd8ff94b71eeaeb280025afe"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Shelltools.G0T.Root.Hiderun.A"
    threattype = "BackDoor"
  strings:
    $s0 = "Usage -- hiderun [AppName]"
    $s7 = "PVAX SW, Alexey A. Popoff, Moscow, 1997."
  condition:
    all of them
}