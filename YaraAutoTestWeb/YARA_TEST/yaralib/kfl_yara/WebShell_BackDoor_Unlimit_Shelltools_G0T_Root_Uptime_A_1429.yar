rule WebShell_BackDoor_Unlimit_Shelltools_G0T_Root_Uptime_A_1429 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file uptime.exe"
    family = "Shelltools"
    hacker = "None"
    hash = "d1f56102bc5d3e2e37ab3ffa392073b9"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Shelltools.G0T.Root.Uptime.A"
    threattype = "BackDoor"
  strings:
    $s0 = "JDiamondCSlC~"
    $s1 = "CharactQA"
    $s2 = "$Info: This file is packed with the UPX executable packer $"
    $s5 = "HandlereateConso"
    $s7 = "ION\\System\\FloatingPo"
  condition:
    all of them
}