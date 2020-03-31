rule WebShell_BackDoor_Unlimit_Adjustcr_A {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file adjustcr.exe"
    family = "Adjustcr"
    hacker = "None"
    hash = "17037fa684ef4c90a25ec5674dac2eb6"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Adjustcr.A"
    threattype = "BackDoor"
  strings:
    $s0 = "$Info: This file is packed with the UPX executable packer $"
    $s2 = "$License: NRV for UPX is distributed under special license $"
    $s6 = "AdjustCR Carr"
    $s7 = "ION\\System\\FloatingPo"
  condition:
    all of them
}