rule WebShell_BackDoor_Unlimit_Webshell_Mumaasp_Com_A_1637 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file mumaasp.com.asp"
    family = "Webshell"
    hacker = "None"
    hash = "cce32b2e18f5357c85b6d20f564ebd5d"
    judge = "unknown"
    reference = "None"
    score = 70
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Mumaasp.Com.A"
    threattype = "BackDoor"
  strings:
    $s0 = "&9K_)P82ai,A}I92]R\"q!C:RZ}S6]=PaTTR"
  condition:
    all of them
}