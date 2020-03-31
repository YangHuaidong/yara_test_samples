rule WebShell_BackDoor_Unlimit_Webshell_Caidao_Shell_Ice_A_1548 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file ice.asp"
    family = "Webshell"
    hacker = "None"
    hash = "6560b436d3d3bb75e2ef3f032151d139"
    judge = "unknown"
    reference = "None"
    score = 70
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Caidao.Shell.Ice.A"
    threattype = "BackDoor"
  strings:
    $s0 = "<%eval request(\"ice\")%>" fullword
  condition:
    all of them
}