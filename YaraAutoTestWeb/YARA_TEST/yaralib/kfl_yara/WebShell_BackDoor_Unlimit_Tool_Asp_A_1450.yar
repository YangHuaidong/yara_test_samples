rule WebShell_BackDoor_Unlimit_Tool_Asp_A_1450 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Semi-Auto-generated  - file Tool.asp.txt"
    family = "Tool"
    hacker = "None"
    hash = "8febea6ca6051ae5e2ad4c78f4b9c1f2"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Tool.Asp.A"
    threattype = "BackDoor"
  strings:
    $s0 = "mailto:rhfactor@antisocial.com"
    $s2 = "?raiz=root"
    $s3 = "DIGO CORROMPIDO<BR>CORRUPT CODE"
    $s4 = "key = \"5DCADAC1902E59F7273E1902E5AD8414B1902E5ABF3E661902E5B554FC41902E53205CA0"
  condition:
    2 of them
}