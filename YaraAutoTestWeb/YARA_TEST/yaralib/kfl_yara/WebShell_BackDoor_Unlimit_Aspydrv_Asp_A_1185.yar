rule WebShell_BackDoor_Unlimit_Aspydrv_Asp_A_1185 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Semi-Auto-generated  - file aspydrv.asp.txt"
    family = "Aspydrv"
    hacker = "None"
    hash = "1c01f8a88baee39aa1cebec644bbcb99"
    judge = "unknown"
    reference = "None"
    score = 60
    threatname = "WebShell[BackDoor]/Unlimit.Aspydrv.Asp.A"
    threattype = "BackDoor"
  strings:
    $s0 = "If mcolFormElem.Exists(LCase(sIndex)) Then Form = mcolFormElem.Item(LCase(sIndex))"
    $s1 = "password"
    $s2 = "session(\"shagman\")="
  condition:
    2 of them
}