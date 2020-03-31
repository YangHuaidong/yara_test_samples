rule WebShell_BackDoor_Unlimit_Webshell_Webshells_New_Asp_A_1743 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/03/28"
    description = "Web shells - generated from file Asp.asp"
    family = "Webshell"
    hacker = "None"
    hash = "32c87744ea404d0ea0debd55915010b7"
    judge = "unknown"
    reference = "None"
    score = 70
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Webshells.New.Asp.A"
    threattype = "BackDoor"
  strings:
    $s1 = "Execute MorfiCoder(\")/*/z/*/(tseuqer lave\")" fullword
    $s2 = "Function MorfiCoder(Code)" fullword
    $s3 = "MorfiCoder=Replace(Replace(StrReverse(Code),\"/*/\",\"\"\"\"),\"\\*\\\",vbCrlf)" fullword
  condition:
    1 of them
}