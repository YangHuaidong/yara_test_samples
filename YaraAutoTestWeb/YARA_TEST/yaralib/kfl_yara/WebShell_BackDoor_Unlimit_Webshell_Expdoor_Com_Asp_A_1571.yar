rule WebShell_BackDoor_Unlimit_Webshell_Expdoor_Com_Asp_A_1571 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/03/28"
    description = "Web shells - generated from file Expdoor.com ASP.asp"
    family = "Webshell"
    hacker = "None"
    hash = "caef01bb8906d909f24d1fa109ea18a7"
    judge = "unknown"
    reference = "None"
    score = 70
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Expdoor.Com.Asp.A"
    threattype = "BackDoor"
  strings:
    $s4 = "\">www.Expdoor.com</a>" fullword
    $s5 = "    <input name=\"FileName\" type=\"text\" value=\"Asp_ver.Asp\" size=\"20\" max"
    $s10 = "set file=fs.OpenTextFile(server.MapPath(FileName),8,True)  '" fullword
    $s14 = "set fs=server.CreateObject(\"Scripting.FileSystemObject\")   '" fullword
    $s16 = "<TITLE>Expdoor.com ASP" fullword
  condition:
    2 of them
}