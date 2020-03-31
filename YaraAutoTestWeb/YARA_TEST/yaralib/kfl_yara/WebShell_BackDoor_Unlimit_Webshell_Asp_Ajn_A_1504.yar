rule WebShell_BackDoor_Unlimit_Webshell_Asp_Ajn_A_1504 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file ajn.asp"
    family = "Webshell"
    hacker = "None"
    hash = "aaafafc5d286f0bff827a931f6378d04"
    judge = "unknown"
    reference = "None"
    score = 70
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Asp.Ajn.A"
    threattype = "BackDoor"
  strings:
    $s1 = "seal.write \"Set WshShell = CreateObject(\"\"WScript.Shell\"\")\" & vbcrlf" fullword
    $s6 = "seal.write \"BinaryStream.SaveToFile \"\"c:\\downloaded.zip\"\", adSaveCreateOve"
  condition:
    all of them
}