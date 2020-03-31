rule WebShell_BackDoor_Unlimit_Fso_S_Ajan_2_A_1247 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file ajan.asp"
    family = "Fso"
    hacker = "None"
    hash = "22194f8c44524f80254e1b5aec67b03e"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Fso.S.Ajan.2.A"
    threattype = "BackDoor"
  strings:
    $s2 = "\"Set WshShell = CreateObject(\"\"WScript.Shell\"\")"
    $s3 = "/file.zip"
  condition:
    all of them
}