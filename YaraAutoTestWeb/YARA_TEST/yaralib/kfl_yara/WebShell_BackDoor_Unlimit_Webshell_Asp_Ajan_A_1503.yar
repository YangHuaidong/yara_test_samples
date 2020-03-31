rule WebShell_BackDoor_Unlimit_Webshell_Asp_Ajan_A_1503 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file Ajan.asp"
    family = "Webshell"
    hacker = "None"
    hash = "b6f468252407efc2318639da22b08af0"
    judge = "unknown"
    reference = "None"
    score = 70
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Asp.Ajan.A"
    threattype = "BackDoor"
  strings:
    $s3 = "entrika.write \"BinaryStream.SaveToFile \"\"c:\\downloaded.zip\"\", adSaveCreate"
  condition:
    all of them
}