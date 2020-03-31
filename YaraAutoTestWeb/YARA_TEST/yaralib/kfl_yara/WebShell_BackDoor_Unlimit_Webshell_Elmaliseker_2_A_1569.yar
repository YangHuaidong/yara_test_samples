rule WebShell_BackDoor_Unlimit_Webshell_Elmaliseker_2_A_1569 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file elmaliseker.asp"
    family = "Webshell"
    hacker = "None"
    hash = "b32d1730d23a660fd6aa8e60c3dc549f"
    judge = "unknown"
    reference = "None"
    score = 70
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Elmaliseker.2.A"
    threattype = "BackDoor"
  strings:
    $s1 = "<td<%if (FSO.GetExtensionName(path & \"\\\" & oFile.Name)=\"lnk\") or (FSO.GetEx"
    $s6 = "<input type=button value=Save onclick=\"EditorCommand('Save')\"> <input type=but"
  condition:
    all of them
}