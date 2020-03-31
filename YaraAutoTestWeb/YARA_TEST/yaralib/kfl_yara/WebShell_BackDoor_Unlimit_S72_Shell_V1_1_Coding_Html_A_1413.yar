rule WebShell_BackDoor_Unlimit_S72_Shell_V1_1_Coding_Html_A_1413 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Semi-Auto-generated  - file s72 Shell v1.1 Coding.html.txt"
    family = "S72"
    hacker = "None"
    hash = "c2e8346a5515c81797af36e7e4a3828e"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.S72.Shell.V1.1.Coding.Html.A"
    threattype = "BackDoor"
  strings:
    $s0 = "Dizin</font></b></font><font face=\"Verdana\" style=\"font-size: 8pt\"><"
    $s1 = "s72 Shell v1.0 Codinf by Cr@zy_King"
    $s3 = "echo \"<p align=center>Dosya Zaten Bulunuyor</p>\""
  condition:
    1 of them
}