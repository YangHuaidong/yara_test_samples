rule WebShell_BackDoor_Unlimit_Webshell_Elmaliseker_Backd00R_A_1570 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file ELMALISEKER Backd00r.asp"
    family = "Webshell"
    hacker = "None"
    hash = "3aa403e0a42badb2c23d4a54ef43e2f4"
    judge = "unknown"
    reference = "None"
    score = 70
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Elmaliseker.Backd00R.A"
    threattype = "BackDoor"
  strings:
    $s0 = "response.write(\"<tr><td bgcolor=#F8F8FF><input type=submit name=cmdtxtFileOptio"
    $s2 = "if FP = \"RefreshFolder\" or request.form(\"cmdOption\")=\"DeleteFolder\" or req"
  condition:
    all of them
}