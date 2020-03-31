rule WebShell_BackDoor_Unlimit_Darksecurityteam_Webshell_A_1219 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Dark Security Team Webshell"
    family = "Darksecurityteam"
    hacker = "None"
    hash = "f1c95b13a71ca3629a0bb79601fcacf57cdfcf768806a71b26f2448f8c1d5d24"
    judge = "unknown"
    reference = "None"
    score = 50
    threatname = "WebShell[BackDoor]/Unlimit.Darksecurityteam.Webshell.A"
    threattype = "BackDoor"
  strings:
    $s0 = "form method=post><input type=hidden name=\"\"#\"\" value=Execute(Session(\"\"#\"\"))><input name=thePath value=\"\"\"&HtmlEncode(Server.MapPath(\".\"))&" ascii
  condition:
    1 of them
}