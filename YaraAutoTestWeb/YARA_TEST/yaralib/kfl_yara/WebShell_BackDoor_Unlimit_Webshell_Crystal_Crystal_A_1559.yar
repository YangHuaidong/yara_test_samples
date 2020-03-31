rule WebShell_BackDoor_Unlimit_Webshell_Crystal_Crystal_A_1559 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file Crystal.php"
    family = "Webshell"
    hacker = "None"
    hash = "fdbf54d5bf3264eb1c4bff1fac548879"
    judge = "unknown"
    reference = "None"
    score = 70
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Crystal.Crystal.A"
    threattype = "BackDoor"
  strings:
    $s1 = "show opened ports</option></select><input type=\"hidden\" name=\"cmd_txt\" value"
    $s6 = "\" href=\"?act=tools\"><font color=#CC0000 size=\"3\">Tools</font></a></span></f"
  condition:
    all of them
}