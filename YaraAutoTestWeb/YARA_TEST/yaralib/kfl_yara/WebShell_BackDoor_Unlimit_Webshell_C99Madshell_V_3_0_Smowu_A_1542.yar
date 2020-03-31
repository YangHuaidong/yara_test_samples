rule WebShell_BackDoor_Unlimit_Webshell_C99Madshell_V_3_0_Smowu_A_1542 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file smowu.php"
    family = "Webshell"
    hacker = "None"
    hash = "74e1e7c7a6798f1663efb42882b85bee"
    judge = "unknown"
    reference = "None"
    score = 70
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.C99Madshell.V.3.0.Smowu.A"
    threattype = "BackDoor"
  strings:
    $s2 = "<tr><td width=\"50%\" height=\"1\" valign=\"top\"><center><b>:: Enter ::</b><for"
    $s8 = "<p><font color=red>Wordpress Not Found! <input type=text id=\"wp_pat\"><input ty"
  condition:
    1 of them
}