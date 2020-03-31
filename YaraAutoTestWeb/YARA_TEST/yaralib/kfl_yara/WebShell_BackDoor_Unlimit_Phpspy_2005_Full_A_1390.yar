rule WebShell_BackDoor_Unlimit_Phpspy_2005_Full_A_1390 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file phpspy_2005_full.php"
    family = "Phpspy"
    hacker = "None"
    hash = "d1c69bb152645438440e6c903bac16b2"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Phpspy.2005.Full.A"
    threattype = "BackDoor"
  strings:
    $s7 = "echo \"  <td align=\\\"center\\\" nowrap valign=\\\"top\\\"><a href=\\\"?downfile=\".urlenco"
  condition:
    all of them
}