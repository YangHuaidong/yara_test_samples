rule WebShell_BackDoor_Unlimit_Webshell_Remview_Fix_A_1712 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file remview_fix.php"
    family = "Webshell"
    hacker = "None"
    hash = "a24b7c492f5f00e2a19b0fa2eb9c3697"
    judge = "unknown"
    reference = "None"
    score = 70
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Remview.Fix.A"
    threattype = "BackDoor"
  strings:
    $s4 = "<a href='$self?c=delete&c2=$c2&confirm=delete&d=\".urlencode($d).\"&f=\".u"
    $s5 = "echo \"<P><hr size=1 noshade>\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n"
  condition:
    1 of them
}