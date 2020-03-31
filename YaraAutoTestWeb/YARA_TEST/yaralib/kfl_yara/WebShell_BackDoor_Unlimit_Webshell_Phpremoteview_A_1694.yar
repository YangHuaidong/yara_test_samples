rule WebShell_BackDoor_Unlimit_Webshell_Phpremoteview_A_1694 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file PHPRemoteView.php"
    family = "Webshell"
    hacker = "None"
    hash = "29420106d9a81553ef0d1ca72b9934d9"
    judge = "unknown"
    reference = "None"
    score = 70
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Phpremoteview.A"
    threattype = "BackDoor"
  strings:
    $s2 = "<input type=submit value='\".mm(\"Delete all dir/files recursive\").\" (rm -fr)'"
    $s4 = "<a href='$self?c=delete&c2=$c2&confirm=delete&d=\".urlencode($d).\"&f=\".u"
  condition:
    1 of them
}