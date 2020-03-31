rule WebShell_BackDoor_Unlimit_Chinese_Spam_Spreader_A_1209 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2016/07/18"
    description = "Catches chinese PHP spam files (autospreaders)"
    family = "Chinese"
    hacker = "None"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Chinese.Spam.Spreader.A"
    threattype = "BackDoor"
  strings:
    $a = "User-Agent: aQ0O010O"
    $b = "<font color='red'><b>Connection Error!</b></font>"
    $c = /if ?\(\$_POST\[Submit\]\) ?{/
  condition:
    all of them
}