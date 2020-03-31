rule WebShell_BackDoor_Unlimit_Webshell_Phpshell3_A_1697 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file phpshell3.php"
    family = "Webshell"
    hacker = "None"
    hash = "76117b2ee4a7ac06832d50b2d04070b8"
    judge = "unknown"
    reference = "None"
    score = 70
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Phpshell3.A"
    threattype = "BackDoor"
  strings:
    $s2 = "<input name=\"nounce\" type=\"hidden\" value=\"<?php echo $_SESSION['nounce'];"
    $s5 = "<p>Username: <input name=\"username\" type=\"text\" value=\"<?php echo $userna"
    $s7 = "$_SESSION['output'] .= \"cd: could not change to: $new_dir\\n\";" fullword
  condition:
    2 of them
}