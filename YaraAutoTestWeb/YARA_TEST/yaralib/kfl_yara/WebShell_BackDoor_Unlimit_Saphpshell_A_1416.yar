rule WebShell_BackDoor_Unlimit_Saphpshell_A_1416 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file saphpshell.php"
    family = "Saphpshell"
    hacker = "None"
    hash = "d7bba8def713512ddda14baf9cd6889a"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Saphpshell.A"
    threattype = "BackDoor"
  strings:
    $s0 = "<td><input type=\"text\" name=\"command\" size=\"60\" value=\"<?=$_POST['command']?>"
  condition:
    all of them
}