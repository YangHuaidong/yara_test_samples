rule WebShell_BackDoor_Unlimit_R57Shell_3_A_1397 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file r57shell.php"
    family = "R57Shell"
    hacker = "None"
    hash = "87995a49f275b6b75abe2521e03ac2c0"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.R57Shell.3.A"
    threattype = "BackDoor"
  strings:
    $s1 = "<b>\".$_POST['cmd']"
  condition:
    all of them
}