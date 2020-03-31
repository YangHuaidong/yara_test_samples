rule WebShell_BackDoor_Unlimit_R57Shell_2_A_1396 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file r57shell.php"
    family = "R57Shell"
    hacker = "None"
    hash = "8023394542cddf8aee5dec6072ed02b5"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.R57Shell.2.A"
    threattype = "BackDoor"
  strings:
    $s2 = "echo \"<br>\".ws(2).\"HDD Free : <b>\".view_size($free).\"</b> HDD Total : <b>\".view_"
  condition:
    all of them
}