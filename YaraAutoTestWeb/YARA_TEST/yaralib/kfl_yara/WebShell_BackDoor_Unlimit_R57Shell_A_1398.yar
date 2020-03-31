rule WebShell_BackDoor_Unlimit_R57Shell_A_1398 {
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
    threatname = "WebShell[BackDoor]/Unlimit.R57Shell.A"
    threattype = "BackDoor"
  strings:
    $s11 = " $_POST['cmd']=\"echo \\\"Now script try connect to"
  condition:
    all of them
}