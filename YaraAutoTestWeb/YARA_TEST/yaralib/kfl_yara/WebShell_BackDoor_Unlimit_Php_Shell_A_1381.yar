rule WebShell_BackDoor_Unlimit_Php_Shell_A_1381 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file shell.php"
    family = "Php"
    hacker = "None"
    hash = "45e8a00567f8a34ab1cccc86b4bc74b9"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Php.Shell.A"
    threattype = "BackDoor"
  strings:
    $s0 = "AR8iROET6mMnrqTpC6W1Kp/DsTgxNby9H1xhiswfwgoAtED0y6wEXTihoAtICkIX6L1+vTUYWuWz"
    $s11 = "1HLp1qnlCyl5gko8rDlWHqf8/JoPKvGwEm9Q4nVKvEh0b0PKle3zeFiJNyjxOiVepMSpflJkPv5s"
  condition:
    all of them
}