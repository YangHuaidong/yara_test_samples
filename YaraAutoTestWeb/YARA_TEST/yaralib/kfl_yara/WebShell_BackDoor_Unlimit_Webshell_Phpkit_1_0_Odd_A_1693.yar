rule WebShell_BackDoor_Unlimit_Webshell_Phpkit_1_0_Odd_A_1693 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file odd.php"
    family = "Webshell"
    hacker = "None"
    hash = "594d1b1311bbef38a0eb3d6cbb1ab538"
    judge = "unknown"
    reference = "None"
    score = 70
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Phpkit.1.0.Odd.A"
    threattype = "BackDoor"
  strings:
    $s0 = "include('php://input');" fullword
    $s1 = "// No eval() calls, no system() calls, nothing normally seen as malicious." fullword
    $s2 = "ini_set('allow_url_include, 1'); // Allow url inclusion in this script" fullword
  condition:
    all of them
}