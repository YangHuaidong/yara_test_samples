rule WebShell_BackDoor_Unlimit_Webshell_Phpkit_0_1A_Odd_A_1692 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file odd.php"
    family = "Webshell"
    hacker = "None"
    hash = "3c30399e7480c09276f412271f60ed01"
    judge = "unknown"
    reference = "None"
    score = 70
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Phpkit.0.1A.Odd.A"
    threattype = "BackDoor"
  strings:
    $s1 = "include('php://input');" fullword
    $s3 = "ini_set('allow_url_include, 1'); // Allow url inclusion in this script" fullword
    $s4 = "// uses include('php://input') to execute arbritary code" fullword
    $s5 = "// php://input based backdoor" fullword
  condition:
    2 of them
}