rule WebShell_BackDoor_Unlimit_Webshell_Nix_Remote_Web_Shell_Nstview_Xxx_A_1645 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - from files NIX REMOTE WEB-SHELL.php, nstview.php, NIX REMOTE WEB-SHELL v.0.5 alpha Lite Public Version.php, Cyber Shell (v 1.0).php"
    family = "Webshell"
    hacker = "None"
    hash0 = "0b19e9de790cd2f4325f8c24b22af540"
    hash1 = "4745d510fed4378e4b1730f56f25e569"
    hash2 = "f3ca29b7999643507081caab926e2e74"
    hash3 = "46a18979750fa458a04343cf58faa9bd"
    judge = "unknown"
    reference = "None"
    score = 70
    super_rule = 1
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Nix.Remote.Web.Shell.Nstview.Xxx.A"
    threattype = "BackDoor"
  strings:
    $s3 = "BODY, TD, TR {" fullword
    $s5 = "$d=str_replace(\"\\\\\",\"/\",$d);" fullword
    $s6 = "if ($file==\".\" || $file==\"..\") continue;" fullword
  condition:
    2 of them
}