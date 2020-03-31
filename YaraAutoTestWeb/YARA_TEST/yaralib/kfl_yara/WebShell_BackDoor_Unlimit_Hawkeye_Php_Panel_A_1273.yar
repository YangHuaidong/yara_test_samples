rule WebShell_BackDoor_Unlimit_Hawkeye_Php_Panel_A_1273 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/12/14"
    description = "Detects HawkEye Keyloggers PHP Panel"
    family = "Hawkeye"
    hacker = "None"
    judge = "unknown"
    reference = "None"
    score = 60
    threatname = "WebShell[BackDoor]/Unlimit.Hawkeye.Php.Panel.A"
    threattype = "BackDoor"
  strings:
    $s0 = "$fname = $_GET['fname'];" ascii fullword
    $s1 = "$data = $_GET['data'];" ascii fullword
    $s2 = "unlink($fname);" ascii fullword
    $s3 = "echo \"Success\";" fullword ascii
  condition:
    all of ($s*) and filesize < 600
}