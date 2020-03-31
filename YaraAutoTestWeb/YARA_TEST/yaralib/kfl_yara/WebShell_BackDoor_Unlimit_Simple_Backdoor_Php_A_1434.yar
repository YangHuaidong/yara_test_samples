rule WebShell_BackDoor_Unlimit_Simple_Backdoor_Php_A_1434 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Semi-Auto-generated  - file simple-backdoor.php.txt"
    family = "Simple"
    hacker = "None"
    hash = "f091d1b9274c881f8e41b2f96e6b9936"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Simple.Backdoor.Php.A"
    threattype = "BackDoor"
  strings:
    $s0 = "$cmd = ($_REQUEST['cmd']);" fullword
    $s1 = "<!-- Simple PHP backdoor by DK (http://michaeldaw.org) -->"
    $s2 = "Usage: http://target.com/simple-backdoor.php?cmd=cat+/etc/passwd" fullword
  condition:
    2 of them
}