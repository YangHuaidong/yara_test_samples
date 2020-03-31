rule WebShell_BackDoor_Unlimit_Ngh_Php_Php_A_1359 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Semi-Auto-generated  - file ngh.php.php.txt"
    family = "Ngh"
    hacker = "None"
    hash = "c372b725419cdfd3f8a6371cfeebc2fd"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Ngh.Php.Php.A"
    threattype = "BackDoor"
  strings:
    $s0 = "Cr4sh_aka_RKL"
    $s1 = "NGH edition"
    $s2 = "/* connectback-backdoor on perl"
    $s3 = "<form action=<?=$script?>?act=bindshell method=POST>"
    $s4 = "$logo = \"R0lGODlhMAAwAOYAAAAAAP////r"
  condition:
    1 of them
}