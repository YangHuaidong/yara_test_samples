rule WebShell_BackDoor_Unlimit_Webshell_Cihshell_Fix_A_1553 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file cihshell_fix.php"
    family = "Webshell"
    hacker = "None"
    hash = "3823ac218032549b86ee7c26f10c4cb5"
    judge = "unknown"
    reference = "None"
    score = 70
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Cihshell.Fix.A"
    threattype = "BackDoor"
  strings:
    $s7 = "<tr style='background:#242424;' ><td style='padding:10px;'><form action='' encty"
    $s8 = "if (isset($_POST['mysqlw_host'])){$dbhost = $_POST['mysqlw_host'];} else {$dbhos"
  condition:
    1 of them
}