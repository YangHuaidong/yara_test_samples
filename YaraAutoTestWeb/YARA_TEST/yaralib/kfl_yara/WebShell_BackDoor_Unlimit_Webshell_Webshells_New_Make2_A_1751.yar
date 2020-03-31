rule WebShell_BackDoor_Unlimit_Webshell_Webshells_New_Make2_A_1751 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/03/28"
    description = "Web shells - generated from file make2.php"
    family = "Webshell"
    hacker = "None"
    hash = "9af195491101e0816a263c106e4c145e"
    judge = "unknown"
    reference = "None"
    score = 50
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Webshells.New.Make2.A"
    threattype = "BackDoor"
  strings:
    $s1 = "error_reporting(0);session_start();header(\"Content-type:text/html;charset=utf-8"
  condition:
    all of them
}