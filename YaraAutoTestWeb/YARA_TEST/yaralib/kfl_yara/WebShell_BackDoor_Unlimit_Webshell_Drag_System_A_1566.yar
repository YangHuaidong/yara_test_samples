rule WebShell_BackDoor_Unlimit_Webshell_Drag_System_A_1566 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file system.jsp"
    family = "Webshell"
    hacker = "None"
    hash = "15ae237cf395fb24cf12bff141fb3f7c"
    judge = "unknown"
    reference = "None"
    score = 70
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Drag.System.A"
    threattype = "BackDoor"
  strings:
    $s9 = "String sql = \"SELECT * FROM DBA_TABLES WHERE TABLE_NAME not like '%$%' and num_"
  condition:
    all of them
}