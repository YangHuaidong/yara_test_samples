rule WebShell_BackDoor_Unlimit_Backup_Php_Often_With_C99Shell_A {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Semi-Auto-generated  - file backup.php.php.txt"
    family = "Backup"
    hacker = "None"
    hash = "aeee3bae226ad57baf4be8745c3f6094"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Backup.Php.Often.With.C99Shell.A"
    threattype = "BackDoor"
  strings:
    $s0 = "#phpMyAdmin MySQL-Dump" fullword
    $s2 = ";db_connect();header('Content-Type: application/octetstr"
    $s4 = "$data .= \"#Database: $database" fullword
  condition:
    all of them
}