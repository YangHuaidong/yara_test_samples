rule WebShell_BackDoor_Unlimit_Backupsql_Php_Often_With_C99Shell_A_1192 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Semi-Auto-generated  - file backupsql.php.php.txt"
    family = "Backupsql"
    hacker = "None"
    hash = "ab1a06ab1a1fe94e3f3b7f80eedbc12f"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Backupsql.Php.Often.With.C99Shell.A"
    threattype = "BackDoor"
  strings:
    $s2 = "//$message.= \"--{$mime_boundary}\\n\" .\"Content-Type: {$fileatt_type};\\n\" ."
    $s4 = "$ftpconnect = \"ncftpput -u $ftp_user_name -p $ftp_user_pass -d debsender_ftplog"
  condition:
    all of them
}