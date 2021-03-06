rule WebShell_BackDoor_Unlimit_Webshell_Backupsql_A_1527 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "PHP Webshells Github Archive - file backupsql.php"
    family = "Webshell"
    hacker = "None"
    hash = "863e017545ec8e16a0df5f420f2d708631020dd4"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Backupsql.A"
    threattype = "BackDoor"
  strings:
    $s0 = "$headers .= \"\\nMIME-Version: 1.0\\n\" .\"Content-Type: multipart/mixed;\\n\" ."
    $s1 = "$ftpconnect = \"ncftpput -u $ftp_user_name -p $ftp_user_pass -d debsender_ftplog"
    $s2 = "* as email attachment, or send to a remote ftp server by" fullword
    $s16 = "* Neagu Mihai<neagumihai@hotmail.com>" fullword
    $s17 = "$from    = \"Neu-Cool@email.com\";  // Who should the emails be sent from?, may "
  condition:
    2 of them
}