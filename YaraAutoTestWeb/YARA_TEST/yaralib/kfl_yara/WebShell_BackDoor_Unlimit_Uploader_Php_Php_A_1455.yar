rule WebShell_BackDoor_Unlimit_Uploader_Php_Php_A_1455 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Semi-Auto-generated  - file uploader.php.php.txt"
    family = "Uploader"
    hacker = "None"
    hash = "0b53b67bb3b004a8681e1458dd1895d0"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Uploader.Php.Php.A"
    threattype = "BackDoor"
  strings:
    $s2 = "move_uploaded_file($userfile, \"entrika.php\"); " fullword
    $s3 = "Send this file: <INPUT NAME=\"userfile\" TYPE=\"file\">" fullword
    $s4 = "<INPUT TYPE=\"hidden\" name=\"MAX_FILE_SIZE\" value=\"100000\">" fullword
  condition:
    2 of them
}