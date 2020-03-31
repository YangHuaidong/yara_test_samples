rule WebShell_BackDoor_Unlimit_Webshell_Uploader_A_1737 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "PHP Webshells Github Archive - file Uploader.php"
    family = "Webshell"
    hacker = "None"
    hash = "e216c5863a23fde8a449c31660fd413d77cce0b7"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Uploader.A"
    threattype = "BackDoor"
  strings:
    $s1 = "move_uploaded_file($userfile, \"entrika.php\"); " fullword
  condition:
    all of them
}