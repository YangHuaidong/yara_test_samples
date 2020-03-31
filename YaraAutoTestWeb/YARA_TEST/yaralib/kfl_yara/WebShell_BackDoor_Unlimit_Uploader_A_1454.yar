rule WebShell_BackDoor_Unlimit_Uploader_A_1454 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file uploader.php"
    family = "Uploader"
    hacker = "None"
    hash = "b9a9aab319964351b46bd5fc9d6246a8"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Uploader.A"
    threattype = "BackDoor"
  strings:
    $s0 = "move_uploaded_file($userfile, \"entrika.php\"); "
  condition:
    all of them
}