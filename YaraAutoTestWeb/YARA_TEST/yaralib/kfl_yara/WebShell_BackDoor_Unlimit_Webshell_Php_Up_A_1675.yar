rule WebShell_BackDoor_Unlimit_Webshell_Php_Up_A_1675 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file up.php"
    family = "Webshell"
    hacker = "None"
    hash = "7edefb8bd0876c41906f4b39b52cd0ef"
    judge = "unknown"
    reference = "None"
    score = 70
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Php.Up.A"
    threattype = "BackDoor"
  strings:
    $s0 = "copy($HTTP_POST_FILES['userfile']['tmp_name'], $_POST['remotefile']);" fullword
    $s3 = "if(is_uploaded_file($HTTP_POST_FILES['userfile']['tmp_name'])) {" fullword
    $s8 = "echo \"Uploaded file: \" . $HTTP_POST_FILES['userfile']['name'];" fullword
  condition:
    2 of them
}