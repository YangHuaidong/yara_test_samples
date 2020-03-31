rule WebShell_BackDoor_Unlimit_Simple_Php_Backdoor_A_1436 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file Simple_PHP_BackDooR.php"
    family = "Simple"
    hacker = "None"
    hash = "a401132363eecc3a1040774bec9cb24f"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Simple.Php.Backdoor.A"
    threattype = "BackDoor"
  strings:
    $s0 = "<hr>to browse go to http://<? echo $SERVER_NAME.$REQUEST_URI; ?>?d=[directory he"
    $s6 = "if(!move_uploaded_file($HTTP_POST_FILES['file_name']['tmp_name'], $dir.$fn"
    $s9 = "// a simple php backdoor"
  condition:
    1 of them
}