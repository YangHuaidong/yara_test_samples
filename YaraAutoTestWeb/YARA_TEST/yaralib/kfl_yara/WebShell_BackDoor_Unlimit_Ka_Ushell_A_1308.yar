rule WebShell_BackDoor_Unlimit_Ka_Ushell_A_1308 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file KA_uShell.php"
    family = "Ka"
    hacker = "None"
    hash = "685f5d4f7f6751eaefc2695071569aab"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Ka.Ushell.A"
    threattype = "BackDoor"
  strings:
    $s5 = "if(empty($_SERVER['PHP_AUTH_PW']) || $_SERVER['PHP_AUTH_PW']<>$pass"
    $s6 = "if ($_POST['path']==\"\"){$uploadfile = $_FILES['file']['name'];}"
  condition:
    all of them
}