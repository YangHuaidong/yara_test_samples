rule WebShell_BackDoor_Unlimit_Webshell_Web_Shell__C_Shankar_A_1738 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "PHP Webshells Github Archive - file Web-shell (c)ShAnKaR.php"
    family = "Webshell"
    hacker = "None"
    hash = "3dd4f25bd132beb59d2ae0c813373c9ea20e1b7a"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Web.Shell..C.Shankar.A"
    threattype = "BackDoor"
  strings:
    $s0 = "header(\"Content-Length: \".filesize($_POST['downf']));" fullword
    $s5 = "if($_POST['save']==0){echo \"<textarea cols=70 rows=10>\".htmlspecialchars($dump"
    $s6 = "write(\"#\\n#Server : \".getenv('SERVER_NAME').\"" fullword
    $s12 = "foreach(@file($_POST['passwd']) as $fed)echo $fed;" fullword
  condition:
    2 of them
}