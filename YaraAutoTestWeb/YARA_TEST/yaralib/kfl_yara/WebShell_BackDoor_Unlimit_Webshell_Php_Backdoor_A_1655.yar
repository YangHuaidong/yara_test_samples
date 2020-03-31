rule WebShell_BackDoor_Unlimit_Webshell_Php_Backdoor_A_1655 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "PHP Webshells Github Archive - file php-backdoor.php"
    family = "Webshell"
    hacker = "None"
    hash = "b190c03af4f3fb52adc20eb0f5d4d151020c74fe"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Php.Backdoor.A"
    threattype = "BackDoor"
  strings:
    $s5 = "http://<? echo $SERVER_NAME.$REQUEST_URI; ?>?d=/etc on *nix" fullword
    $s6 = "// a simple php backdoor | coded by z0mbie [30.08.03] | http://freenet.am/~zombi"
    $s11 = "if(!isset($_REQUEST['dir'])) die('hey,specify directory!');" fullword
    $s13 = "else echo \"<a href='$PHP_SELF?f=$d/$dir'><font color=black>\";" fullword
    $s15 = "<pre><form action=\"<? echo $PHP_SELF; ?>\" METHOD=GET >execute command: <input "
  condition:
    1 of them
}