rule WebShell_BackDoor_Unlimit_Webshell_Php_Webshells_Cpanel_A_1678 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "PHP Webshells Github Archive - file cpanel.php"
    family = "Webshell"
    hacker = "None"
    hash = "433dab17106b175c7cf73f4f094e835d453c0874"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Php.Webshells.Cpanel.A"
    threattype = "BackDoor"
  strings:
    $s0 = "function ftp_check($host,$user,$pass,$timeout){" fullword
    $s3 = "curl_setopt($ch, CURLOPT_URL, \"http://$host:2082\");" fullword
    $s4 = "[ user@alturks.com ]# info<b><br><font face=tahoma><br>" fullword
    $s12 = "curl_setopt($ch, CURLOPT_FTPLISTONLY, 1);" fullword
    $s13 = "Powerful tool , ftp and cPanel brute forcer , php 5.2.9 safe_mode & open_basedir"
    $s20 = "<br><b>Please enter your USERNAME and PASSWORD to logon<br>" fullword
  condition:
    2 of them
}