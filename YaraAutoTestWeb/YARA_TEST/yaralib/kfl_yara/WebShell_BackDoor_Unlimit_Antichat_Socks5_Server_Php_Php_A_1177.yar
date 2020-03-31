rule WebShell_BackDoor_Unlimit_Antichat_Socks5_Server_Php_Php_A_1177 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Semi-Auto-generated  - file Antichat Socks5 Server.php.php.txt"
    family = "Antichat"
    hacker = "None"
    hash = "cbe9eafbc4d86842a61a54d98e5b61f1"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Antichat.Socks5.Server.Php.Php.A"
    threattype = "BackDoor"
  strings:
    $s0 = "$port = base_convert(bin2hex(substr($reqmessage[$id], 3+$reqlen+1, 2)), 16, 10);" fullword
    $s3 = "#   [+] Domain name address type"
    $s4 = "www.antichat.ru"
  condition:
    1 of them
}