rule WebShell_BackDoor_Unlimit_Php_Reverse_Shell_A_1379 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-22"
    description = "Laudanum Injector Tools - file php-reverse-shell.php"
    family = "Php"
    hacker = "None"
    hash = "3ef03bbe3649535a03315dcfc1a1208a09cea49d"
    judge = "unknown"
    reference = "http://laudanum.inguardians.com/"
    threatname = "WebShell[BackDoor]/Unlimit.Php.Reverse.Shell.A"
    threattype = "BackDoor"
  strings:
    $s1 = "$process = proc_open($shell, $descriptorspec, $pipes);" fullword ascii /* PEStudio Blacklist: strings */
    $s2 = "printit(\"Successfully opened reverse shell to $ip:$port\");" fullword ascii /* PEStudio Blacklist: strings */
    $s3 = "$input = fread($pipes[1], $chunk_size);" fullword ascii /* PEStudio Blacklist: strings */
  condition:
    filesize < 15KB and all of them
}