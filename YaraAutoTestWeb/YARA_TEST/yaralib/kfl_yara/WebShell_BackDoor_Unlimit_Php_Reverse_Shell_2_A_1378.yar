rule WebShell_BackDoor_Unlimit_Php_Reverse_Shell_2_A_1378 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-22"
    description = "Laudanum Injector Tools - file php-reverse-shell.php"
    family = "Php"
    hacker = "None"
    hash = "025db3c3473413064f0606d93d155c7eb5049c42"
    judge = "unknown"
    reference = "http://laudanum.inguardians.com/"
    threatname = "WebShell[BackDoor]/Unlimit.Php.Reverse.Shell.2.A"
    threattype = "BackDoor"
  strings:
    $s1 = "$process = proc_open($shell, $descriptorspec, $pipes);" fullword ascii /* PEStudio Blacklist: strings */
    $s7 = "$shell = 'uname -a; w; id; /bin/sh -i';" fullword ascii /* PEStudio Blacklist: strings */
  condition:
    filesize < 10KB and all of them
}