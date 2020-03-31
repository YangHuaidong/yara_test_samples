rule WebShell_BackDoor_Unlimit_Is_A_1299 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/12/14"
    description = "Weevely Webshell - Generic Rule - heavily scrambled tiny web shell"
    family = "Is"
    hacker = "None"
    judge = "unknown"
    reference = "http://www.ehacking.net/2014/12/weevely-php-stealth-web-backdoor-kali.html"
    score = 60
    threatname = "WebShell[BackDoor]/Unlimit.Is.A"
    threattype = "BackDoor"
  strings:
    $php = "<?php" ascii
    $s0 = /\$[a-z]{4} = \$[a-z]{4}\("[a-z][a-z]?",[\s]?"",[\s]?"/ ascii
    $s1 = /\$[a-z]{4} = str_replace\("[a-z][a-z]?","","/ ascii
    $s2 = /\$[a-z]{4}\.\$[a-z]{4}\.\$[a-z]{4}\.\$[a-z]{4}\)\)\); \$[a-z]{4}\(\);/ ascii
    $s4 = /\$[a-z]{4}="[a-zA-Z0-9]{70}/ ascii
  condition:
    $php at 0 and all of ($s*) and filesize > 570 and filesize < 800
}