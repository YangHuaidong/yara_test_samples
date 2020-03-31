rule WebShell_BackDoor_Unlimit_Phpshell17_Php_A_1389 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Semi-Auto-generated  - file phpshell17.php.txt"
    family = "Phpshell17"
    hacker = "None"
    hash = "9a928d741d12ea08a624ee9ed5a8c39d"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Phpshell17.Php.A"
    threattype = "BackDoor"
  strings:
    $s0 = "<input name=\"submit_btn\" type=\"submit\" value=\"Execute Command\"></p>" fullword
    $s1 = "<title>[ADDITINAL TITTLE]-phpShell by:[YOURNAME]<?php echo PHPSHELL_VERSION ?></"
    $s2 = "href=\"mailto: [YOU CAN ENTER YOUR MAIL HERE]- [ADDITIONAL TEXT]</a></i>" fullword
  condition:
    1 of them
}