rule WebShell_BackDoor_Unlimit_Webshell_Php_Webshells_Phpinj_A_1686 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "PHP Webshells Github Archive - file pHpINJ.php"
    family = "Webshell"
    hacker = "None"
    hash = "75116bee1ab122861b155cc1ce45a112c28b9596"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Php.Webshells.Phpinj.A"
    threattype = "BackDoor"
  strings:
    $s3 = "echo '<a href='.$expurl.'> Click Here to Exploit </a> <br />';" fullword
    $s10 = "<form action = \"<?php echo \"$_SERVER[PHP_SELF]\" ; ?>\" method = \"post\">" fullword
    $s11 = "$sql = \"0' UNION SELECT '0' , '<? system(\\$_GET[cpc]);exit; ?>' ,0 ,0 ,0 ,0 IN"
    $s13 = "Full server path to a writable file which will contain the Php Shell <br />" fullword
    $s14 = "$expurl= $url.\"?id=\".$sql ;" fullword
    $s15 = "<header>||   .::News PHP Shell Injection::.   ||</header> <br /> <br />" fullword
    $s16 = "<input type = \"submit\" value = \"Create Exploit\"> <br /> <br />" fullword
  condition:
    1 of them
}