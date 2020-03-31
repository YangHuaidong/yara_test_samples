rule WebShell_BackDoor_Unlimit_Webshell_Qsd_Php_Backdoor_A_1703 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "PHP Webshells Github Archive - file qsd-php-backdoor.php"
    family = "Webshell"
    hacker = "None"
    hash = "4856bce45fc5b3f938d8125f7cdd35a8bbae380f"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Qsd.Php.Backdoor.A"
    threattype = "BackDoor"
  strings:
    $s1 = "// A robust backdoor script made by Daniel Berliner - http://www.qsdconsulting.c"
    $s2 = "if(isset($_POST[\"newcontent\"]))" fullword
    $s3 = "foreach($parts as $val)//Assemble the path back together" fullword
    $s7 = "$_POST[\"newcontent\"]=urldecode(base64_decode($_POST[\"newcontent\"]));" fullword
  condition:
    2 of them
}