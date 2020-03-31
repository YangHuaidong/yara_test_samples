rule WebShell_BackDoor_Unlimit_Webshell_Simple_Php_Backdoor_By_Dk_A_1731 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "PHP Webshells Github Archive - file Simple_PHP_backdoor_by_DK.php"
    family = "Webshell"
    hacker = "None"
    hash = "03f6215548ed370bec0332199be7c4f68105274e"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Simple.Php.Backdoor.By.Dk.A"
    threattype = "BackDoor"
  strings:
    $s0 = "<!-- Simple PHP backdoor by DK (http://michaeldaw.org) -->" fullword
    $s1 = "<!--    http://michaeldaw.org   2006    -->" fullword
    $s2 = "Usage: http://target.com/simple-backdoor.php?cmd=cat+/etc/passwd" fullword
    $s6 = "if(isset($_REQUEST['cmd'])){" fullword
    $s8 = "system($cmd);" fullword
  condition:
    2 of them
}