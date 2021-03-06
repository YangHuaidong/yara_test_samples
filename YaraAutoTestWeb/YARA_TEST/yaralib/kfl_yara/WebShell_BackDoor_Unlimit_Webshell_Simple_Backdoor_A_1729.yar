rule WebShell_BackDoor_Unlimit_Webshell_Simple_Backdoor_A_1729 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "PHP Webshells Github Archive - file simple-backdoor.php"
    family = "Webshell"
    hacker = "None"
    hash = "edcd5157a68fa00723a506ca86d6cbb8884ef512"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Simple.Backdoor.A"
    threattype = "BackDoor"
  strings:
    $s0 = "<!-- Simple PHP backdoor by DK (http://michaeldaw.org) -->" fullword
    $s1 = "<!--    http://michaeldaw.org   2006    -->" fullword
    $s2 = "Usage: http://target.com/simple-backdoor.php?cmd=cat+/etc/passwd" fullword
    $s3 = "        echo \"</pre>\";" fullword
    $s4 = "        $cmd = ($_REQUEST['cmd']);" fullword
    $s5 = "        echo \"<pre>\";" fullword
    $s6 = "if(isset($_REQUEST['cmd'])){" fullword
    $s7 = "        die;" fullword
    $s8 = "        system($cmd);" fullword
  condition:
    all of them
}