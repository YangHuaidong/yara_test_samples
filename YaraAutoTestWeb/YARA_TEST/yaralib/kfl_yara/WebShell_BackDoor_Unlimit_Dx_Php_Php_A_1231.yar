rule WebShell_BackDoor_Unlimit_Dx_Php_Php_A_1231 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Semi-Auto-generated  - file Dx.php.php.txt"
    family = "Dx"
    hacker = "None"
    hash = "9cfe372d49fe8bf2fac8e1c534153d9b"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Dx.Php.Php.A"
    threattype = "BackDoor"
  strings:
    $s0 = "print \"\\n\".'Tip: to view the file \"as is\" - open the page in <a href=\"'.Dx"
    $s2 = "$DEF_PORTS=array (1=>'tcpmux (TCP Port Service Multiplexer)',2=>'Management Util"
    $s3 = "$ra44  = rand(1,99999);$sj98 = \"sh-$ra44\";$ml = \"$sd98\";$a5 = $_SERVER['HTTP"
  condition:
    1 of them
}