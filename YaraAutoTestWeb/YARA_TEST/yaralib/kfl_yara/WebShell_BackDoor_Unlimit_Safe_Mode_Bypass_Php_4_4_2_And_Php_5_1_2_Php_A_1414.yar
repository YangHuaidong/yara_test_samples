rule WebShell_BackDoor_Unlimit_Safe_Mode_Bypass_Php_4_4_2_And_Php_5_1_2_Php_A_1414 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Semi-Auto-generated  - file Safe_Mode Bypass PHP 4.4.2 and PHP 5.1.2.php.txt"
    family = "Safe"
    hacker = "None"
    hash = "49ad9117c96419c35987aaa7e2230f63"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Safe.Mode.Bypass.Php.4.4.2.And.Php.5.1.2.Php.A"
    threattype = "BackDoor"
  strings:
    $s0 = "Welcome.. By This script you can jump in the (Safe Mode=ON) .. Enjoy"
    $s1 = "Mode Shell v1.0</font></span>"
    $s2 = "has been already loaded. PHP Emperor <xb5@hotmail."
  condition:
    1 of them
}