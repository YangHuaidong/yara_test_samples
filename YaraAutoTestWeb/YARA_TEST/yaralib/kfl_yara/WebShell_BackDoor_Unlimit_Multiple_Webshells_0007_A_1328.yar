rule WebShell_BackDoor_Unlimit_Multiple_Webshells_0007_A_1328 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Semi-Auto-generated  - from files r577.php.php.txt, spy.php.php.txt, s.php.php.txt"
    family = "Multiple"
    hacker = "None"
    hash0 = "0714f80f35c1fddef1f8938b8d42a4c8"
    hash1 = "eed14de3907c9aa2550d95550d1a2d5f"
    hash2 = "817671e1bdc85e04cc3440bbd9288800"
    judge = "unknown"
    reference = "None"
    super_rule = 1
    threatname = "WebShell[BackDoor]/Unlimit.Multiple.Webshells.0007.A"
    threattype = "BackDoor"
    was = "_r577_php_php_spy_php_php_s_php_php"
  strings:
    $s2 = "echo $te.\"<div align=center><textarea cols=35 name=db_query>\".(!empty($_POST['"
    $s3 = "echo sr(45,\"<b>\".$lang[$language.'_text80'].$arrow.\"</b>\",\"<select name=db>"
  condition:
    1 of them
}