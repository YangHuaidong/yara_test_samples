rule WebShell_BackDoor_Unlimit_Multiple_Webshells_0014_A_1335 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Semi-Auto-generated  - from files r577.php.php.txt, r57 Shell.php.php.txt, spy.php.php.txt, s.php.php.txt"
    family = "Multiple"
    hacker = "None"
    hash0 = "0714f80f35c1fddef1f8938b8d42a4c8"
    hash1 = "8023394542cddf8aee5dec6072ed02b5"
    hash2 = "eed14de3907c9aa2550d95550d1a2d5f"
    hash3 = "817671e1bdc85e04cc3440bbd9288800"
    judge = "unknown"
    reference = "None"
    super_rule = 1
    threatname = "WebShell[BackDoor]/Unlimit.Multiple.Webshells.0014.A"
    threattype = "BackDoor"
    was = "_r577_php_php_r57_Shell_php_php_spy_php_php_s_php_php"
  strings:
    $s0 = "echo ws(2).$lb.\" <a"
    $s1 = "$sql = \"LOAD DATA INFILE \\\"\".$_POST['test3_file']"
    $s3 = "if (empty($_POST['cmd'])&&!$safe_mode) { $_POST['cmd']=($windows)?(\"dir\"):(\"l"
  condition:
    2 of them
}