rule WebShell_BackDoor_Unlimit_Lamashell_Php_A_1311 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Semi-Auto-generated  - file lamashell.php.txt"
    family = "Lamashell"
    hacker = "None"
    hash = "de9abc2e38420cad729648e93dfc6687"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Lamashell.Php.A"
    threattype = "BackDoor"
  strings:
    $s0 = "lama's'hell" fullword
    $s1 = "if($_POST['king'] == \"\") {"
    $s2 = "if (move_uploaded_file($_FILES['fila']['tmp_name'], $curdir.\"/\".$_FILES['f"
  condition:
    1 of them
}