rule WebShell_BackDoor_Unlimit_Defacekeeper_0_2_Php_A_1226 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Semi-Auto-generated  - file DefaceKeeper_0.2.php.txt"
    family = "Defacekeeper"
    hacker = "None"
    hash = "713c54c3da3031bc614a8a55dccd7e7f"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Defacekeeper.0.2.Php.A"
    threattype = "BackDoor"
  strings:
    $s0 = "target fi1e:<br><input type=\"text\" name=\"target\" value=\"index.php\"></br>" fullword
    $s1 = "eval(base64_decode(\"ZXZhbChiYXNlNjRfZGVjb2RlKCJhV2R1YjNKbFgzVnpaWEpmWVdKdmNuUW9"
    $s2 = "<img src=\"http://s43.radikal.ru/i101/1004/d8/ced1f6b2f5a9.png\" align=\"center"
  condition:
    1 of them
}