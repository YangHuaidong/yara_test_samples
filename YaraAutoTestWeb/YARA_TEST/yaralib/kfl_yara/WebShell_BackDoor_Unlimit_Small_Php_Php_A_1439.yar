rule WebShell_BackDoor_Unlimit_Small_Php_Php_A_1439 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Semi-Auto-generated  - file small.php.php.txt"
    family = "Small"
    hacker = "None"
    hash = "fcee6226d09d150bfa5f103bee61fbde"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Small.Php.Php.A"
    threattype = "BackDoor"
  strings:
    $s1 = "$pass='abcdef1234567890abcdef1234567890';" fullword
    $s2 = "eval(gzinflate(base64_decode('FJzHkqPatkU/550IGnjXxHvv6bzAe0iE5+svFVGtKqXMZq05x1"
    $s4 = "@ini_set('error_log',NULL);" fullword
  condition:
    2 of them
}