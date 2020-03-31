rule WebShell_BackDoor_Unlimit_Php_Dns_A_1374 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-22"
    description = "Laudanum Injector Tools - file dns.php"
    family = "Php"
    hacker = "None"
    hash = "01d5d16d876c55d77e094ce2b9c237de43b21a16"
    judge = "unknown"
    reference = "http://laudanum.inguardians.com/"
    threatname = "WebShell[BackDoor]/Unlimit.Php.Dns.A"
    threattype = "BackDoor"
  strings:
    $s1 = "$query = isset($_POST['query']) ? $_POST['query'] : '';" fullword ascii /* PEStudio Blacklist: strings */
    $s2 = "$result = dns_get_record($query, $types[$type], $authns, $addtl);" fullword ascii /* PEStudio Blacklist: strings */
    $s3 = "if ($_SERVER[\"REMOTE_ADDR\"] == $IP)" fullword ascii /* PEStudio Blacklist: strings */
    $s4 = "foreach (array_keys($types) as $t) {" fullword ascii
  condition:
    filesize < 15KB and all of them
}