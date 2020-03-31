rule WebShell_BackDoor_Unlimit_Webshell_Wso2_5_1_Wso2_5_Wso2_A_1765 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - from files wso2.5.1.php, wso2.5.php, wso2.php"
    family = "Webshell"
    hacker = "None"
    hash0 = "dbeecd555a2ef80615f0894027ad75dc"
    hash1 = "7c8e5d31aad28eb1f0a9a53145551e05"
    hash2 = "cbc44fb78220958f81b739b493024688"
    judge = "unknown"
    reference = "None"
    score = 70
    super_rule = 1
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Wso2.5.1.Wso2.5.Wso2.A"
    threattype = "BackDoor"
  strings:
    $s7 = "$opt_charsets .= '<option value=\"'.$item.'\" '.($_POST['charset']==$item?'selec"
    $s8 = ".'</td><td><a href=\"#\" onclick=\"g(\\'FilesTools\\',null,\\''.urlencode($f['na"
  condition:
    all of them
}