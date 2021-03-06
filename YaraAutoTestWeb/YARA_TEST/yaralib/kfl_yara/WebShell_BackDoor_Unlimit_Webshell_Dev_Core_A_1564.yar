rule WebShell_BackDoor_Unlimit_Webshell_Dev_Core_A_1564 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/03/28"
    description = "Web shells - generated from file dev_core.php"
    family = "Webshell"
    hacker = "None"
    hash = "55ad9309b006884f660c41e53150fc2e"
    judge = "unknown"
    reference = "None"
    score = 70
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Dev.Core.A"
    threattype = "BackDoor"
  strings:
    $s1 = "if (strpos($_SERVER['HTTP_USER_AGENT'], 'EBSD') == false) {" fullword
    $s9 = "setcookie('key', $_POST['pwd'], time() + 3600 * 24 * 30);" fullword
    $s10 = "$_SESSION['code'] = _REQUEST(sprintf(\"%s?%s\",pack(\"H*\",'6874"
    $s11 = "if (preg_match(\"/^HTTP\\/\\d\\.\\d\\s([\\d]+)\\s.*$/\", $status, $matches))"
    $s12 = "eval(gzuncompress(gzuncompress(Crypt::decrypt($_SESSION['code'], $_C"
    $s15 = "if (($fsock = fsockopen($url2['host'], 80, $errno, $errstr, $fsock_timeout))"
  condition:
    1 of them
}