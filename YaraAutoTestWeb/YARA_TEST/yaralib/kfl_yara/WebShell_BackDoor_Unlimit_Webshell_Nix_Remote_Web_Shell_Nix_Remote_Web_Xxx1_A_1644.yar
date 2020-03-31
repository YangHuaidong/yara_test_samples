rule WebShell_BackDoor_Unlimit_Webshell_Nix_Remote_Web_Shell_Nix_Remote_Web_Xxx1_A_1644 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - from files NIX REMOTE WEB-SHELL.php, NIX REMOTE WEB-SHELL v.0.5 alpha Lite Public Version.php, KAdot Universal Shell v0.1.6.php"
    family = "Webshell"
    hacker = "None"
    hash0 = "0b19e9de790cd2f4325f8c24b22af540"
    hash1 = "f3ca29b7999643507081caab926e2e74"
    hash2 = "527cf81f9272919bf872007e21c4bdda"
    judge = "unknown"
    reference = "None"
    score = 70
    super_rule = 1
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Nix.Remote.Web.Shell.Nix.Remote.Web.Xxx1.A"
    threattype = "BackDoor"
  strings:
    $s1 = "<td><input size=\"48\" value=\"$docr/\" name=\"path\" type=\"text\"><input type="
    $s2 = "$uploadfile = $_POST['path'].$_FILES['file']['name'];" fullword
    $s6 = "elseif (!empty($_POST['ac'])) {$ac = $_POST['ac'];}" fullword
    $s7 = "if ($_POST['path']==\"\"){$uploadfile = $_FILES['file']['name'];}" fullword
  condition:
    2 of them
}