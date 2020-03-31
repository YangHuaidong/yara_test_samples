rule WebShell_BackDoor_Unlimit_Webshell_Phpspy_2005_Full_Phpspy_2005_Lite_Phpspy_A_1699 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - from files phpspy_2005_full.php, phpspy_2005_lite.php, PHPSPY.php"
    family = "Webshell"
    hacker = "None"
    hash0 = "b68bfafc6059fd26732fa07fb6f7f640"
    hash1 = "42f211cec8032eb0881e87ebdb3d7224"
    hash2 = "0712e3dc262b4e1f98ed25760b206836"
    judge = "unknown"
    reference = "None"
    score = 70
    super_rule = 1
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Phpspy.2005.Full.Phpspy.2005.Lite.Phpspy.A"
    threattype = "BackDoor"
  strings:
    $s6 = "<input type=\"text\" name=\"command\" size=\"60\" value=\"<?=$_POST['comma"
    $s7 = "echo $msg=@copy($_FILES['uploadmyfile']['tmp_name'],\"\".$uploaddir.\"/\".$_FILE"
    $s8 = "<option value=\"passthru\" <? if ($execfunc==\"passthru\") { echo \"selected\"; "
  condition:
    2 of them
}