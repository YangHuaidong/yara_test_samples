rule WebShell_BackDoor_Unlimit_Webshell_C99_C66_C99_Shadows_Mod_C99Shell_A_1533 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - from files c99.php, c66.php, c99-shadows-mod.php, c99shell.php"
    family = "Webshell"
    hacker = "None"
    hash0 = "61a92ce63369e2fa4919ef0ff7c51167"
    hash1 = "0f5b9238d281bc6ac13406bb24ac2a5b"
    hash2 = "68c0629d08b1664f5bcce7d7f5f71d22"
    hash3 = "048ccc01b873b40d57ce25a4c56ea717"
    judge = "unknown"
    reference = "None"
    score = 70
    super_rule = 1
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.C99.C66.C99.Shadows.Mod.C99Shell.A"
    threattype = "BackDoor"
  strings:
    $s2 = "  if (unlink(_FILE_)) {@ob_clean(); echo \"Thanks for using c99shell v.\".$shv"
    $s3 = "  \"c99sh_backconn.pl\"=>array(\"Using PERL\",\"perl %path %host %port\")," fullword
    $s4 = "<br><TABLE style=\"BORDER-COLLAPSE: collapse\" cellSpacing=0 borderColorDark=#66"
    $s7 = "   elseif (!$data = c99getsource($bind[\"src\"])) {echo \"Can't download sources"
    $s8 = "  \"c99sh_datapipe.pl\"=>array(\"Using PERL\",\"perl %path %localport %remotehos"
    $s9 = "   elseif (!$data = c99getsource($bc[\"src\"])) {echo \"Can't download sources!"
  condition:
    2 of them
}