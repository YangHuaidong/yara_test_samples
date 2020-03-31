rule WebShell_BackDoor_Unlimit_Webshell_C99_Shell_Ci_Biz_Was_Here_C100_V_Xxx_A_1540 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - from files c99.php, Shell [ci] .Biz was here.php, c100 v. 777shell v. Undetectable #18a Modded by 777 - Don.php, c66.php, c99-shadows-mod.php, c99shell.php"
    family = "Webshell"
    hacker = "None"
    hash0 = "61a92ce63369e2fa4919ef0ff7c51167"
    hash1 = "f2fa878de03732fbf5c86d656467ff50"
    hash2 = "27786d1e0b1046a1a7f67ee41c64bf4c"
    hash3 = "0f5b9238d281bc6ac13406bb24ac2a5b"
    hash4 = "68c0629d08b1664f5bcce7d7f5f71d22"
    hash5 = "048ccc01b873b40d57ce25a4c56ea717"
    judge = "unknown"
    reference = "None"
    score = 70
    super_rule = 1
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.C99.Shell.Ci.Biz.Was.Here.C100.V.Xxx.A"
    threattype = "BackDoor"
  strings:
    $s8 = "else {echo \"Running datapipe... ok! Connect to <b>\".getenv(\"SERVER_ADDR\""
  condition:
    all of them
}