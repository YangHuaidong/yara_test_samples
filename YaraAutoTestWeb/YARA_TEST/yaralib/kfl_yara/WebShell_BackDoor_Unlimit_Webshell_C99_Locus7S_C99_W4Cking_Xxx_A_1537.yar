rule WebShell_BackDoor_Unlimit_Webshell_C99_Locus7S_C99_W4Cking_Xxx_A_1537 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - from files c99_locus7s.php, c99_w4cking.php, r57shell.php, r57shell127.php, SnIpEr_SA Shell.php, EgY_SpIdEr ShElL V2.php, r57_iFX.php, r57_kartal.php, r57_Mohajer22.php, r57.php, acid.php, newsh.php, r57.php, Backdoor.PHP.Agent.php"
    family = "Webshell"
    hacker = "None"
    hash0 = "38fd7e45f9c11a37463c3ded1c76af4c"
    hash1 = "9c34adbc8fd8d908cbb341734830f971"
    hash10 = "b8f261a3cdf23398d573aaf55eaf63b5"
    hash11 = "0d2c2c151ed839e6bafc7aa9c69be715"
    hash12 = "41af6fd253648885c7ad2ed524e0692d"
    hash13 = "6fcc283470465eed4870bcc3e2d7f14d"
    hash2 = "ef43fef943e9df90ddb6257950b3538f"
    hash3 = "ae025c886fbe7f9ed159f49593674832"
    hash4 = "911195a9b7c010f61b66439d9048f400"
    hash5 = "697dae78c040150daff7db751fc0c03c"
    hash6 = "513b7be8bd0595c377283a7c87b44b2e"
    hash7 = "1d912c55b96e2efe8ca873d6040e3b30"
    hash8 = "e5b2131dd1db0dbdb43b53c5ce99016a"
    hash9 = "4108f28a9792b50d95f95b9e5314fa1e"
    judge = "unknown"
    reference = "None"
    score = 70
    super_rule = 1
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.C99.Locus7S.C99.W4Cking.Xxx.A"
    threattype = "BackDoor"
  strings:
    $s1 = "$res = @shell_exec($cfe);" fullword
    $s8 = "$res = @ob_get_contents();" fullword
    $s9 = "@exec($cfe,$res);" fullword
  condition:
    2 of them
}