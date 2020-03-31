rule WebShell_BackDoor_Unlimit_Webshell_Gfs_Sh_R57Shell_R57Shell127_Sniper_Sa_Xxx_A_1588 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - from files gfs_sh.php, r57shell.php, r57shell127.php, SnIpEr_SA Shell.php, EgY_SpIdEr ShElL V2.php, r57_iFX.php, r57_kartal.php, r57_Mohajer22.php, r57.php, r57.php, Backdoor.PHP.Agent.php"
    family = "Webshell"
    hacker = "None"
    hash0 = "a2516ac6ee41a7cf931cbaef1134a9e4"
    hash1 = "ef43fef943e9df90ddb6257950b3538f"
    hash10 = "6fcc283470465eed4870bcc3e2d7f14d"
    hash2 = "ae025c886fbe7f9ed159f49593674832"
    hash3 = "911195a9b7c010f61b66439d9048f400"
    hash4 = "697dae78c040150daff7db751fc0c03c"
    hash5 = "513b7be8bd0595c377283a7c87b44b2e"
    hash6 = "1d912c55b96e2efe8ca873d6040e3b30"
    hash7 = "e5b2131dd1db0dbdb43b53c5ce99016a"
    hash8 = "4108f28a9792b50d95f95b9e5314fa1e"
    hash9 = "41af6fd253648885c7ad2ed524e0692d"
    judge = "unknown"
    reference = "None"
    score = 70
    super_rule = 1
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Gfs.Sh.R57Shell.R57Shell127.Sniper.Sa.Xxx.A"
    threattype = "BackDoor"
  strings:
    $s0 = "kVycm9yOiAkIVxuIik7DQpjb25uZWN0KFNPQ0tFVCwgJHBhZGRyKSB8fCBkaWUoIkVycm9yOiAkIVxuI"
    $s11 = "Aoc3RydWN0IHNvY2thZGRyICopICZzaW4sIHNpemVvZihzdHJ1Y3Qgc29ja2FkZHIpKSk8MCkgew0KIC"
  condition:
    all of them
}