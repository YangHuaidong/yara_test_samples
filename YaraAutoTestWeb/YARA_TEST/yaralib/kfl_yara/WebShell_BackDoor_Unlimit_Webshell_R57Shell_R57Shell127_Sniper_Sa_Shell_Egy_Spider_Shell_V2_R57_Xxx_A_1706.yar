rule WebShell_BackDoor_Unlimit_Webshell_R57Shell_R57Shell127_Sniper_Sa_Shell_Egy_Spider_Shell_V2_R57_Xxx_A_1706 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - from files r57shell.php, r57shell127.php, SnIpEr_SA Shell.php, EgY_SpIdEr ShElL V2.php, r57_iFX.php, r57_kartal.php, r57_Mohajer22.php, r57.php, r57.php, Backdoor.PHP.Agent.php"
    family = "Webshell"
    hacker = "None"
    hash0 = "ef43fef943e9df90ddb6257950b3538f"
    hash1 = "ae025c886fbe7f9ed159f49593674832"
    hash2 = "911195a9b7c010f61b66439d9048f400"
    hash3 = "697dae78c040150daff7db751fc0c03c"
    hash4 = "513b7be8bd0595c377283a7c87b44b2e"
    hash5 = "1d912c55b96e2efe8ca873d6040e3b30"
    hash6 = "e5b2131dd1db0dbdb43b53c5ce99016a"
    hash7 = "4108f28a9792b50d95f95b9e5314fa1e"
    hash8 = "41af6fd253648885c7ad2ed524e0692d"
    hash9 = "6fcc283470465eed4870bcc3e2d7f14d"
    judge = "unknown"
    reference = "None"
    score = 70
    super_rule = 1
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.R57Shell.R57Shell127.Sniper.Sa.Shell.Egy.Spider.Shell.V2.R57.Xxx.A"
    threattype = "BackDoor"
  strings:
    $s2 = "echo sr(15,\"<b>\".$lang[$language.'_text58'].$arrow.\"</b>\",in('text','mk_name"
    $s3 = "echo sr(15,\"<b>\".$lang[$language.'_text21'].$arrow.\"</b>\",in('checkbox','nf1"
    $s9 = "echo sr(40,\"<b>\".$lang[$language.'_text26'].$arrow.\"</b>\",\"<select size="
  condition:
    all of them
}