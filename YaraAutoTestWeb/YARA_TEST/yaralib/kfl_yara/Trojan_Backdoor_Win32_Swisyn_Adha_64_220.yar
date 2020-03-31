rule Trojan_Backdoor_Win32_Swisyn_Adha_64_220
{

  meta:
    judge = "black"
	threatname = "Trojan[Backdoor]/Win32.Swisyn.A!dha"
	threattype = "Backdoor"
	family = "Swisyn"
	hacker = "apt_c16_win_memory_pcclient"
	comment = "http://blog.dragonthreatlabs.com/2015/01/dtl-12012015-01-hong-kong-swc-attack.html"
	date = "2015-01-11"
	author = "@dragonthreatlab--DC"
	description = "File matching the md5 above tends to only live in memory, hence the lack of MZ header check." 
	refer = "ec532bbe9d0882d403473102e9724557"
    
  strings:
    $str1 = "Kill You" ascii
    $str2 = "%4d-%02d-%02d %02d:%02d:%02d" ascii
    $str3 = "%4.2f  KB" ascii
    $encodefunc = {8A 08 32 CA 02 CA 88 08 40 4E 75 F4}

  condition:
    all of them
}