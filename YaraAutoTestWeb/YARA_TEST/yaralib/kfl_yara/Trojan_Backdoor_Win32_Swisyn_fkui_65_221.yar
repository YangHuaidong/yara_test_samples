rule Trojan_Backdoor_Win32_Swisyn_fkui_65_221
{

  meta:
    judge = "black"
	threatname = "Trojan[Backdoor]/Win32.Swisyn.fkui"
	threattype = "Backdoor"
	family = "Swisyn"
	hacker = "apt_c16_win_memory_pcclient"
	comment = "http://blog.dragonthreatlabs.com/2015/01/dtl-12012015-01-hong-kong-swc-attack.html"
	date = "2015-01-11"
	author = "@dragonthreatlab--DC"
	description = "File matching the md5 above tends to only live in memory, hence the lack of MZ header check. apt_c16_win_swisyn" 
	refer = "a6a18c846e5179259eba9de238f67e41"
    
  strings:
    $mz = {4D 5A}
    $str1 = "/ShowWU" ascii
    $str2 = "IsWow64Process"
    $str3 = "regsvr32 "
    $str4 = {8A 11 2A 55 FC 8B 45 08 88 10 8B 4D 08 8A 11 32 55 FC 8B 45 08 88 10}

  condition:
    $mz at 0 and all of ($str*)
}