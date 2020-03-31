rule Trojan_Backdoor_Win32_Swisyn_Mdha_66_222
{

  meta:
    judge = "black"
	threatname = "Trojan[Backdoor]/Win32.Swisyn.M!dha"
	threattype = "Backdoor"
	family = "Swisyn"
	hacker = "None"
	comment = "http://blog.dragonthreatlabs.com/2015/01/dtl-12012015-01-hong-kong-swc-attack.html"
	date = "2015-01-11"
	author = "@dragonthreatlab--DC"
	description = "APT malware used to drop PcClient RAT apt_c16_win32_dropper" 
	refer = "ad17eff26994df824be36db246c8fb6a"
  strings:
    $mz = {4D 5A}
    $str1 = "clbcaiq.dll" ascii
    $str2 = "profapi_104" ascii
    $str3 = "/ShowWU" ascii
    $str4 = "Software\\Microsoft\\Windows\\CurrentVersion\\" ascii
    $str5 = {8A 08 2A CA 32 CA 88 08 40 4E 75 F4 5E}

  condition:
    $mz at 0 and all of ($str*)
}
