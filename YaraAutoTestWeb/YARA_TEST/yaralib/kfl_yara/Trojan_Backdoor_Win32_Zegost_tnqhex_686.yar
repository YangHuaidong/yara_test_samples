rule Trojan_Backdoor_Win32_Zegost_tnqhex_686
{
    meta:
	        judge = "black"
			threatname = "Trojan[Backdoor]/Win32.Zegost.tnqhex"
			threattype = "Backdoor"
			family = "Zegost"
			hacker = "none"
			refer = "973f60be2d029e6601bf113906f4ed8d"
			comment = "none"
			author = "xc"
			date = "2017-07-27"
			description = "None"
	strings:
			$s0 = {55 8B EC 6A FF 68 40 4E 40 00}
			$s1 = {55 8B EC 6A FF 68 50 4E 40 00}
			$s2 = {55 8B EC 6A FF 68 30 4E 40 00}
    condition:
            all of them
}