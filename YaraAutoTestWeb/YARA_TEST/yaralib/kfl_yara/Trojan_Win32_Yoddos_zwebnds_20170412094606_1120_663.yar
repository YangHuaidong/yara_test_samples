rule Trojan_Win32_Yoddos_zwebnds_20170412094606_1120_663 
{
	meta:
		judge = "black"
		threatname = "Trojan[Backdoor]/Win32.Yoddos.zwebnds"
		threattype = "RAT|DDOS"
		family = "Yoddos"
		hacker = "None"
		refer = "95201bc883f1885d5fadb7cf0c78f19e,b788819917be10c0f657b3556617006e,c6730107d2db7ab6e0ef4a8fce14a283,262d68507a4a47f43f057c0abba6d885,eb4bc4d2894ab345aca31bc071e049ce"
		description = "None"
		comment = "None"
		author = "sxy"
		date = "2017-04-06"
	strings:
		$s0 = "ZWebNds" nocase
		$s1 = "TrikIE/1.0"
		$s2 = "myfile.txt"
		$s3 = "%s%s%s_new%s"
		$s4 = "webnds_xxx.exe"
		$S5 = "RookIE/1.0"

	condition:
		5 of them
}
