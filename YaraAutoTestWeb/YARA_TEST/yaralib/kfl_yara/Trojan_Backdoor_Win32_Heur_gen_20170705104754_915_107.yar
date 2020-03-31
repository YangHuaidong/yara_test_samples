rule Trojan_Backdoor_Win32_Heur_gen_20170705104754_915_107 
{
	meta:
		judge = "black"
		threatname = "Trojan[Backdoor]/Win32.Heur.gen"
		threattype = "BackDoor"
		family = "Heur"
		hacker = "none"
		refer = "c8e8b5f517313cf60e7b40d2b6fa610c"
		description = "None"
		comment = "none"
		author = "xc"
		date = "2017-06-28"
	strings:
		$s0 = "222.186.34.15"
		$s1 = "\\quanye.exe"

	condition:
		all of them
}
