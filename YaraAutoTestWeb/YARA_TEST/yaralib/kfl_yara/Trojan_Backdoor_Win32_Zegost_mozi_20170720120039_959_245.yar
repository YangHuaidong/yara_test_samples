rule Trojan_Backdoor_Win32_Zegost_mozi_20170720120039_959_245 
{
	meta:
		judge = "black"
		threatname = "Trojan[Backdoor]/Win32.Zegost.mozi"
		threattype = "BackDoor"
		family = "Zegost"
		hacker = "none"
		refer = "c5e5714df44be16b68268a96501b4811"
		description = "None"
		comment = "none"
		author = "xc"
		date = "2017-07-14"
	strings:
		$s0 = "mozi"
		$s1 = "C:\\WINDOWS\\TU.exe"
		$s2 = "peelS"

	condition:
		all of them
}
