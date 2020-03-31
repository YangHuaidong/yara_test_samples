rule Trojan_Backdoor_Win32_Farfli_s_20170720120037_912_88 
{
	meta:
		judge = "black"
		threatname = "Trojan[Backdoor]/Win32.Farfli.s"
		threattype = "BackDoor"
		family = "Farfli"
		hacker = "none"
		refer = "c5f3363b4316c0a17540629dbfc4d98c"
		description = "None"
		comment = "none"
		author = "xc"
		date = "2017-07-14"
	strings:
		$s0 = "S.exe"
		$s1 = "DUB.exe"
		$s2 = "\\\\.\\agmkis2"
		$s3 = "4648150"

	condition:
		all of them
}
