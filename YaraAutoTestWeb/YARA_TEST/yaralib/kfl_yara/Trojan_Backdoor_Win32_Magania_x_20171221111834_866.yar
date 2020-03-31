rule Trojan_Backdoor_Win32_Magania_x_20171221111834_866 
{
	meta:
		judge = "black"
		threatname = "Trojan[Backdoor]/Win32.Magania.x"
		threattype = "BackDoor"
		family = "Magania"
		hacker = "None"
		refer = "035bb6fed1e9ee18db2e0a8cfb7e2c2c"
		description = "None"
		comment = "None"
		author = "xc"
		date = "2017-09-28"
	strings:
		$s0 = "Msauo.exe"
		$s1 = "8a56abdb45dbd9f287f0df383828ade2"
		$s2 = "Ueiyuu ogaumgug"
		$s3 = "FSaomo eyemgwye"

	condition:
		all of them
}
