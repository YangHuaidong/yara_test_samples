rule Trojan_Backdoor_Win32_Zegost_auto_20170407172743_958_244 
{
	meta:
		judge = "black"
		threatname = "Trojan[Backdoor]/Win32.Zegost.auto"
		threattype = "BackDoor"
		family = "Zegost"
		hacker = "None"
		refer = "46bdf586cb3d9ab4b4b9b949dbbfaf15"
		description = "None"
		comment = "None"
		author = "sxy"
		date = "2017-03-30"
	strings:
		$s0 = "Autoexec"
		$s1 = "%c%c%c%c%c%c.bat"
		$s2 = "DirectX Remover"
		$s3 = "3389"

	condition:
		all of them
}
