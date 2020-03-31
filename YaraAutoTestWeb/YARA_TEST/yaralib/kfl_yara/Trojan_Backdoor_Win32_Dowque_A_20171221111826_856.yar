rule Trojan_Backdoor_Win32_Dowque_A_20171221111826_856 
{
	meta:
		judge = "black"
		threatname = "Trojan[Backdoor]/Win32.Dowque.A"
		threattype = "BackDoor"
		family = "Dowque"
		hacker = "None"
		refer = "cc8a4343f171218e0eced9ff026e5795"
		description = "None"
		comment = "None"
		author = "HuangYY"
		date = "2017-09-06"
	strings:
		$s0 = "dTemp.exe"
		$s1 = "Beep.sys"
		$s3 = "SystemRoot\\System32"
		$s4 = "LoadPeFile OK!"
		$s5 = "ntoskrnl.exe"
		$s6 = "ntkrnlpa.exe"

	condition:
		all of them
}
