rule Trojan_Backdoor_Win32_Dowque_A_734
{
	meta:
		judge = "black"
		threatname = "Trojan[Backdoor]/Win32.Dowque.A"
		threattype = "Backdoor"
		family = "Dowque"
		hacker = "None"
		refer = "cc8a4343f171218e0eced9ff026e5795"
		author = "HuangYY"
		comment = "None"
		date = "2017-09-06"
		description = "None"

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