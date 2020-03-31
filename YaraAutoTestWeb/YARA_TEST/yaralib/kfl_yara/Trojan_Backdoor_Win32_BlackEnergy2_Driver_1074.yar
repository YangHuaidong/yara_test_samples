rule Trojan_Backdoor_Win32_BlackEnergy2_Driver_1074
{
	meta:
		judge = "black"
		threatname = "Trojan[Backdoor]/Win32.BlackEnergy2.Driver"
		threattype = "ICS,Backdoor"
		family = "BlackEnergy"
		hacker = "None"
		refer = "26a10fa32d0d7216c8946c8d83dd3787"
		author = "LiuGuangzhu"
		comment = "None"
		date = "2019-03-09"
		description = "None"
	strings:
		$a0 = {7E 4B 54 1A}
		$a1 = {E0 3C 96 A2}
		$a2 = "IofCompleteRequest" ascii
		$b0 = {31 A1 44 BC}
		$b1 = "IoAttachDeviceToDeviceStack" ascii
		$b2 = "KeInsertQueueDpc" ascii
		$c0 = {A3 41 FD 66}
		$c1 = {61 1E 4E F8}
		$c2 = "PsCreateSystemThread" ascii
	condition:
		all of ($a*) and 3 of ($b*, $c*)
}