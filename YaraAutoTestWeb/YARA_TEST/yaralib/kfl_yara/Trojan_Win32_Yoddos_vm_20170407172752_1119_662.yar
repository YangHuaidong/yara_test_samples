rule Trojan_Win32_Yoddos_vm_20170407172752_1119_662 
{
	meta:
		judge = "black"
		threatname = "Trojan[Backdoor]/Win32.Yoddos.vm"
		threattype = "RAT|DDOS"
		family = "Yoddos"
		hacker = "None"
		refer = "f63ba22b4a508616014e0e303fc594d4"
		description = "None"
		comment = "None"
		author = "sxy"
		date = "2017-03-29"
	strings:
		$s0 = "vmwar.exe"
		$s1 = "C:\\WINDOWS\\system32\\vmware.exe"
		$s2 = "tmsst.exe"
		$s3 = "VM.exe"
		$s4 = "VMm.exe"
		$s5 = "VMn.exe"
		$s6 = "VMt.exe"

	condition:
		3 of them
}
