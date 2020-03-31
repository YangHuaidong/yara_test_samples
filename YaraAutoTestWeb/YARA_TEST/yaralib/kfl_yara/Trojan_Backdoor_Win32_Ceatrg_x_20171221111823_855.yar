rule Trojan_Backdoor_Win32_Ceatrg_x_20171221111823_855 
{
	meta:
		judge = "black"
		threatname = "Trojan[Backdoor]/Win32.Ceatrg.x"
		threattype = "BackDoor"
		family = "Ceatrg"
		hacker = "None"
		refer = "061c348f462753d1913222c34d94f73b"
		description = "None"
		comment = "None"
		author = "xc"
		date = "2017-09-28"
	strings:
		$s0 = "127.0.0.1"
		$s1 = "BSettings"
		$s2 = "calc.exe"
		$s3 = "Flood"
		$s4 = "5-1299"
		$s5 = "Debug"

	condition:
		all of them
}
