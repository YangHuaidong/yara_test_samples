rule Trojan_DDoS_Win32_Resod_Kernel32_20170324123750_1018_313 
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Win32.Resod.Kernel32"
		threattype = "DDOS"
		family = "Resod"
		hacker = "None"
		refer = "eadb9d1568f5e5324428e4fd0137bca4"
		description = "None"
		comment = "None"
		author = "cjf"
		date = "2017-03-01"
	strings:
		$s0 = "KERNEL32" fullword
		$s1 = "DDoSer"
		$s2 = "r<6,^hg7"
		$s3 = "RegisterServiceProcess"
		$s4 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"

	condition:
		4 of them
}
