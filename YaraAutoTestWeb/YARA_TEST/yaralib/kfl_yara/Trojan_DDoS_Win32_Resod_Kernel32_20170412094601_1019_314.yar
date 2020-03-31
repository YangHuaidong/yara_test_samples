rule Trojan_DDoS_Win32_Resod_Kernel32_20170412094601_1019_314 
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
		author = "djw"
		date = "2016-12-14"
	strings:
		$s0 = "KERNEL32" fullword
		$s1 = "DDoSer" nocase wide ascii
		$s2 = "KillTimer" nocase wide ascii
		$s3 = "GetExitCodeThread" nocase wide ascii
		$s4 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" nocase wide ascii
		$a0 = "ShellExecuteA"
		$a1 = "ss#KERNEL32o" nocase wide ascii

	condition:
		all of ($s*) or all of ($a*)
}
