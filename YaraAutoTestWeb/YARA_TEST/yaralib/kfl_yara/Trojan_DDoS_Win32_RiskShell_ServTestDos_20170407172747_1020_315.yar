rule Trojan_DDoS_Win32_RiskShell_ServTestDos_20170407172747_1020_315 
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Win32.RiskShell.ServTestDos"
		threattype = "DDOS"
		family = "RiskShell"
		hacker = "None"
		refer = "27255ca6b0b1e419696fb7a25cf8ede1,27255ca6b0b1e419696fb7a25cf8ede1"
		description = "None"
		comment = "None"
		author = "djw"
		date = "2017-03-29"
	strings:
		$a0 = "ServTestDos" nocase wide ascii
		$a1 = "SerfdsfvTestDos" nocase wide ascii
		$s0 = ".vmp1"
		$s1 = "GetSystemInfo"  nocase wide ascii
		$s2 = "ConnectNamedPipe"
		$s3 = "SetServiceStatus"

	condition:
		(all of ($s*)) and (1 of ($a*))
}
