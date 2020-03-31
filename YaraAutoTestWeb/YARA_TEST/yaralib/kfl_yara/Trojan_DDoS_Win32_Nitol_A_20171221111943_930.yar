rule Trojan_DDoS_Win32_Nitol_A_20171221111943_930 
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Win32.Nitol.A"
		threattype = "DDOS"
		family = "Nitol"
		hacker = "None"
		refer = "011575c3137d16ad2a11be402b2c47a7"
		description = "None"
		comment = "None"
		author = "mqx"
		date = "2017-11-24"
	strings:
		$s0 = "SYSTEM\\CurrentControlSet\\Services\\"
		$s1 = "%s%d_IEFile.exe"
		$s2 = "c:\\conf.h"
		$s3 = "index.dat"
		$s4 = "desktop.ini"
		$s5 = "IEBroser.EXE"

	condition:
		5 of them
}
