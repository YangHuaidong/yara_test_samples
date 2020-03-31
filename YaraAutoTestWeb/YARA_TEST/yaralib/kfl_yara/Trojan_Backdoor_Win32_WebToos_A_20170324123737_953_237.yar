rule Trojan_Backdoor_Win32_WebToos_A_20170324123737_953_237 
{
	meta:
		judge = "black"
		threatname = "Trojan[Backdoor]/Win32.WebToos.A"
		threattype = "BackDoor"
		family = "WebToos"
		hacker = "None"
		refer = "91fc27de2c5b2dfbc69be16a80200b90"
		description = "None"
		comment = "None"
		author = "sxy"
		date = "2017-02-28"
	strings:
		$s0 = "Taskkill"
		$s1 = "Bill"
		$s2 = "DbSecuritySpt"
		$s3 = "agony rootkit v1.0"
		$s4 = "%d, Url: %s"
		$s5 = "%s -s service         : hide the service"
		$s6 = "%s -stop              : stop and uninstall rootkit"

	condition:
		4 of them
}
