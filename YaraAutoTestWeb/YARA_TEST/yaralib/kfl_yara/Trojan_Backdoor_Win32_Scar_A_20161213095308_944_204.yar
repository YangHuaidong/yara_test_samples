rule Trojan_Backdoor_Win32_Scar_A_20161213095308_944_204 
{
	meta:
		judge = "black"
		threatname = "Trojan[Backdoor]/Win32.Scar.A"
		threattype = "RAT|DDOS"
		family = "Scar"
		hacker = "None"
		refer = "AC805AEF5332FC701917DF8DDD432F20"
		description = "None"
		comment = "None"
		author = "sxy"
		date = "2016-11-29"
	strings:
		$s0 = "zzdszzds"
		$s1 = "www.qianai8.com:7200"
		$s2 = "NT LM Security Support Providers"
		$s3 = "%c%c%c%c%c%c.exe"
		$s4 = "GET %s HTTP/1.1"
		$s5 = "PlusCtrl.dll"

	condition:
		4 of them
}
