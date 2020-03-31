rule Trojan_DDoS_Linux_Elknot_zn_20161213095135_966_258 
{
	meta:
		judge = "black"
		threatname = "Trojan[DDOS]/Linux.Elknot.zn"
		threattype = "DDOS"
		family = "Elknot"
		hacker = "None"
		refer = "387D4B2BBE856D8C76C499F32AEE47BF"
		description = "Linux / Windows DDoS botnet, alias DnsAmp,http://www.kernelmode.info/forum/viewtopic.php?f=16&t=3099"
		comment = "None"
		author = "dongjianwu, @benkow_"
		date = "2016-11-29"
	strings:
		$a = "ZN8CUtility7DeCryptEPciPKci"
		$b = "ZN13CThreadAttack5StartEP11CCmdMessage"

	condition:
		$a and $b
}
