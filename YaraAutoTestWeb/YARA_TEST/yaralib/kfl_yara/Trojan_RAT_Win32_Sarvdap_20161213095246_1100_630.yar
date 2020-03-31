rule Trojan_RAT_Win32_Sarvdap_20161213095246_1100_630 
{
	meta:
		judge = "black"
		threatname = "Trojan[RAT]/Win32.Sarvdap"
		threattype = "rat"
		family = "Sarvdap"
		hacker = "None"
		refer = "41481c0a3180b63bbff7ca4e754cd5f7"
		description = "None"
		comment = "None"
		author = "dengcong"
		date = "2016-10-23"
	strings:
		$s0 = "reg.exe add \"HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\" /t REG_SZ /f /v %s /d"
		$s1 = "svchost.exe"
		$s2 = "IMAGE_BIN"
		$S3 = "MSUNatService"
		$S4 = "MS UNat Service"
		$S5 = "MS_UNAT_MODULE_TO_START"
		$S6 = "%s%x%x.exe"
		$s7 = "micheal jackon is great"
		$s8 = "someone is over there"
		$s9 = "Tonight you will become a wellknown person"
		$s10 = "haystack"
		$s11 = "mall.giorgioinvernizzi.com"
		$s12 = "k1.clanupstairs.com"
		$s13 = "dop.premiocastelloacaja.com"

	condition:
		10 of them
}
