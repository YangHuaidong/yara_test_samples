rule Trojan_Win32_Bladabindi_g_20161213095256_1108_649 
{
	meta:
		judge = "black"
		threatname = "Trojan/Win32.Bladabindi.g"
		threattype = "rat"
		family = "Bladabindi"
		hacker = "None"
		refer = "98afb5e03e2eff9dbcfe61c99633a7fe"
		description = "VirusRat"
		comment = "None"
		author = "Kevin Breen <kevin@techanarchy.net>"
		date = "2016-06-23"
	strings:
		$s0 = "virustotal"
		$s1 = "virusscan"
		$s2 = "abccba"
		$s3 = "pronoip"
		$s4 = "streamWebcam"
		$s5 = "DOMAIN_PASSWORD"
		$s6 = "Stub.Form1.resources"
		$s7 = "ftp://{0}@{1}" wide
		$s8 = "SELECT * FROM moz_logins" wide
		$s9 = "SELECT * FROM moz_disabledHosts" wide
		$s10 = "DynDNS\\Updater\\config.dyndns" wide
		$s11 = "|BawaneH|" wide

	condition:
		all of them
}
