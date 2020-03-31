rule Trojan_Downloader_Linux_Tsunami_ask_20171221112006_954 
{
	meta:
		judge = "black"
		threatname = "Trojan[Downloader]/Linux.Tsunami.ask"
		threattype = "Downloader"
		family = "Tsunami"
		hacker = "None"
		refer = "0de87c318cbaf71faf728ec38e7114bd"
		description = "None"
		comment = "None"
		author = "copy"
		date = "2017-10-18"
	strings:
		$s0 = "chmod +x" nocase wide ascii
		$s1 = "chmod 700" nocase wide ascii
		$s2 = "var//tmp//pty" nocase wide ascii
		$s3 = "var//run//pty" nocase wide ascii

	condition:
		all of them
}
