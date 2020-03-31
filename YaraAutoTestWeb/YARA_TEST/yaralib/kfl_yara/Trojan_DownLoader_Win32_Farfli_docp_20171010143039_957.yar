rule Trojan_DownLoader_Win32_Farfli_docp_20171010143039_957 
{
	meta:
		judge = "black"
		threatname = "Trojan[DownLoader]/Win32.Farfli.docp"
		threattype = "Downloader"
		family = "Farfli"
		hacker = "None"
		refer = "e23dee5b76393b6514d1ff68441c831b"
		description = "None"
		comment = "None"
		author = "copy"
		date = "2017-09-14"
	strings:
		$s0 = "MbWdP7WG" nocase wide ascii
		$s1 = "tem\\CentralProcessor\\0" nocase wide ascii
		$s2 = "mozi" nocase wide ascii
		$s3 = "HARDWARE\\DES" nocase wide ascii

	condition:
		all of them
}
