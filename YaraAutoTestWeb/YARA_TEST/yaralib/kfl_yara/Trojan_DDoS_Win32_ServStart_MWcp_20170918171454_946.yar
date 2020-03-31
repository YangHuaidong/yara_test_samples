rule Trojan_DDoS_Win32_ServStart_MWcp_20170918171454_946 
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Win32.ServStart.MWcp"
		threattype = "DDOS"
		family = "ServStart"
		hacker = "None"
		refer = "299522fe80c136bdaca59c58b5a2d4e9"
		description = "None"
		comment = "None"
		author = "copy"
		date = "2017-09-14"
	strings:
		$s0 = ")\\MemLoader\\MainFrm.cpp" nocase wide ascii
		$s1 = "losYA" nocase wide ascii
		$s2 = ")\\MemLoader\\WaveView.cpp" nocase wide ascii
		$s3 = ")\\MemLoader\\WaveDoc.cpp" nocase wide ascii

	condition:
		all of them
}
