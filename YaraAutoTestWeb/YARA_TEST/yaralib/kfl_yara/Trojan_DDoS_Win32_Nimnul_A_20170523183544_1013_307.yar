rule Trojan_DDoS_Win32_Nimnul_A_20170523183544_1013_307 
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Win32.Nimnul.A"
		threattype = "DDOS"
		family = "Nimnul"
		hacker = "None"
		refer = "A56BBD5D5564B8FBA5A659904DBD1138,A6862A588D0919D0F3093BF0AA654F77,5B516477F98D01878C03743716D6496A"
		description = "None"
		comment = "None"
		author = "sxy"
		date = "2017-05-10"
	strings:
		$hex_JJsPNb_exe = { c7 45 b8 4a 4a 73 50 c7 45 bc 4e 62 2e 65 c7 45 c0 78 65 00 00 c7 45 c4 00 00 00 00 }
		$hex_AeJrzN_exe = { c7 45 b8 41 65 4a 72 c7 45 bc 7a 4e 2e 65 c7 45 c0 78 65 00 00 c7 45 c4 00 00 00 00 }
		$hex_sGLWT_exe = { c7 45 b8 73 47 4c 57 c7 45 bc 54 2e 65 78 c7 45 c0 65 00 00 00 c7 45 c4 00 00 00 00 }

	condition:
		1 of them
}
