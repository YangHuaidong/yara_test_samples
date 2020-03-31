rule Trojan_RAT_Win32_DarkComet_trkwks_20170110095500_1084_607 
{
	meta:
		judge = "black"
		threatname = "Trojan[RAT]/Win32.DarkComet.trkwks"
		threattype = "rat"
		family = "DarkComet"
		hacker = "None"
		refer = "4C59641274DED17C486F0335A0CFA8B0,42121E4CD5E217F0B8A9CCDA9B0C38CD,59923DBE93B7A4A648D0AA151F7E849A"
		description = "DarkComet RAT"
		comment = "None"
		author = "DJW"
		date = "2016-12-05"
	strings:
		$s0 = "HttpOpenRequestA"
		$s1 = "pipe\\trkwks"
		$s2 = "LastGood.Tmp"
		$s3 = "SvcctrlStartEvent_A3752DX"

	condition:
		3 of them
}
