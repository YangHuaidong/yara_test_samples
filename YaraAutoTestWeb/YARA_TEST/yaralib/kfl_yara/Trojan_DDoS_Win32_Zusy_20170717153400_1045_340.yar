rule Trojan_DDoS_Win32_Zusy_20170717153400_1045_340 
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Win32.Zusy"
		threattype = "DDOS"
		family = "Zusy"
		hacker = "None"
		refer = "0311cd0be99abf4c71ebce8713cdf851"
		description = "None"
		comment = "None"
		author = "HuangYY"
		date = "2017-06-30"
	strings:
		$s0 = "360tray.exe"
		$s1 = "ast.exe"
		$s3 = "AST.exe"
		$s4 = "iexplore.exe"
		$s5 = "hangeulmenu"
		$s6 = "kanjimenu"

	condition:
		all of them
}
