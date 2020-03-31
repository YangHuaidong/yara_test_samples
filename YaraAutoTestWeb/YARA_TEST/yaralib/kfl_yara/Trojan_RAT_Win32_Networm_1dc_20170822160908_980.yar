rule Trojan_RAT_Win32_Networm_1dc_20170822160908_980 
{
	meta:
		judge = "black"
		threatname = "Trojan[RAT]/Win32.Networm.1dc"
		threattype = "rat"
		family = "Networm"
		hacker = "None"
		refer = "5e513a458972e3b6702115354e432372"
		description = "None"
		comment = "None"
		author = "copy"
		date = "2017-08-10"
	strings:
		$s0 = "Yuemingl.txt" nocase wide ascii
		$s1 = "hackshen.exe" nocase wide ascii
		$s2 = "svchost.exe" nocase wide ascii

	condition:
		all of them
}
