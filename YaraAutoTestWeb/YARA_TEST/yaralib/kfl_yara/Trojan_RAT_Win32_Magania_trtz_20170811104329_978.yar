rule Trojan_RAT_Win32_Magania_trtz_20170811104329_978 
{
	meta:
		judge = "black"
		threatname = "Trojan[RAT]/Win32.Magania.trtz"
		threattype = "rat"
		family = "Magania"
		hacker = "None"
		refer = "01f26dab28aa34deecfd62495a9c3366"
		description = "None"
		comment = "None"
		author = "copy"
		date = "2017-07-24"
	strings:
		$s0 = "Netroot.dat" nocase wide ascii
		$s1 = "Vwxyab Defghijk" nocase wide ascii
		$s2 = "%c%c%c%c%c%c.dll" nocase wide ascii
		$s3 = "GyQmHisnYSl2dnV1YSEoN216c3N2Qw" nocase wide ascii

	condition:
		all of them
}
