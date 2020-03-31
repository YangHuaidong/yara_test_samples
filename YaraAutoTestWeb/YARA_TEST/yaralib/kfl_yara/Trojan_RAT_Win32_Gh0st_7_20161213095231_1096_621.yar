rule Trojan_RAT_Win32_Gh0st_7_20161213095231_1096_621 
{
	meta:
		judge = "black"
		threatname = "Trojan[RAT]/Win32.Gh0st.7"
		threattype = "rat"
		family = "Gh0st"
		hacker = "None"
		refer = "EE2B21DF333484987715096095EDBD60"
		description = "Gh0st"
		comment = "None"
		author = "botherder https://github.com/botherder"
		date = "2016-12-08"
	strings:
		$s0 = /(G)host/
		$s1 = /(i)nflate 1\.1\.4 Copyright 1995-2002 Mark Adler/
		$s2 = /(d)eflate 1\.1\.4 Copyright 1995-2002 Jean-loup Gailly/
		$s3 = /(%)s\\shell\\open\\command/
		$s4 = /(G)etClipboardData/
		$s5 = /(W)riteProcessMemory/
		$s6 = /(A)djustTokenPrivileges/
		$s7 = /(W)inSta0\\Default/
		$s8 = /(#)32770/
		$s9 = /(#)32771/
		$s10 = /(#)32772/
		$s11 = /(#)32774/

	condition:
		all of them
}
