rule Trojan_RAT_Win32_Gh0st_dump_20161213095232_1097_622 
{
	meta:
		judge = "black"
		threatname = "Trojan[RAT]/Win32.Gh0st.dump"
		threattype = "rat"
		family = "Gh0st"
		hacker = "None"
		refer = "EE2B21DF333484987715096095EDBD60"
		description = "The characteristic dump string of Gh0st"
		comment = "None"
		author = "Dongjianwu"
		date = "2016-11-29"
	strings:
		$a = { 47 68 30 73 74 ?? ?? ?? ?? ?? ?? ?? ?? 78 9C }
		$b = "Gh0st Update"

	condition:
		any of them
}
