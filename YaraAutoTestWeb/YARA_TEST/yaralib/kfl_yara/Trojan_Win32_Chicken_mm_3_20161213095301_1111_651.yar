rule Trojan_Win32_Chicken_mm_3_20161213095301_1111_651 
{
	meta:
		judge = "black"
		threatname = "Trojan/Win32.Chicken_mm.3"
		threattype = "DDOS"
		family = "Chicken_mm"
		hacker = "None"
		refer = "d5ae6a10a7dd6ab60b80287d210a62d0,CA692B09A0F11531F0CA0A04C677572B"
		description = "None"
		comment = "None"
		author = "djw"
		date = "2016-09-01"
	strings:
		$s0 = { e6 af 9b e6 af 9b }
		$s1 = ".pdb"

	condition:
		all of them
}
