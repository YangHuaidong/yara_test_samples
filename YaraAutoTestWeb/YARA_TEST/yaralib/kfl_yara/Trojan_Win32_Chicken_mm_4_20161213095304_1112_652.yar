rule Trojan_Win32_Chicken_mm_4_20161213095304_1112_652 
{
	meta:
		judge = "black"
		threatname = "Trojan/Win32.Chicken_mm.4"
		threattype = "DDOS"
		family = "Chicken_mm"
		hacker = "None"
		refer = "d5ae6a10a7dd6ab60b80287d210a62d0,CA692B09A0F11531F0CA0A04C677572B"
		description = "None"
		comment = "None"
		author = "djw"
		date = "2016-09-01"
	strings:
		$s0 = "Chicken.pdb"
		$s1 = "\\Chicken\\Release\\svchost.pdb"
		$s2 = "\\RJShell\\Release\\RJShell.pdb"
		$s3 = "\\Chicken-windows\\Release\\svchost.pdb"
		$s4 = "2008\\Chicken\\x64\\Release\\svchost.pdb"

	condition:
		1 of them
}
