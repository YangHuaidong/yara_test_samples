rule Trojan_Win32_Chicken_mm_1_20161213095257_1109_650 
{
	meta:
		judge = "black"
		threatname = "Trojan/Win32.Chicken_mm.1"
		threattype = "DDOS"
		family = "Chicken_mm"
		hacker = "None"
		refer = "d5ae6a10a7dd6ab60b80287d210a62d0,CA692B09A0F11531F0CA0A04C677572B"
		description = "None"
		comment = "None"
		author = "djw"
		date = "2016-09-01"
	strings:
		$s0 = "HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0"
		$s1 = "Chicken_Mutex_MM"
		$s2 = "\\Chicken\\Release\\Chicken.pdb"
		$s3 = "Windows XP"
		$s4 = "\\Processor(%d)\\%% Processor Time"

	condition:
		4 of them
}
