rule Worm_Backdoor_Win32_Flame_1058
{
	meta:
		judge = "black"
		threatname = "Worm[Backdoor]/Win32.Flame"
		threattype = "ICS,Backdoor"
		family = "Flame"
		hacker = "None"
		refer = "bdc9e04388bda8527b398a8c34667e18"
		author = "LiuGuangzhu"
		comment = "None"
		date = "2019-03-09"
		description = "None"

	strings:		
		$s0 = {65 78 70 00 70 6F 77}
		$s1 = {3F 36 46 49 44 1B 3F 39 3E}
		$s3 = {2E 63 6D 64} //.cmd
		$s4 = {2E 6D 69 78 63 72 74} //.mixcrt
		$s5 = {2E 62 61 74} //.bat
		$s6 = {52 65 67 44 65 6C 65 74 65 56 61 6C 75 65 57} //RegDeleteValueW
		$s7 = {6D 73 73 65 63 6D 67 72 2E 6F 63 78} //mssecmgr.ocx
	condition:
		all of them
}