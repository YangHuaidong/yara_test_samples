rule Worm_Backdoor_Win32_Flame_a_1113
{
	meta:
		judge = "black"
		threatname = "Worm[Backdoor]/Win32.Flame.a"
		threattype = "ICS,Backdoor"
		family = "Flame"
		hacker = "None"
		refer = "0A17040C18A6646D485BDE9CE899789F"
		author = "LiuGuangzhu"
		comment = "None"
		date = "2019-04-29"
		description = "None"

	strings:		
		$s0 = ".mixcrt"
		$s1 = {6D 73 73 65 63 6D 67 72 2E 6F 63 78}
		$s2 = {25 00 73 00 5C 00 54 00 48 00 5F 00 50 00 4F 00 4F 00 4C 00 5F 00 53 00 48 00 44 00 5F 00 4D 00 54 00 58 00 5F 00 46 00 53 00 57 00 39 00 35 00 58 00 51 00 5F 00 25 00 64}
		$s3 = {53 00 65 00 73 00 73 00 69 00 6F 00 6E 00 5C 00 25 00 64}
	condition:
		all of them
}