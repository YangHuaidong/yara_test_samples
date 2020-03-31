rule Trojan_Backdoor_Win32_Blakken_A_1_20170110095445_901_44 
{
	meta:
		judge = "black"
		threatname = "Trojan[Backdoor]/Win32.Blakken.A"
		threattype = "rat"
		family = "Blakken"
		hacker = "None"
		refer = "8b152fc5885cb4629f802543993f32a1"
		description = "None"
		comment = "None"
		author = "None"
		date = "2016-12-27"
	strings:
		$s0 = {C7 [1-5] 33 32 2E 64 C7 [1-5] 77 73 32 5F 66 C7 [1-5] 6C 6C} //ws3_32.dll
		$s1 = {C7 [1-5] 75 73 65 72 C7 [1-5] 33 32 2E 64 66 C7 [1-5] 6C 6C} //user32.dll
		$s2 = {C7 [1-5] 61 64 76 61 C7 [1-5] 70 69 33 32 C7 [1-5] 2E 64 6C 6C} //advapi32.dll
		$s3 = {C7 [1-5] 77 69 6E 69 C7 [1-5] 6E 65 74 2E C7 [1-5] 64 6C 6C}  //wininet.dll
		$s4 = {C7 [1-5] 73 68 65 6C C7 [1-5] 6C 33 32 2E C7 [1-5] 64 6C 6C} //shell32.dll
		$s5 = {C7 [1-5] 70 73 61 70 C7 [1-5] 69 2E 64 6C 66 C7 [1-5] 6C} //psapi.dll
		$s6 = {C7 [1-5] 6E 65 74 61 C7 [1-5] 70 69 33 32 C7 [1-5] 2E 64 6C 6C} //netapi32.dll
		$s7 = {C7 [1-5] 76 65 72 73 C7 [1-5] 69 6F 6E 2E C7 [1-5] 64 6C 6C} //version.dll
		$s8 = {C7 [1-5] 6F 6C 65 61 C7 [1-5] 75 74 33 32 C7 [1-5] 2E 64 6C 6C} //oldaut32.dll
		$s9 = {C7 [1-5] 69 6D 61 67 C7 [1-5] 65 68 6C 70 C7 [1-5] 2E 64 6C 6C} //imagehlp.dll

	condition:
		3 of them
}
