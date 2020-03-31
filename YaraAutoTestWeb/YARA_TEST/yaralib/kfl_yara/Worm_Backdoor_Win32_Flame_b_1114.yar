rule Worm_Backdoor_Win32_Flame_b_1114
{
	meta:
		judge = "black"
		threatname = "Worm[Backdoor]/Win32.Flame.b"
		threattype = "ICS,Backdoor"
		family = "Flame"
		hacker = "None"
		refer = "BDDBC6974EB8279613B833804EDA12F9"
		author = "LiuGuangzhu"
		comment = "None"
		date = "2019-04-19"
		description = "None"

	strings:		
		$s0 = {73 74 61 72 74 20 2F 77 61 69 74 20 52 75 6E 44 6C 6C 33 32 2E 65 78 65 20 25 77 69 6E 64 69 72 25 5C 74 65 6D 70 5C 7E 5A 46 46 30 34 32 2E 6F 63 78 2C 44 44 45 6E 75 6D 43 61 6C 6C 62 61 63 6B} //start /wait RunDll32.exe %windir%\temp\~ZFF042.ocx,DDEnumCallback
		$s1 = {64 65 6C 20 2F 71 20 25 77 69 6E 64 69 72 25 5C 74 65 6D 70 5C 7E 5A 46 46 30 34 32 2E 6F 63 78 4A} //del /q %windir%\temp\~ZFF042.ocxJ
		$s2 = {53 4E 41 43 4B 5F 45 4E 54 49 54 59 5F 41 43 54 49 4F 4E 2E 6C 75 61} //SNACK_ENTITY_ACTION.lua
		$s3 = {61 00 64 00 6D 00 69 00 6E 00 24 00 5C 00 54 00 65 00 6D 00 70 00 5C 00 7E 00 5A 00 46 00 46 00 30 00 34 00 32 00 2E 00 6F 00 63 00 78 00} //admin$\Temp\~ZFF042.ocx
		$s4 = {61 00 64 00 6D 00 69 00 6E 00 24 00 5C 00 54 00 65 00 6D 00 70 00 5C 00 66 00 69 00 62 00 33 00 32 00 2E 00 62 00 61 00 74 00} //admin$\Temp\fib32.bat
		$s5 = {61 00 64 00 6D 00 69 00 6E 00 24 00 5C 00 73 00 79 00 73 00 74 00 65 00 6D 00 33 00 32 00 5C 00 73 00 73 00 74 00 61 00 62 00} //admin$\system32\sstab
		$s6 = {25 00 77 00 69 00 6E 00 64 00 69 00 72 00 25 00 5C 00 73 00 79 00 73 00 74 00 65 00 6D 00 33 00 32 00 5C 00 6E 00 74 00 65 00 70 00 73 00 33 00 32 00 2E 00 6F 00 63 00 78 00} //%windir%\system32\nteps32.ocx
	condition:
		all of them
}