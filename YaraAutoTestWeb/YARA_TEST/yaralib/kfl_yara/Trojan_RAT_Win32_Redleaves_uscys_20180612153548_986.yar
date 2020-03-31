rule Trojan_RAT_Win32_Redleaves_uscys_20180612153548_986 
{
	meta:
		judge = "black"
		threatname = "Trojan[RAT]/Win32.Redleaves.uscys"
		threattype = "rat"
		family = "Redleaves"
		hacker = "None"
		refer = "7f8a867a8302fe58039a6db254d335ae"
		description = "Detect the DLL responsible for loading and deobfuscating the DAT file containing shellcode and core REDLEAVES RAT"
		comment = "None"
		author = "USG-copy"
		date = "2018-05-30"
	strings:
		$s0 = {32 0c 3a 83 c2 02 88 0e 83 fa 08 [4-14] 32 0c 3a 83 c2 02 88 0e 83 fa 10}

	condition:
		all of them
}
