rule Trojan_Backdoor_Win32_RockRat_aba_383_196
{
    meta:
        judge = "black"
        threatname = "Trojan[Backdoor]/Win32.RockRat.aba"
        threattype = "backdoor"
        family = "RockRat"
        hacker = "None"
        author = "copy"
        refer = "d2881e56e66aeaebef7efaa60a58ef9b"
        comment = "https://www.carbonblack.com/2018/02/27/threat-analysis-rokrat-malware/"
        date = "2018-06-20"
        description = "None"
    strings:
		$n1 = "wscript.exe"
		$n2 = "cmd.exe"
		$s1 = "CreateProcess"
		$s2 = "VirtualAlloc"
		$s3 = "WriteProcessMemory"
		$s4 = "CreateRemoteThread"
		$s5 = "LoadResource"
		$s6 = "FindResource"
		$b1 = {33 C9 33 C0 E8 00 00 00 00 5E}
		$b2 = /\xB9.{3}\x00\x81\xE9?.{3}\x00/ 
		$b3 = {03 F1 83 C6 02} //Fix up position
		$b4 = {3E 8A 06 34 90 46} //XOR decode Key
		$b5 = {3E 30 06 46 49 83 F9 00 75 F6} //XOR routine and jmp to code
		$hpt_1 = {68 EC 97 03 0C} //api name hash value – Global Alloc
		$hpt_2 = {68 54 CA AF 91} //api name hash value – Virtual Alloc
		$hpt_3 = {68 8E 4E 0E EC} //api name hash value – Load Library
		$hpt_4 = {68 AA FC 0D 7C} //api name hash value – GetProc Addr
		$hpt_5 = {68 1B C6 46 79} //api name hash value – Virtual Protect
		$hpt_6 = {68 F6 22 B9 7C} //api name hash value – Global Free
		$henc_1 = {7B FF 84 10 1F} //api name hash value – Global Alloc
		$henc_2 = {7B 47 D9 BC 82} //api name hash value – Virtual Alloc
		$henc_3 = {7B 9D 5D 1D EC} //api name hash value – Load Library
		$henc_4 = {7B B9 EF 1E 6F} //api name hash value – GetProc Addr
		$henc_5 = {7B 08 D5 55 6A} //api name hash value – Virtual Protect
		$henc_6 = {7B E5 31 AA 6F} //api name hash value – Global Free
	condition:
		(1 of ($n*) and 4 of ($s*) and 4 of ($b*)) or all of ($hpt*) or all of ($henc*)
}