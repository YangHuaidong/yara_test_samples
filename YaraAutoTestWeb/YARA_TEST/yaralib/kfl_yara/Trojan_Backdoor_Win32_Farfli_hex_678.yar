rule Trojan_Backdoor_Win32_Farfli_hex_678
{
    meta:
	        judge = "black"
			threatname = "Trojan[Backdoor]/Win32.Farfli.hex"
			threattype = "backdoor"
			family = "Farfli"
			hacker = "none"
			refer = "6b75286ff8aef529d02c7fad7d85a968"
			comment = "none"
			author = "xc"
			date = "2017-08-03"
			description = "None"
	strings:
			$s0 = {C1 E9 1D C1 EA 1E 8B F0 83 E1 01 83 E2 01 C1 EE 1F A9 00 00 00 02} 
			$s1 = {25 FF 00 00 00 C1 EA 18 33 CB 83 C6 04} 
			$s2 = {25 FF 00 00 00 C1 EA 18 33 CB 83 EF 20}
    condition:
            all of them
}