rule Trojan_RAT_Win32_Generic_hex_708
{
    meta:
	        judge = "black"
			threatname = "Trojan[RAT]/Win32.Generic.hex"
			threattype = "rat"
			family = "Generic"
			hacker = "none"
			refer = "91e0bac2651d904610368b47d939d273"
			comment = "none"
			author = "xc"
			date = "2017-07-27"
			description = "None"
	strings:
			$s0 = {C1 E9 1D C1 EA 1E 83 E1 01 83 E2 01 C1 E8 1F}
			$s1 = {83 E8 18 C1 F8 03 C1 E0 0C}
			$s2 = {83 EE 18 C1 FE 03 C1 E6 0C}
    condition:
            all of them
}