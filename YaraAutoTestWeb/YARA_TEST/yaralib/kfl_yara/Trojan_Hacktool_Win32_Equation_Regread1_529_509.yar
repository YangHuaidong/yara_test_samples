rule Trojan_Hacktool_Win32_Equation_Regread1_529_509
{
    meta:
        judge = "black"
        threatname = "Trojan[Hacktool]/Win32.Equation.Regread1"
        threattype = "Hacktool"
        family = "Equation"
        hacker = "None"
        author = "Florian Roth-copy"
        refer = "9d6f88030fd7775129d947ad1dd9c689"
        comment = "APT Equation Grou-https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
        date = "2018-07-30"
        description = "Equation Group hack tool set Regread1 "
	strings:
		$s1 = "[+] Connected to the Registry Service" fullword ascii
		$s2 = "f08d49ac41d1023d9d462d58af51414daff95a6a" fullword ascii
	condition:
		( uint16(0) == 0x5a4d and filesize < 80KB and 1 of them )
}