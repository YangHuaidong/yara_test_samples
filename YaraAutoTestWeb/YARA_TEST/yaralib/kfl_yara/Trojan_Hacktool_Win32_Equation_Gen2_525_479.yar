rule Trojan_Hacktool_Win32_Equation_Gen2_525_479
{
    meta:
        judge = "black"
        threatname = "Trojan[Hacktool]/Win32.Equation.Gen2"
        threattype = "Hacktool"
        family = "Equation"
        hacker = "None"
        author = "Florian Roth-copy"
        refer = "52933e70e022054153aa37dfd44bcafa,a35c794efe857bfd2cfffa97dd4a2ed3,6db7cd3b51f7f4d4b4f201f62d392745,619b15112ce02459d3bb414b6ea653ed"
        comment = "APT Equation Grou-https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
        date = "2018-07-30"
        description = "Equation Group hack tool set Gen2 "
	strings:
		$s1 = "[+] Setting password : (NULL)" fullword ascii
		$s2 = "[-] TbBuffCpy() failed!" fullword ascii
		$s3 = "[+] SMB negotiation" fullword ascii
		$s4 = "12345678-1234-ABCD-EF00-0123456789AB" fullword ascii
		$s5 = "Value must end with 0000 (2 NULLs)" fullword ascii
		$s6 = "[*] Configuring Payload" fullword ascii
		$s7 = "[*] Connecting to listener" fullword ascii
		$op1 = { b0 42 40 00 89 44 24 30 c7 44 24 34 }
		$op2 = { eb 59 8b 4c 24 10 68 1c 46 }
	condition:
		( uint16(0) == 0x5a4d and filesize < 80KB and 1 of ($s*) and 1 of ($op*) ) or 3 of them
}