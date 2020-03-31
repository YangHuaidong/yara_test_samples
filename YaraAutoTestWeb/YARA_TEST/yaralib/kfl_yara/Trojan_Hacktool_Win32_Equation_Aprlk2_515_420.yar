rule Trojan_Hacktool_Win32_Equation_Aprlk2_515_420
{
    meta:
        judge = "black"
        threatname = "Trojan[Hacktool]/Win32.Equation.Aprlk2"
        threattype = "Hacktool"
        family = "Equation"
        hacker = "None"
        author = "Florian Roth-copy"
        refer = "7e1a081a93d07705bd5ed2d2919c4eea,dc53bd258f6debef8604d441c85cb539"
        comment = "APT Equation Grou-https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
        date = "2018-07-30"
        description = "Equation Group hack tool set April Leak "
	strings:
		$x1 = "[-] %s - Target might not be in a usable state." fullword ascii
		$x2 = "[*] Exploiting Target" fullword ascii
		$x3 = "[-] Encoding Exploit Payload failed!" fullword ascii
	condition:
		( uint16(0) == 0x5a4d and filesize < 100KB and 1 of them )
}