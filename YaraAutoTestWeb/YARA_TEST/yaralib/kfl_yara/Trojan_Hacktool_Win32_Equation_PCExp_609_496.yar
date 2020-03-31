rule Trojan_Hacktool_Win32_Equation_PCExp_609_496
{
    meta:
        judge = "black"
        threatname = "Trojan[Hacktool]/Win32.Equation.PCExp"
        threattype = "Hacktool"
        family = "Equation"
        hacker = "None"
        author = "Florian Roth-copy"
        refer = "71ac72eacbd9f662eeeb60169fdb7f78"
        comment = "APT Equation Grou-https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
        date = "2018-08-20"
        description = "Equation Group hack tool set PC_Exploit "
	strings:
		$s1 = "\\\\.\\pipe\\pcheap_reuse" fullword wide
		$s2 = "**** FAILED TO DUPLICATE SOCKET ****" fullword wide
		$s3 = "**** UNABLE TO DUPLICATE SOCKET TYPE %u ****" fullword wide
		$s4 = "YOU CAN IGNORE ANY 'ServiceEntry returned error' messages after this..." fullword wide
	condition:
		( uint16(0) == 0x5a4d and filesize < 20KB and 1 of them )
}