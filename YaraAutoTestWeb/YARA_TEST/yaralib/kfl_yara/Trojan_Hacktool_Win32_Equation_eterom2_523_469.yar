rule Trojan_Hacktool_Win32_Equation_eterom2_523_469
{
    meta:
        judge = "black"
        threatname = "Trojan[Hacktool]/Win32.Equation.eterom2"
        threattype = "Hacktool"
        family = "Equation"
        hacker = "None"
        author = "Florian Roth-copy"
        refer = "8d3ffa58cb0dc684c9c1d059a154cf43,4420f8917dc320a78d2ef14136032f69,2a8d437f0b9ffac482750fe052223c3d"
        comment = "APT Equation Grou-https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
        date = "2018-07-30"
        description = "Equation Group hack tool set Eternalromance_2 "
	strings:
		$x1 = "[+] Backdoor shellcode written" fullword ascii
		$x2 = "[*] Attempting exploit method %d" fullword ascii
	condition:
		( uint16(0) == 0x5a4d and filesize < 600KB and 1 of them )
}