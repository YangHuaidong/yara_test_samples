rule Trojan_Hacktool_Win32_Equation_yak_595_529
{
    meta:
        judge = "black"
        threatname = "Trojan[Hacktool]/Win32.Equation.yak"
        threattype = "Hacktool"
        family = "Equation"
        hacker = "None"
        author = "Florian Roth-copy"
        refer = "e1ad634a76511878f63ef9e0acd2d98a"
        comment = "APT Equation Grou-https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
        date = "2018-08-13"
        description = "Equation Group hack tool set yak "
	strings:
		$x1 = "-xd = dump archive data & store in scancodes.txt" fullword ascii
		$x2 = "-------- driver start token -------" fullword wide
		$x3 = "-------- keystart token -------" fullword wide
		$x4 = "-xta = same as -xt but show special chars & store in keys_all.txt" fullword ascii
	condition:
		( uint16(0) == 0x5a4d and filesize < 800KB and 2 of them )
}