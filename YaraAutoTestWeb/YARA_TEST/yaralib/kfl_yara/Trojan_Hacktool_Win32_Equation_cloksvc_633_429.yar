rule Trojan_Hacktool_Win32_Equation_cloksvc_633_429
{
    meta:
        judge = "black"
        threatname = "Trojan[Hacktool]/Win32.Equation.cloksvc"
        threattype = "Hacktool"
        family = "Equation"
        hacker = "None"
        author = "Florian Roth-copy"
        refer = "9812a5c5a89b6287c8893d3651b981a0"
        comment = "APT Equation Grou-https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
        date = "2018-08-20"
        description = "Equation Group hack tool set clocksvc "
	strings:
		$x1 = "~debl00l.tmp" fullword ascii
		$x2 = "\\\\.\\mailslot\\c54321" fullword ascii
		$x3 = "\\\\.\\mailslot\\c12345" fullword ascii
		$x4 = "nowMutex" fullword ascii
		$s1 = "System\\CurrentControlSet\\Services\\MSExchangeIS\\ParametersPrivate" fullword ascii
		$s2 = "000000005017C31B7C7BCF97EC86019F5026BE85FD1FB192F6F4237B78DB12E7DFFB07748BFF6432B3870681D54BEF44077487044681FB94D17ED04217145B98" ascii
		$s3 = "00000000E2C9ADBD8F470C7320D28000353813757F58860E90207F8874D2EB49851D3D3115A210DA6475CCFC111DCC05E4910E50071975F61972DCE345E89D88" ascii
	condition:
		( uint16(0) == 0x5a4d and filesize < 200KB and ( 1 of ($x*) or 2 of ($s*) ) )
}