rule Trojan_Hacktool_Win32_Equation_regprobe_647_508
{
    meta:
        judge = "black"
        threatname = "Trojan[Hacktool]/Win32.Equation.regprobe"
        threattype = "Hacktool"
        family = "Equation"
        hacker = "None"
        author = "Florian Roth-copy"
        refer = "550af0ee163cd29b76c32b67836bc978"
        comment = "APT Equation Grou-https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
        date = "2018-08-20"
        description = "Equation Group hack tool set regprobe "
	strings:
		$x1 = "Usage: %s targetIP protocolSequence portNo [redirectorIP] [CLSID]" fullword ascii
		$x2 = "key does not exist or pinging w2k system" fullword ascii
		$x3 = "RpcProxy=255.255.255.255:65536" fullword ascii
	condition:
		( uint16(0) == 0x5a4d and filesize < 100KB and 1 of them )
}