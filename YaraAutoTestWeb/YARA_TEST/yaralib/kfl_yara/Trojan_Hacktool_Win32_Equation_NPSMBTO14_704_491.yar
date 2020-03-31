rule Trojan_Hacktool_Win32_Equation_NPSMBTO14_704_491
{
    meta:
        judge = "black"
        threatname = "Trojan[Hacktool]/Win32.Equation.NPSMBTO14"
        threattype = "Hacktool"
        family = "Equation"
        hacker = "None"
        author = "Florian Roth-copy"
        refer = "9ee1e8bc87085a2891e1620c11a4c5c8,63138b529e830a57197c1caf9978d582"
        comment = "APT Equation Grou-https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
        date = "2018-09-03"
        description = "Equation Group hack tool set NameProbe_SMBTOUCH_14 "
	strings:
		$s1 = "DEC Pathworks TCPIP service on Windows NT" fullword ascii
		$s2 = "<\\\\__MSBROWSE__> G" fullword ascii
		$s3 = "<IRISNAMESERVER>" fullword ascii
	condition:
		( uint16(0) == 0x5a4d and filesize < 300KB and all of them )
}