rule Trojan_Hacktool_Win32_Equation_ETSMBTO17_701_471
{
    meta:
        judge = "black"
        threatname = "Trojan[Hacktool]/Win32.Equation.ETSMBTO17"
        threattype = "Hacktool"
        family = "Equation"
        hacker = "None"
        author = "Florian Roth-copy"
        refer = "e62f9433faa7b33c7856e8b30b69b698,ea147f8bf6e4fc490b8a92478ea247e4,63138b529e830a57197c1caf9978d582"
        comment = "APT Equation Grou-https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
        date = "2018-09-03"
        description = "Equation Group hack tool set ETBL_ETRE_SMBTOUCH_17 "
	strings:
		$x1 = "ERROR: Connection terminated by Target (TCP Ack/Fin)" fullword ascii
		$s2 = "Target did not respond within specified amount of time" fullword ascii
	condition:
		( uint16(0) == 0x5a4d and filesize < 300KB and 1 of them )
}	