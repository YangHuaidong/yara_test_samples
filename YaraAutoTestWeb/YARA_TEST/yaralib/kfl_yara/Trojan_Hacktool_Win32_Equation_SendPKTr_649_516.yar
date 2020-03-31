rule Trojan_Hacktool_Win32_Equation_SendPKTr_649_516
{
    meta:
        judge = "black"
        threatname = "Trojan[Hacktool]/Win32.Equation.SendPKTr"
        threattype = "Hacktool"
        family = "Equation"
        hacker = "None"
        author = "Florian Roth-copy"
        refer = "83ed8b6065add87a32104101eb30bd31"
        comment = "APT Equation Grou-https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
        date = "2018-08-20"
        description = "Equation Group hack tool set SendPKTrigger "
	strings:
		$x1 = "----====**** PORT KNOCK TRIGGER BEGIN ****====----" fullword wide
	condition:
		( uint16(0) == 0x5a4d and filesize < 300KB and all of them )
}