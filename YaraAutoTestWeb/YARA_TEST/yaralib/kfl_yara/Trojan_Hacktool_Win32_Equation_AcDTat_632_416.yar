rule Trojan_Hacktool_Win32_Equation_AcDTat_632_416
{
    meta:
        judge = "black"
        threatname = "Trojan[Hacktool]/Win32.Equation.AcDTat"
        threattype = "Hacktool"
        family = "Equation"
        hacker = "None"
        author = "Florian Roth-copy"
        refer = "dc185715af55900c80c0c1d8ea300f56"
        comment = "APT Equation Grou-https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
        date = "2018-08-27"
        description = "Equation Group hack tool set ActiveDirectory_Target "
	strings:
		$s1 = "(&(objectCategory=person)(objectClass=user)(cn=" fullword wide
		$s2 = "(&(objectClass=user)(objectCategory=person)" fullword wide
	condition:
		( uint16(0) == 0x5a4d and filesize < 200KB and all of them )
}	