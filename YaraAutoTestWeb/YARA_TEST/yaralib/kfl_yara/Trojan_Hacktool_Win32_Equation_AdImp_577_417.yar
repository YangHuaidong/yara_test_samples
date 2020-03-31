rule Trojan_Hacktool_Win32_Equation_AdImp_577_417
{
    meta:
        judge = "black"
        threatname = "Trojan[Hacktool]/Win32.Equation.AdImp"
        threattype = "Hacktool"
        family = "Equation"
        hacker = "None"
        author = "Florian Roth-copy"
        refer = "4f2eab2ff0a9d4bad505cf5409e2a9db"
        comment = "APT Equation Grou-https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
        date = "2018-08-13"
        description = "Equation Group hack tool set AdUser_Implant "
	strings:
		$s1 = ".?AVFeFinallyFailure@@" fullword ascii
		$s2 = "(&(objectCategory=person)(objectClass=user)(cn=" fullword wide
	condition:
		( uint16(0) == 0x5a4d and filesize < 40KB and all of them )
}