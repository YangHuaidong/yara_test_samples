rule Trojan_Hacktool_Win32_Equation_EREKv13_697_461
{
    meta:
        judge = "black"
        threatname = "Trojan[Hacktool]/Win32.Equation.EREKv13"
        threattype = "Hacktool"
        family = "Equation"
        hacker = "None"
        author = "Florian Roth-copy"
        refer = "c716ad40c0aaef9b936595ba1e9365cd,22b6f3ae1a645e7bdf2b20682a1cb55e"
        comment = "APT Equation Grou-https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
        date = "2018-09-03"
        description = "Equation Group hack tool set ELV_ESKE_13 "
	strings:
		$x1 = "Skip call to PackageRideArea().  Payload has already been packaged. Options -x and -q ignored." fullword ascii
		$s2 = "ERROR: pGvars->pIntRideAreaImplantPayload is NULL" fullword ascii
	condition:
		( uint16(0) == 0x5a4d and filesize < 600KB and 1 of them )
}