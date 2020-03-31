rule Trojan_Hacktool_Win32_Equation_GAdmLSAIm_638_476
{
    meta:
        judge = "black"
        threatname = "Trojan[Hacktool]/Win32.Equation.GAdmLSAIm"
        threattype = "Hacktool"
        family = "Equation"
        hacker = "None"
        author = "Florian Roth-copy"
        refer = "c11142caa3013f852ccb698cc6008b51,199796e3f413074d5fdef7fe8334eccf"
        comment = "APT Equation Grou-https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
        date = "2018-08-20"
        description = "Equation Group hack tool set GetAdmin_LSADUMP_ModifyPrivilege_Implant "
	strings:
		$s1 = "\\system32\\win32k.sys" fullword wide
		$s2 = "hKeAddSystemServiceTable" fullword ascii
		$s3 = "hPsDereferencePrimaryToken" fullword ascii
		$s4 = "CcnFormSyncExFBC" fullword wide
		$s5 = "hPsDereferencePrimaryToken" fullword ascii
		$op1 = { 0c 2b ca 8a 04 11 3a 02 75 01 47 42 4e 75 f4 8b }
		$op2 = { 14 83 c1 05 80 39 85 75 0c 80 79 01 c0 75 06 80 }
		$op3 = { eb 3d 83 c0 06 33 f6 80 38 ff 75 2c 80 78 01 15 }
	condition:
		( uint16(0) == 0x5a4d and filesize < 80KB and ( 4 of ($s*) or all of ($op*) ) )
}