rule Trojan_Hacktool_Win32_Equation_PCLevG_643_498
{
    meta:
        judge = "black"
        threatname = "Trojan[Hacktool]/Win32.Equation.PCLevG"
        threattype = "Hacktool"
        family = "Equation"
        hacker = "None"
        author = "Florian Roth-copy"
        refer = "fb97f8b8535de1e2cb7eac6177226cca,b2981b5e2c63e8278c909c70077c65d1,4c42669a7620ad3494d1fd409dc4f61e,d093db7f175af28d6e7492918d38234f,2ae29b004930df253457cec48e2d3116,b506eb0cf30b0b0f9aef5904cad01085,276e6c023e0e6d8bbeda8db2996b3765,90b42c32aa3442106c0eb49a7e9527d6,45cb795ea7f4d89c422f6e16ac777a89,83449d72701c253422cdee18e30ca305"
        comment = "APT Equation Grou-https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
        date = "2018-08-27"
        description = "Equation Group hack tool set PC_Level_Generic "
	strings:
		$s1 = "wshtcpip.WSHGetSocketInformation" fullword ascii
		$s2 = "\\\\.\\%hs" fullword ascii
		$s3 = ".?AVResultIp@Mini_Mcl_Cmd_NetConnections@@" fullword ascii
		$s4 = "Corporation. All rights reserved." fullword wide
		$s5 = { 49 83 3c 24 00 75 02 eb 5d 49 8b 34 24 0f b7 46 }
		$op1 = { 44 24 57 6f c6 44 24 58 6e c6 44 24 59 }
		$op2 = { c6 44 24 56 64 88 5c 24 57 }
		$op3 = { 44 24 6d 4c c6 44 24 6e 6f c6 44 24 6f }
	condition:
		uint16(0) == 0x5a4d and filesize < 400KB and ( 2 of ($s*) or all of ($op*) )
}	