rule Trojan_Hacktool_Win32_Equation_Gen4_527_481
{
    meta:
        judge = "black"
        threatname = "Trojan[Hacktool]/Win32.Equation.Gen4"
        threattype = "Hacktool"
        family = "Equation"
        hacker = "None"
        author = "Florian Roth-copy"
        refer = "e730225caa4e1fc3f75fee247b5f54e5,91ab4b74e86e7db850d7c127eeb5d473,4b5c89998a4f48c11f4a2f0591ab2293,59268a3cbe5f2ab0b26d4de239dff68d,1ec381aa04945298ae85bed76b2194af,12dea3524d5c7937102075c781a3ef85,9f285065c8315da2de01a48e8ca7e7be,4f6a975ddd6ed3903b8129441240b46f,9d6f88030fd7775129d947ad1dd9c689,b012614bf00aecfbee2a7707e21c2841,3a4223a09a928606723fd36186179934,866612476e5707c3c4d34d6527f1495a,958cbaaf1e7f89501d442ab4bf596e67,601fb299e706301b0b0a1b3d6ac1bfa5"
        comment = "APT Equation Grou-https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
        date = "2018-07-30"
        description = "Equation Group hack tool set Gen4 "
	strings:
		$x1 = "[+] \"TargetPort\"      %hu" fullword ascii
		$x2 = "---<<<  Complete  >>>---" fullword ascii
		$x3 = "[+] \"NetworkTimeout\"  %hu" fullword ascii
		$op1 = { 46 83 c4 0c 83 fe 0c 0f 8c 5e ff ff ff b8 }
	condition:
		( uint16(0) == 0x5a4d and filesize < 150KB and ( 1 of ($x*) or 2 of them ) )
}