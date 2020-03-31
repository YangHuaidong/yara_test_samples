rule Trojan_Hacktool_Win32_Equation_Nadpto2_528_490
{
    meta:
        judge = "black"
        threatname = "Trojan[Hacktool]/Win32.Equation.Nadpto2"
        threattype = "Hacktool"
        family = "Equation"
        hacker = "None"
        author = "Florian Roth-copy"
        refer = "23727130cf7e7476cea1e493350e68a8"
        comment = "APT Equation Grou-https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
        date = "2018-07-30"
        description = "Equation Group hack tool set Namedpipetouch_2_0_0 "
	strings:
		$s1 = "[*] Summary: %d pipes found" fullword ascii
		$s3 = "[+] Testing %d pipes" fullword ascii
		$s6 = "[-] Error on SMB startup, aborting" fullword ascii
		$s12 = "92a761c29b946aa458876ff78375e0e28bc8acb0" fullword ascii
		$op1 = { 68 10 10 40 00 56 e8 e1 }
	condition:
		( uint16(0) == 0x5a4d and filesize < 40KB and 2 of them )
}