rule Trojan_Hacktool_Linux_Equation_exchang_463_388
{
    meta:
        judge = "black"
        threatname = "Trojan[Hacktool]/Linux.Equation.exchang"
        threattype = "Hacktool"
        family = "Equation"
        hacker = "None"
        author = "Florian Roth-copy"
        refer = "b19559ea955e9f445da1d5494583429c,cfe87f285903b6a3e36185584485e717"
        comment = "APT Equation Grou-https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
        date = "2018-07-30"
        description = "Equation Group hack tool set EquationGroup_linux_exactchange"
	strings:
		$x1 = "kernel has 4G/4G split, not exploitable" fullword ascii
		$x2 = "[+] kernel stack size is %d" fullword ascii
	condition:
		( uint16(0) == 0x457f and filesize < 1000KB and 1 of them )
}