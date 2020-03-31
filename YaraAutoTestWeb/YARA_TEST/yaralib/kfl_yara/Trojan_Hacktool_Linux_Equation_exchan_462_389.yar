rule Trojan_Hacktool_Linux_Equation_exchan_462_389
{
    meta:
        judge = "black"
        threatname = "Trojan[Hacktool]/Linux.Equation.exchan"
        threattype = "Hacktool"
        family = "Equation"
        hacker = "None"
        author = "Florian Roth-copy"
        refer = "b19559ea955e9f445da1d5494583429c,cfe87f285903b6a3e36185584485e717,14537f7459c891d34106c7526a88c906,47fc9f11d8130e29fca9cdd024d6d25c"
        comment = "APT Equation Grou-https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
        date = "2018-07-30"
        description = "Equation Group hack tool set EquationGroup_linux_exactchange"
	strings:
		$x1 = "[+] looking for vulnerable socket" fullword ascii
		$x2 = "can't use 32-bit exploit on 64-bit target" fullword ascii
		$x3 = "[+] %s socket ready, exploiting..." fullword ascii
		$x4 = "[!] nothing looks vulnerable, trying everything" fullword ascii
	condition:
		( uint16(0) == 0x457f and filesize < 2000KB and 1 of them )
}