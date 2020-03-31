rule Trojan_Hacktool_Win32_Equation_Ericto_476_462
{
    meta:
        judge = "black"
        threatname = "Trojan[Hacktool]/Win32.Equation.Ericto"
        threattype = "Hacktool"
        family = "Equation"
        hacker = "None"
        author = "Florian Roth-copy"
        refer = "9f60e690feabdaa2611373e93aa50450"
        comment = "APT Equation Grou-https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
        date = "2018-07-30"
        description = "Equation Group hack tool set Ericto "
	strings:
		$x1 = "[-] Unable to connect to broswer named pipe, target is NOT vulnerable" fullword ascii
		$x2 = "[-] Unable to bind to Dimsvc RPC syntax, target is NOT vulnerable" fullword ascii
		$x3 = "[+] Bound to Dimsvc, target IS vulnerable" fullword ascii
	condition:
		( uint16(0) == 0x5a4d and filesize < 30KB and 1 of them )
}