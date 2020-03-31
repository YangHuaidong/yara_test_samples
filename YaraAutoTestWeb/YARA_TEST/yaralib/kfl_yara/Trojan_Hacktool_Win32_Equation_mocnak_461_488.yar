rule Trojan_Hacktool_Win32_Equation_mocnak_461_488
{
    meta:
        judge = "black"
        threatname = "Trojan[Hacktool]/Win32.Equation.mocnak"
        threattype = "Hacktool"
        family = "Equation"
        hacker = "None"
        author = "Florian Roth-copy"
        refer = "4dc387739200006fb6ba4bd03813c305"
        comment = "APT Equation Grou-https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
        date = "2018-07-24"
        description = "Equation Group hack tool set morerats_client_addkey "
	strings:
		$x1 = "print '  -s storebin  use storebin as the Store executable\\n'" fullword ascii
		$x2 = "os.system('%s --file=\"%s\" --wipe > /dev/null' % (storebin, b))" fullword ascii
		$x3 = "print '  -k keyfile   the key text file to inject'" fullword ascii
	condition:
		( filesize < 20KB and 1 of them )
}