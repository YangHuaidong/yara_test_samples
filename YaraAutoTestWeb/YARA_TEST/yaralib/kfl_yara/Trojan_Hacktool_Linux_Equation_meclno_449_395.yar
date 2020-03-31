rule Trojan_Hacktool_Linux_Equation_meclno_449_395
{
    meta:
        judge = "black"
        threatname = "Trojan[Hacktool]/Linux.Equation.meclno"
        threattype = "Hacktool"
        family = "Equation"
        hacker = "None"
        author = "Florian Roth-copy"
        refer = "f8512961b200c0f4759ccf7831f94ab3"
        comment = "APT Equation Grou-https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
        date = "2018-07-24"
        description = "Equation Group hack tool set morerats_client_noprep"
	strings:
		$x1 = "storestr = 'echo -n \"%s\" | Store --nullterminate --file=\"%s\" --set=\"%s\"' % (nopenargs, outfile, VAR_NAME)" fullword ascii
		$x2 = "The NOPEN-args provided are injected into infile if it is a valid" fullword ascii
		$x3 = " -i                do not autokill after 5 hours" fullword ascii
	condition:
		( filesize < 9KB and 1 of them )
}