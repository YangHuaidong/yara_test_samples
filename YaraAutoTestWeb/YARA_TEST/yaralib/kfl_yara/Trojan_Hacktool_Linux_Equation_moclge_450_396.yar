rule Trojan_Hacktool_Linux_Equation_moclge_450_396
{
    meta:
        judge = "black"
        threatname = "Trojan[Hacktool]/Linux.Equation.moclge"
        threattype = "Hacktool"
        family = "Equation"
        hacker = "None"
        author = "Florian Roth-copy"
        refer = "ec1c3d8c64ece1f3214a185b06e9c58e"
        comment = "APT Equation Grou-https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
        date = "2018-07-24"
        description = "Equation Group hack tool set morerats_client_genkey"
	strings:
		$x1 = "rsakey_txt = lo_execute('openssl genrsa 2048 2> /dev/null | openssl rsa -text 2> /dev/null')" fullword ascii
		$x2 = "client_auth = binascii.hexlify(lo_execute('openssl rand 16'))" fullword ascii
	condition:
		( filesize < 3KB and all of them )
}