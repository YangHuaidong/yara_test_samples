rule Trojan_Downloader_Linux_Shell_qwe_387_342
{
    meta:
        judge = "black"
        threatname = "Trojan[Downloader]/Linux.Shell.qwe"
        threattype = "Downloader"
        family = "Shell"
        hacker = "None"
        author = "Florian Roth-copy"
        refer = "a273b31c7ae40ee817485eb01d81ff16"
        comment = "APT Equation Grou-https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
        date = "2018-07-02"
        description = "Equation Group hack tool leaked by ShadowBrokers- file ys.ratload.sh"
	strings:
		$x1 = "echo \"example: ${0} -l 192.168.1.1 -p 22222 -x 9999\"" fullword ascii
		$x2 = "-x [ port to start mini X server on DEFAULT = 12121 ]\"" fullword ascii
		$x3 = "CALLBACK_PORT=32177" fullword ascii
	condition:
		( uint16(0) == 0x2123 and filesize < 3KB and 1 of them )
}