rule Trojan_Downloader_Linux_EquationDrug_qwe_386_341
{
    meta:
        judge = "black"
        threatname = "Trojan[Downloader]/Linux.EquationDrug.qwe"
        threattype = "Downloader"
        family = "EquationDrug"
        hacker = "None"
        author = "Florian Roth-copy"
        refer = "6aa81f1b02a0777507fb6035e75fc45d"
        comment = "APT Equation Grou-https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
        date = "2018-07-02"
        description = "Equation Group hack tool leaked by ShadowBrokers- file eh.1.1.0.0"
	strings:
		$x1 = "usage: %s -e -v -i target IP [-c Cert File] [-k Key File]" fullword ascii
		$x2 = "TYPE=licxfer&ftp=%s&source=/var/home/ftp/pub&version=NA&licfile=" ascii
		$x3 = "[-l Log File] [-m save MAC time file(s)] [-p Server Port]" fullword ascii
	condition:
		( uint16(0) == 0x457f and filesize < 100KB and 1 of them )
}