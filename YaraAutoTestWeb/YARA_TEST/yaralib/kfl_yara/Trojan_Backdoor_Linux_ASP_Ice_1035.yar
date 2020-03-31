rule Trojan_Backdoor_Linux_ASP_Ice_1035
{
    meta:
        judge = "black"
        threatname = "Trojan[Backdoor]/Linux.ASP.Ice"
        threattype = "Backdoor"
        family = "ASP"
        hacker = "None"
        author = "copy"
        refer = "d141e011a92f48da72728c35f1934a2b"
        comment = "None"
        date = "2018-12-13"
        description = "Web Shell - file ice.asp"
		score = 70
	strings:
		$s0 = "D,'PrjknD,J~[,EdnMP[,-4;DS6@#@&VKobx2ldd,'~JhC"
	condition:
		all of them
}