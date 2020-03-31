rule Trojan_Backdoor_Linux_ASP_EFSO2_1033
{
    meta:
        judge = "black"
        threatname = "Trojan[Backdoor]/Linux.ASP.EFSO2"
        threattype = "Backdoor"
        family = "ASP"
        hacker = "None"
        author = "copy"
        refer = "a341270f9ebd01320a7490c12cb2e64c"
        comment = "None"
        date = "2018-12-13"
        description = "Web Shell - file EFSO_2.asp"
		score = 70
	strings:
		$s0 = "%8@#@&P~,P,PP,MV~4BP^~,NS~m~PXc3,_PWbSPU W~~[u3Fffs~/%@#@&~~,PP~~,M!PmS,4S,mBPNB"
	condition:
		all of them
}