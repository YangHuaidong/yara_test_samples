rule Trojan_Backdoor_Linux_ASP_hsxa_1034
{
    meta:
        judge = "black"
        threatname = "Trojan[Backdoor]/Linux.ASP.hsxa"
        threattype = "Backdoor"
        family = "ASP"
        hacker = "None"
        author = "copy"
        refer = "d0e05f9c9b8e0b3fa11f57d9ab800380"
        comment = "None"
        date = "2018-12-13"
        description = "Web Shell - file hsxa.jsp"
		score = 70
	strings:
		$s0 = "<%@ page language=\"java\" pageEncoding=\"gbk\"%><jsp:directive.page import=\"ja"
	condition:
		all of them
}