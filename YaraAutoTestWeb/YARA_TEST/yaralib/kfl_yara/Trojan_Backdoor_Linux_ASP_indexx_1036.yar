rule Trojan_Backdoor_Linux_ASP_indexx_1036
{
    meta:
        judge = "black"
        threatname = "Trojan[Backdoor]/Linux.ASP.indexx"
        threattype = "Backdoor"
        family = "ASP"
        hacker = "None"
        author = "copy"
        refer = "b7f46693648f534c2ca78e3f21685707"
        comment = "None"
        date = "2018-12-13"
        description = "Web Shell - file file indexx.asp"
		score = 70
	strings:
		$s3 = "Const strs_toTransform=\"command|Radmin|NTAuThenabled|FilterIp|IISSample|PageCou"
	condition:
		all of them
}