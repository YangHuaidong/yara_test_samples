rule Trojan_Backdoor_Win32_RockRat_jowj_384_197
{
    meta:
        judge = "black"
        threatname = "Trojan[Backdoor]/Win32.RockRat.jowj"
        threattype = "backdoor"
        family = "RockRat"
        hacker = "None"
        author = "CarbonBlack Threat Research-copy"
        refer = "5c6c1ed910e7c9740a0289a6d278908a"
        comment = "https://www.carbonblack.com/2018/02/27/threat-analysis-rokrat-malware/"
        date = "2018-06-20"
        description = "Designed to catch loader observed used with ROKRAT malware"
    strings:
		$s1 = "api.box.com/oauth2/token" wide
		$s2 = "upload.box.com/api/2.0/files/content" wide
		$s3 = "api.pcloud.com/uploadfile?path=%s&filename=%s&nopartial=1" wide
		$s4 = "cloud-api.yandex.net/v1/disk/resources/download?path=%s" wide
		$s5 = "SbieDll.dll"
		$s6 = "dbghelp.dll"
		$s7 = "api_log.dll"
		$s8 = "dir_watch.dll"
		$s9 = "def_%s.jpg" wide
		$s10 = "pho_%s_%d.jpg" wide
		$s11 = "login=%s&password=%s&login_submit=Authorizing" wide
		$s12 = "gdiplus.dll"
		$s13 = "Set-Cookie:\\b*{.+?}\\n" wide
		$s14 = "charset={[A-Za-z0-9\\-_]+}" wide
	condition:
		12 of ($s*)
}