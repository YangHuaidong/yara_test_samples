rule Trojan_Hacktool_Win32_Laudanum_wbshelaspx_874_535
{
    meta:
        judge = "black"
        threatname = "Trojan[Hacktool]/Win32.Laudanum.wbshelaspx"
        threattype = "Hacktool"
        family = "Laudanum"
        hacker = "None"
        author = "copy"
        refer = "e22a112e72086075023b40ddfacd2d68"
        comment = "http://laudanum.inguardians.com/"
        date = "2018-08-20"
        description = "Laudanum Injector Tools - file shell.aspx"
	strings:
		$s1 = "remoteIp = HttpContext.Current.Request.Headers[\"X-Forwarded-For\"].Split(new" ascii /* PEStudio Blacklist: strings */
		$s2 = "remoteIp = Request.UserHostAddress;" fullword ascii /* PEStudio Blacklist: strings */
		$s3 = "<form method=\"post\" name=\"shell\">" fullword ascii /* PEStudio Blacklist: strings */
		$s4 = "<body onload=\"document.shell.c.focus()\">" fullword ascii /* PEStudio Blacklist: strings */
	condition:
		filesize < 20KB and all of them
}