rule Trojan_Downloader_Win32_PcClient_gic_815
{
	meta:
	    judge = "black"
	    threatname = "Trojan[Downloader]/Win32.PcClient.gic"
	    threattype = "Downloader"
	    family = "PcClient"
	    hacker = "None"
	    refer = "5e7e9cbec1b7cf3d00b8a6886c59c470"
	    comment = "None"
		description = "Chinese Hacktool Set - file PcShare.exe"
		author = "Florian Roth -lz"
		date = "2015-06-13"

	strings:
		$s0 = "title=%s%s-%s;id=%s;hwnd=%d;mainhwnd=%d;mainprocess=%d;cmd=%d;" fullword wide
		$s1 = "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0; .NET CLR 1.1.4322)" fullword wide
		$s2 = "http://www.pcshares.cn/pcshare200/lostpass.asp" fullword wide
		$s5 = "port=%s;name=%s;pass=%s;" fullword wide
		$s16 = "%s\\ini\\*.dat" fullword wide
		$s17 = "pcinit.exe" fullword wide
		$s18 = "http://www.pcshare.cn" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 6000KB and 3 of them
}