rule Trojan_Downloader_Win32_HintSoft_passthru_20170412094602_1047_353 
{
	meta:
		judge = "black"
		threatname = "Trojan[Downloader]/Win32.HintSoft.passthru"
		threattype = "Downloader"
		family = "HintSoft"
		hacker = "None"
		refer = "15a0471032be7647778618790ebbdc08"
		description = "Passthru.sys with description Hint Service is a driver file from company HintSoft Corporation belonging to product Microsoft? Windows? Operating System."
		comment = "None"
		author = "djw"
		date = "2017-03-29"
	strings:
		$s0 = "passthru" nocase wide ascii
		$s1 = "snetcfg -v -l C:\\netsf.inf"  nocase wide ascii
		$s2 = "myfile.txt"  nocase wide ascii
		$s3 = ".PEDATA"  nocase wide ascii
		$s4 = "%%CMDCMDLINE%%" nocase wide ascii
		$s5 = "NetCfgWriteLock"  nocase wide ascii

	condition:
		4 of them
}
