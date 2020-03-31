rule Trojan_RAT_Win32_Toga_ass_723
{
    meta:
	        judge = "black"
			threatname = "Trojan[RAT]/Win32.Toga.ass"
			threattype = "RAT"
			family = "Toga"
			hacker = "none"
			refer = "9d9635f8d3adcf217435875b1496829a"
			comment = "none"
			author = "xc"
			date = "2017-07-27"
			description = "None"
	strings:
			$s0 = "qiannian"
			$s1 = "PAbusi.exe*773822*busi.bat"
			$s2 = "ass.exe*176128*mima.bat"
			$s3 = "minist9or ...]"
    condition:
            all of them
}