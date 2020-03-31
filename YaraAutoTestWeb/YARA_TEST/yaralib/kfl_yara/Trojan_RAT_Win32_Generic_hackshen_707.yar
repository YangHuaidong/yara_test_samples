rule Trojan_RAT_Win32_Generic_hackshen_707
{
    meta:
	        judge = "black"
			threatname = "Trojan[rat]/Win32.Generic.hackshen"
			threattype = "RAT"
			family = "Generic"
			hacker = "none"
			refer = "14d996266926bf59ae3d99ff79d3c717"
			comment = "none"
			author = "xc"
			date = "2017-07-26"
			description = "None"
	strings:
			$s0 = "C:\\Program Files\\svchost.exe"
			$s1 = "\\\\%s\\admin$\\hackshen.exe"
			$s2 = "C:\\Yuemingl.txt"
    condition:
            all of them
}