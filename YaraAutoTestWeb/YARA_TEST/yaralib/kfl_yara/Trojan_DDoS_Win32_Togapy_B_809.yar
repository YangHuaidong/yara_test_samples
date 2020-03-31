rule Trojan_DDoS_Win32_Togapy_B_809
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Win32.Togapy.bfddos"
		threattype = "DDoS"
		family = "Togapy"
		hacker = "None"
		refer = "90323af2e98f28d16a3c5c6ea481e997,7650bb1ee33640b89f5d772a9eb48ada,a1bfb21a297e3bbf6b1d535d67a080fc,8cec4dab1206ed1fd3865964c9719269,82a5ce3d15c1aad52a035cda87a8d64c"
		author = "LGZ"
		comment = "None"
		date = "2017-08-20"
		description = "None"

	strings:
		$s0 = "Win %s SP%d"
		$s1 = "\\Program Files\\Internet Explorer\\"
		$s2 = "HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0"
		$s3 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run"
		$s4 = "IEBroser"
		$s5 = "%s%d.exe"
		$s6 = "SYSTEM\\CurrentControlSet\\Services\\%s"
		$s7 = "iexplore.exe"
	condition:
		//3 of them 
		$s0 and $s1 and $s2 and (($s3 and $s4 and $s5) or ($s3 and $s5 and $s7) or ($s6 and $s7))
}