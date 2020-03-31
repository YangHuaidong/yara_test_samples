import "pe"
rule Trojan_Backdoor_Win32_Tiggre_a_418_225
{
	meta:
		 judge = "black"
		 threatname = "Trojan[Backdoor]/Win32.Tiggre.a"
		 threattype = "Backdoor"
		 family = "Tiggre"
		 hacker = "apt15"
		 comment = "https://www.nccgroup.trust/us/about-us/newsroom-and-events/blog/2018/march/apt15-is-alive-and-strong-an-analysis-of-royalcli-and-royaldns/"
		 date = "2018-05-22"
		 author = "Ahmed Zaki--DC"
		 description = "malware_apt15_royaldll_2 DNS backdoor used by APT15" 
		 refer = "941a4fc3d2a3289017cf9c56584d1168"
	strings:
		    $= "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Svchost" wide ascii 
		    $= "netsvcs" wide ascii fullword
		    $= "%SystemRoot%\\System32\\svchost.exe -k netsvcs" wide ascii fullword
		    $= "SYSTEM\\CurrentControlSet\\Services\\" wide ascii
		    $= "myWObject" wide ascii 
	condition:
		uint16(0) == 0x5A4D and all of them
		and pe.exports("ServiceMain")
		and filesize > 50KB and filesize < 600KB
}