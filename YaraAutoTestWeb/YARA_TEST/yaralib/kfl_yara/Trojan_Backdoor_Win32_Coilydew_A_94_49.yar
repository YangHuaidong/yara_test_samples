rule Trojan_Backdoor_Win32_Coilydew_A_94_49
{
	meta:	
		judge = "black"
	  threatname = "Trojan[Backdoor]/Win32.Coilydew.A"
	  threattype = "Backdoor"
	  family = "Coilydew"
	  hacker = "None"
	  comment = "malware_apt15_royalcli_1__6df9b712ff56009810c4000a0ad47e41b7a6183b69416251e060b5c80cd05785 https://www.nccgroup.trust/us/about-us/newsroom-and-events/blog/2018/march/apt15-is-alive-and-strong-an-analysis-of-royalcli-and-royaldns/"
	  date = "2018-04-12"
	  author = "David Cannings--DC"
	  description = "Generic strings found in the Royal CLI tool" 
	  refer = "5e5c9e6e710f67f4886e4f4169d02b1d"
	  sha256 = "6df9b712ff56009810c4000a0ad47e41b7a6183b69416251e060b5c80cd05785"
		
	strings:
	    $ = "%s~clitemp%08x.tmp" fullword
	    $ = "qg.tmp" fullword
	    $ = "%s /c %s>%s" fullword
	    $ = "hkcmd.exe" fullword
	    $ = "%snewcmd.exe" fullword
	    $ = "%shkcmd.exe" fullword
	    $ = "%s~clitemp%08x.ini" fullword
	    $ = "myRObject" fullword
	    $ = "myWObject" fullword
	    $ = "10 %d %x\x0D\x0A"
	    $ = "4 %s  %d\x0D\x0A"
	    $ = "6 %s  %d\x0D\x0A"
	    $ = "1 %s  %d\x0D\x0A"
	    $ = "3 %s  %d\x0D\x0A"
	    $ = "5 %s  %d\x0D\x0A"
	    $ = "2 %s  %d 0 %d\x0D\x0A"
	    $ = "2 %s  %d 1 %d\x0D\x0A"
	    $ = "%s file not exist" fullword

	condition:
	    5 of them
}
