rule Trojan_Downloader_Win32_Small_XX_816  
{
	meta:
	    judge = "black"
	    threatname = "Trojan[Downloader]/Win32.Small.XX"
	    threattype = "Downloader"
	    family = "Small"
	    hacker = "None"
	    refer = "9e1ab25a937f39ed8b031cd8cfbc4c07,cafc31d39c1e4721af3ba519759884b9,8e635b9a1e5aa5ef84bfa619bd2a1f92"
	    comment = "None"
		description = "Tiny tool with suspicious function imports. (Rule based on WinEggDrop Scanner samples)"
		author = "Florian Roth -lz"
		date = "2014-08-10"
		
		
	strings:
		$magic	= { 4d 5a }

		$s0 = "KERNEL32.DLL" fullword ascii
		$s1 = "CRTDLL.DLL" fullword ascii
		$s3 = "LoadLibraryA" fullword ascii
		$s4 = "GetProcAddress" fullword ascii

		$y1 = "WININET.DLL" fullword ascii
		$y2 = "atoi" fullword ascii

		$x1 = "ADVAPI32.DLL" fullword ascii
		$x2 = "USER32.DLL" fullword ascii
		$x3 = "wsock32.dll" fullword ascii
		$x4 = "FreeSid" fullword ascii
		$x5 = "atoi" fullword ascii

		$z1 = "ADVAPI32.DLL" fullword ascii
		$z2 = "USER32.DLL" fullword ascii
		$z3 = "FreeSid" fullword ascii
		$z4 = "ToAscii" fullword ascii

	condition:
		( $magic at 0 ) and all of ($s*) and ( all of ($y*) or all of ($x*) or all of ($z*) ) and filesize < 15KB
}