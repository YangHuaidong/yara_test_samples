rule Trojan_Backdoor_Win32_Danti_d_18_51
{

    meta:
        judge = "black"
				threatname = "Trojan[Backdoor]/Win32.Danti.d"
				threattype = "Backdoor"
				family = "Danti"
				hacker = "None"
				comment = "http://goo.gl/m2CXWR,TidePool_Malware_APTKe3chang"
				date = "2016-05-24"
				author = "Florian Roth-DC"
				description = "Detects TidePool malware mentioned in Ke3chang report by Palo Alto Networks" 
				refer = "be0cc8411c066eac246097045b73c282"
	      hash2 = "bae673964e9bc2a45ebcc667895104ef"
	      hash3 = "9469dd12136b6514d82c3b01d6082f59"
	      hash4 = "8ad9cb6b948bcf7f9211887e0cf6f02a"
	      hash5 = "be0cc8411c066eac246097045b73c282"
    strings:
        $x1 = "Content-Disposition: form-data; name=\"m1.jpg\"" fullword ascii
        $x2 = "C:\\PROGRA~2\\IEHelper\\mshtml.dll" fullword wide
        $x3 = "C:\\DOCUME~1\\ALLUSE~1\\IEHelper\\mshtml.dll" fullword wide
        $x4 = "IEComDll.dat" fullword ascii
        $s1 = "Content-Type: multipart/form-data; boundary=----=_Part_%x" fullword wide
        $s2 = "C:\\Windows\\System32\\rundll32.exe" fullword wide
        $s3 = "network.proxy.socks_port\", " fullword ascii
    
    condition:
        ( uint16(0) == 0x5a4d and filesize < 200KB and ( 1 of ($x*) ) ) or ( 4 of them )
}
