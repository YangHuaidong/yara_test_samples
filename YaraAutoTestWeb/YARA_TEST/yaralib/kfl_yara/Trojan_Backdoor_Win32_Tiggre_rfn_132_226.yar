rule Trojan_Backdoor_Win32_Tiggre_rfn_132_226
{
	meta:
		judge = "black"
		threatname = "Trojan[Backdoor]/Win32.Tiggre.!rfn"
		threattype = "Backdoor"
		family = "Tiggre"
		hacker = "apt15"
		comment = "https://www.nccgroup.trust/us/about-us/newsroom-and-events/blog/2018/march/apt15-is-alive-and-strong-an-analysis-of-royalcli-and-royaldns/"
		date = "2018-05-22"
		author = "David Cannings--DC"
		description = "malware_apt15_royaldll DLL implant, originally rights.dll and runs as a service" 
		refer = "941a4fc3d2a3289017cf9c56584d1168"
		sha256 = "bc937f6e958b339f6925023bc2af375d669084e9551fd3753e501ef26e36b39d"
	
	
	strings:
	    /*
	      56                push    esi
	      B8 A7 C6 67 4E    mov     eax, 4E67C6A7h
	      83 C1 02          add     ecx, 2
	      BA 04 00 00 00    mov     edx, 4
	      57                push    edi
	      90                nop
	    */
	    // JSHash implementation (Justin Sobel's hash algorithm)
		$opcodes_jshash = { B8 A7 C6 67 4E 83 C1 02 BA 04 00 00 00 57 90 }

	    /*
	      0F B6 1C 03       movzx   ebx, byte ptr [ebx+eax]
	      8B 55 08          mov     edx, [ebp+arg_0]
	      30 1C 17          xor     [edi+edx], bl
	      47                inc     edi
	      3B 7D 0C          cmp     edi, [ebp+arg_4]
	      72 A4             jb      short loc_10003F31
	    */
	    // Encode loop, used to "encrypt" data before DNS request
		$opcodes_encode = { 0F B6 1C 03 8B 55 08 30 1C 17 47 3B 7D 0C }

	    /*
	      68 88 13 00 00    push    5000 # Also seen 3000, included below
	      FF D6             call    esi ; Sleep
	      4F                dec     edi
	      75 F6             jnz     short loc_10001554
	    */
	    // Sleep loop
		$opcodes_sleep_loop = { 68 (88|B8) (13|0B) 00 00 FF D6 4F 75 F6 }

	    // Generic strings
	    $ = "Nwsapagent" fullword
	    $ = "\"%s\">>\"%s\"\\s.txt"
	    $ = "myWObject" fullword
	    $ = "del c:\\windows\\temp\\r.exe /f /q"
	    $ = "del c:\\windows\\temp\\r.ini /f /q"
	condition:
		3 of them
}
