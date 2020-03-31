rule Trojan_HACKTOOL_Win32_iamalt_v1_774_532
{
	meta:

		judge = "black"
	    threatname = "Trojan[HACKTOOL]/Win32.iamalt.v1"
	    threattype = "HACKTOOL"
	    family = "iamalt"
	    hacker = "None"  
	    refer = "7877e129f393d479eba841cd22e40f56"
	    comment = "None"
		description = "Auto-generated rule - file iam-alt.exe"
		author = "Florian Roth -lz"
		date = "2015-07-10"
		
	strings:
		$s0 = "<cmd>. Create a new logon session and run a command with the specified credentials (e.g.: -r cmd.exe)" fullword ascii /* PEStudio Blacklist: strings */ /* score: '59.00' */
		$s1 = "IAM-ALT v1.1 - by Hernan Ochoa (hochoa@coresecurity.com, hernan@gmail.com) - (c) 2007-2008 Core Security Technologies" fullword ascii /* PEStudio Blacklist: strings */ /* score: '43.00' */
		$s2 = "This tool allows you to change the NTLM credentials of the current logon session" fullword ascii /* PEStudio Blacklist: strings */ /* score: '31.00' */
		$s3 = "username:domainname:lmhash:nthash" fullword ascii /* PEStudio Blacklist: strings */ /* score: '15.00' */
		$s4 = "Error in cmdline!. Bye!." fullword ascii /* score: '12.00' */
		$s5 = "Error: Cannot open LSASS.EXE!." fullword ascii /* score: '12.00' */
		$s6 = "nthash is too long!." fullword ascii /* score: '8.00' */
		$s7 = "LSASS HANDLE: %x" fullword ascii /* score: '5.00' */
	condition:
		uint16(0) == 0x5a4d and filesize < 240KB and 2 of them
}