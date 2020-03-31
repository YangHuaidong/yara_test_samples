rule Trojan_HACKTOOL_Win32_iam_v1_773_527
{
	meta:
	
	    judge = "black"
	    threatname = "Trojan[HACKTOOL]/Win32.iam.v1"
	    threattype = "HACKTOOL"
	    family = "iam"
	    hacker = "None"
	    refer = "fc24babef9f727b4d6389bda8c5a6d6a"
	    comment = "None"
		description = "Auto-generated rule - file iam.exe"
		author = "Florian Roth -lz"
		date = "2015-07-10"

	strings:
		$s1 = "<cmd>. Create a new logon session and run a command with the specified credentials (e.g.: -r cmd.exe)" fullword ascii /* PEStudio Blacklist: strings */ /* score: '59.00' */
		$s2 = "iam.exe -h administrator:mydomain:"  ascii /* PEStudio Blacklist: strings */ /* score: '40.00' */
		$s3 = "An error was encountered when trying to change the current logon credentials!." fullword ascii /* PEStudio Blacklist: strings */ /* score: '33.00' */
		$s4 = "optional parameter. If iam.exe crashes or doesn't work when run in your system, use this parameter." fullword ascii /* PEStudio Blacklist: strings */ /* score: '30.00' */
		$s5 = "IAM.EXE will try to locate some memory locations instead of using hard-coded values." fullword ascii /* score: '26.00' */
		$s6 = "Error in cmdline!. Bye!." fullword ascii /* score: '12.00' */
		$s7 = "Checking LSASRV.DLL...." fullword ascii /* score: '12.00' */
	condition:
		uint16(0) == 0x5a4d and filesize < 300KB and all of them
}