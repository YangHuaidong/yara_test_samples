rule Trojan_RAT_Win32_Srvcmd_A_1023
{
	meta:
		judge = "black"
		threatname = "Trojan[RAT]/Win32.Srvcmd.A"
		threattype = "RAT"
		family = "Srvcmd"
		hacker = "None"
		refer = "8d95ba5a969e125ae53c9568173c5cd0"
		comment = "None"
		description = "Disclosed hacktool set (old stuff) - file 2323.exe"
		author = "Florian Roth -lz"
		date = "23.11.14"

	strings:
		$s0 = "port - Port to listen on, defaults to 2323" fullword ascii
		$s1 = "Usage: srvcmd.exe [/h] [port]" fullword ascii
		$s3 = "Failed to execute shell" fullword ascii
		$s5 = "/h   - Hide Window" fullword ascii
		$s7 = "Accepted connection from client at %s" fullword ascii
		$s9 = "Error %d: %s" fullword ascii
	condition:
		all of them
}
