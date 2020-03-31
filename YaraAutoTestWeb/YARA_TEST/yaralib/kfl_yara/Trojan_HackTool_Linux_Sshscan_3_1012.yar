rule Trojan_HackTool_Linux_Sshscan_3_1012 
{
	meta:
	    judge = "black"
	    threatname = "Trojan[HackTool]/Linux.Sshcan.3"
	    threattype = "HackTool"
	    family = "Sshcan"
	    hacker = "None"
	    refer = "ab106d75a3b87641937d5a8891abc8ce"
	    comment = "None"
		description = "Linux hack tools - file scanssh"
		author = "Florian Roth -lz"
		reference = "not set"
		date = "2015/01/19"

	strings:
		$s0 = "Connection closed by remote host" fullword ascii
		$s1 = "Writing packet : error on socket (or connection closed): %s" fullword ascii
		$s2 = "Remote connection closed by signal SIG%s %s" fullword ascii
		$s4 = "Reading private key %s failed (bad passphrase ?)" fullword ascii
		$s5 = "Server closed connection" fullword ascii
		$s6 = "%s: line %d: list delimiter not followed by keyword" fullword ascii
		$s8 = "checking for version `%s' in file %s required by file %s" fullword ascii
		$s9 = "Remote host closed connection" fullword ascii
		$s10 = "%s: line %d: bad command `%s'" fullword ascii
		$s13 = "verifying that server is a known host : file %s not found" fullword ascii
		$s14 = "%s: line %d: expected service, found `%s'" fullword ascii
		$s15 = "%s: line %d: list delimiter not followed by domain" fullword ascii
		$s17 = "Public key from server (%s) doesn't match user preference (%s)" fullword ascii
	condition:
		all of them
}