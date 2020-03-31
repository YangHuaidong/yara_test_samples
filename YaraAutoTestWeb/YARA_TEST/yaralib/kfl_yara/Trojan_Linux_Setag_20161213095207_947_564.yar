rule Trojan_Linux_Setag_20161213095207_947_564 
{
	meta:
		judge = "black"
		threatname = "Trojan/Linux.Setag"
		threattype = "DDOS"
		family = "Setag"
		hacker = "none"
		refer = "8aaf936b63e9ab6bd0ea3c520aa71834,8dc4ac174c1bf456c27a5d4c64649797,15621ba30d969a8257fdb89b5cb9d9ed,b94e63d38073df0009e727039a512ad3,d360cc67cced926ab96a60933578c5e4"
		description = "None"
		comment = "none"
		author = "HuangYY"
		date = "2016-08-17"
	strings:
		$s0 = "dst_mac %02x:%02x:%02x:%02x:%02x:%02x"
		$s1 = "ln -s /etc/init.d/%s %s"
		$s2 = "%16s 0x%d 0x%d %20s %s"
		$s3 = "/usr/share/zoneinfo"
		$s4 = "/proc/cpuinfo"
		$s5 = "/proc/net/pktgen/kpktgend_%d"

	condition:
		all of them
}
