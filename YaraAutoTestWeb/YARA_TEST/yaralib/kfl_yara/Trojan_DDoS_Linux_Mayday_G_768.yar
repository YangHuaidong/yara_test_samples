rule Trojan_DDoS_Linux_Mayday_G_768
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Linux.Mayday.G"
		threattype = "DDoS"
		family = "Mayday"
		hacker = "None"
		refer = "9a09c5781ea71049ba17d7b1057605d2,516da47db49442725b4dc843c97e7809,006f7ce75d0b8768d833f81486ae7a96,9b65f910fb30aff2e736fd260fa2c1d3,e17a45d6ea9d19f137e3a506f055f722,96fd9dca52e1fb6a555aaa1ef1a80693,d9d24caa06e10c9a76a923a193952a62,3227ef4ee9b52312637b8e55dea0ca9b,6c3717ace0ac07e2d6b119ef864dbc25"
		author = "LiuGuangzhu"
		comment = "None"
		date = "2017-08-18"
		description = "None"
	strings:
		$s0 = "%7s %llu %lu %lu %lu %lu %lu %lu %lu %llu %lu %lu %lu %lu %lu %lu %lu"
		$s1 = "%s %llu %llu %llu %llu"
		$s2 = "cpu %llu %llu %llu %llu"
		$s3 = "[ %02d.%02d %02d:%02d:%02d.%03ld ] [%lu] [%s] %s"
		$s4 = "%Y-%m-%d"
		$s5 = "/etc/nsswitch.conf"
		$s6 = "/proc/%d/exe"
		$s7 = "%s: line %d"
		$s8 = "%a %b %e %H:%M:%S %Y"
		$s9 = "%a %b %e %H:%M:%S %Z %Y"
		$s10 = "M%hu.%hu.%hu%n"
		$s11 = "MemFree: %ld kB"
		$s12 = "MemTotal: %ld kB"
	condition:
		//$s0 and $s1 and $s2 and $s3 and $s4 and $s5 and $s6 and $s6 and $s7 and $s8 and $s9 and $s10 and $s11 and $s12
		all of them
}