rule Trojan_Backdoor_Linux_Httpsd_hhcynhsfhd_837_29
{
	meta:
		judge = "black"
		threatname = "Trojan[Backdoor]/Linux.Httpsd.hhcynhsfhd"
		threattype = "Backdoor"
		family = "Httpsd"
		hacker = "None"
		author = "ljy"
		refer = "b0202d01a27e6ae30fa713a7c1fc6f60,ab62973fe40925bba59c940329a8e2af"
		comment = "None"
		date = "2018-11-21"
		description = "None"
	strings:
		$st01 = "k.conectionapis.com" fullword nocase wide ascii
		$st02 = "key=%s&host_name=%s&cpu_count=%d&os_type=%s&core_count=%s" fullword nocase wide ascii
		$st03 = "id=%d&result=%s" fullword nocase wide ascii
		$st04 = "rtime" fullword nocase wide ascii
		$st05 = "down" fullword nocase wide ascii
		$st06 = "cmd" fullword nocase wide ascii
		$st07 = "0 */6 * * * root" fullword nocase wide ascii
		$st08 = "/etc/cron.d/httpsd" fullword nocase wide ascii
		$st09 = "cat /proc/cpuinfo |grep processor|wc -l" fullword nocase wide ascii
		$st10 = "k.conectionapis.com" fullword nocase wide ascii
		$st11 = "/api" fullword nocase wide ascii
		$st12 = "/tmp/.httpslog" fullword nocase wide ascii
		$st13 = "/bin/.httpsd" fullword nocase wide ascii
		$st14 = "/tmp/.httpsd" fullword nocase wide ascii
		$st15 = "/tmp/.httpspid" fullword nocase wide ascii
		$st16 = "/tmp/.httpskey" fullword nocase wide ascii

	condition:
		all of them
}
