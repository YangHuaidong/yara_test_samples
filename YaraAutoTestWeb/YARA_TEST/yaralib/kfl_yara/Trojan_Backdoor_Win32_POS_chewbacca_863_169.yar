rule Trojan_Backdoor_Win32_POS_chewbacca_863_169
{
    meta:
        judge = "black"
        threatname = "Trojan[Backdoor]/Win32.POS.chewbacca"
        threattype = "Backdoor"
        family = "POS"
        hacker = "None"
        author = "copy"
        refer = "21f8b9d9a6fa3a0cd3a3f0644636bf09,28bc48ac4a92bde15945afc0cee0bd54"
        comment = "https://www.securelist.com/en/blog/208214185/ChewBacca_a_new_episode_of_Tor_based_Malware"
        date = "2018-11-05"
        description = "Point of Sale (POS) Malware"
strings:
	$s1 = "tor -f <torrc>"
	$s2 = "tor_"
	$s3 = "umemscan"
	$s4 = "CHEWBAC"
condition:
	uint16(0) == 0x5A4D and (all of ($s*))
}