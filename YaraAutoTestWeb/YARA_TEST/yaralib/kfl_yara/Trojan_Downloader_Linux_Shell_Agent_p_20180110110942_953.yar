rule Trojan_Downloader_Linux_Shell_Agent_p_20180110110942_953 
{
	meta:
		judge = "black"
		threatname = "Trojan[Downloader]/Linux.Shell_Agent.p"
		threattype = "Downloader"
		family = "Shell_Agent"
		hacker = "None"
		refer = "2867587ab704c55a6c1a71705f8de5da"
		description = "None"
		comment = "None"
		author = "mqx"
		date = "2017-01-04"
	strings:
		$s0 = "chmod +x pl0xmips"
		$s1 = "chmod +x pl0xsh4"
		$s2 = "rm -rf pl0xsh4"
		$s3 = "cd /var/run"

	condition:
		all of them
}
