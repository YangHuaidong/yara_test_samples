rule Trojan_Downloader_Win32_Farfli_Kbit_20180110110944_958 
{
	meta:
		judge = "black"
		threatname = "Trojan[Downloader]/Win32.Farfli.Kbit"
		threattype = "Downloader"
		family = "Farfli"
		hacker = "None"
		refer = "096bd69505393c9338253a61314e27b6"
		description = "None"
		comment = "None"
		author = "mqx"
		date = "2017-01-04"
	strings:
		$s0 = "select * from house"
		$s1 = "select * from house where roomtype = '%s' and buildingnum = %s"
		$s2 = " and major = '"
		$s3 = " buildingnum = %d"

	condition:
		all of them
}
