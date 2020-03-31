rule Trojan_DDoS_Linux_BillGates_Update_20161213095134_964_256 
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Linux.BillGates.Update"
		threattype = "DDOS"
		family = "BillGates"
		hacker = "None"
		refer = "385c946e31449e654fe0bca1b230c979"
		description = "http://www.kernelmode.info/forum/viewtopic.php?f=16&t=3429"
		comment = "None"
		author = "djw, @benkow_"
		date = "2016-06-23"
	strings:
		$a = "12CUpdateGates"
		$b = "11CUpdateBill"

	condition:
		$a and $b
}
