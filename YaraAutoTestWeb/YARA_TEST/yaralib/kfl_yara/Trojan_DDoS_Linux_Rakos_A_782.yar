rule Trojan_DDoS_Linux_Rakos_A_782
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Linux.Rakos.A"
		threattype = "DDoS"
		family = "Rakos"
		hacker = "None"
		refer = "4d08072825eb9e32b9736988c57050eb,abf87f358d265a072d3ee4a4e1ddc16f"
		author = "LiuGuangZhu"
		comment = "None"
		date = "2018-01-17"
		description = "None"
	strings:
        $ = "upgrade/vars.yaml"
        $ = "upgrade/up"
        $ = "/tmp/init"
        $ = "dalek"
        $ = "skaro"
	condition:
        4 of them
}