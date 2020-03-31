rule Trojan_Backdoor_Linux_Mysql_v1_1037
{
    meta:
        judge = "black"
        threatname = "Trojan[Backdoor]/Linux.Mysql.v1"
        threattype = "Backdoor"
        family = "Mysql"
        hacker = "None"
        author = "copy"
        refer = "a12fc0a3d31e2f89727b9678148cd487"
        comment = "None"
        date = "2018-12-13"
        description = "Web Shell - file Mysql interface v1.0.php"
		score = 70
	strings:
		$s0 = "echo \"<td><a href='$PHP_SELF?action=dropDB&dbname=$dbname' onClick=\\\"return"
	condition:
		all of them
}