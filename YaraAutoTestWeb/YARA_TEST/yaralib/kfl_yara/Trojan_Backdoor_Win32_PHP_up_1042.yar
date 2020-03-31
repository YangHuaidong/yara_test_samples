rule Trojan_Backdoor_Win32_PHP_up_1042
{
    meta:
        judge = "black"
        threatname = "Trojan[Backdoor]/Win32.PHP.up"
        threattype = "Backdoor"
        family = "PHP"
        hacker = "None"
        author = "copy"
        refer = "7edefb8bd0876c41906f4b39b52cd0ef"
        comment = "None"
        date = "2018-12-13"
        description = "Web Shell - file up.php"
		score = 70
	strings:
		$s0 = "copy($HTTP_POST_FILES['userfile']['tmp_name'], $_POST['remotefile']);" fullword
		$s3 = "if(is_uploaded_file($HTTP_POST_FILES['userfile']['tmp_name'])) {" fullword
		$s8 = "echo \"Uploaded file: \" . $HTTP_POST_FILES['userfile']['name'];" fullword
	condition:
		2 of them
}