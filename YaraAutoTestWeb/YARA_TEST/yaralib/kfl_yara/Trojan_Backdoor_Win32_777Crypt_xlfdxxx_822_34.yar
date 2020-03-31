rule Trojan_Backdoor_Win32_777Crypt_xlfdxxx_822_34
{
    meta:
        judge = "black"
        threatname = "Trojan[Backdoor]/Win32.777Crypt.xlfdxxx"
        threattype = "Backdoor"
        family = "777Crypt"
        hacker = "None"
        author = "bala"
        refer = "7dbf6ab8ce790f3322e0e4c8a0deb0c0"
        comment = "None"
        date = "2018-10-31"
        description = "None"
	strings:
        $s1 = "http://tuginsaat.com/wp-content/themes/twentythirteen/stats.php"
        $s2 = "read_this_file.txt" wide // Ransom note filename.
        $s3 = "seven_legion@india.com" // Part of the format string used to rename files.
        $s4 = {46 4f 52 20 44 45 43 52 59 50 54 20 46 49 4c 45 53 0d 0a 53 45 4e 44 20 4f
               4e 45 20 46 49 4c 45 20 49 4e 20 45 2d 4d 41 49 4c 0d 0a 73 65 76 65 6e 5f
               6c 65 67 69 6f 6e 40 69 6e 64 69 61 2e 63 6f 6d } // Ransom note content.
        $s5 = "%s._%02i-%02i-%02i-%02i-%02i-%02i_$%s$.777" // Renaming format string.

    condition:
        4 of ($s*)
}