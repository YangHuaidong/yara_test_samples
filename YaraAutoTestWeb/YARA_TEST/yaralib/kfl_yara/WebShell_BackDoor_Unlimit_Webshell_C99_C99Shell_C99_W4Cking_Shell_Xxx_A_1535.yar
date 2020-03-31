rule WebShell_BackDoor_Unlimit_Webshell_C99_C99Shell_C99_W4Cking_Shell_Xxx_A_1535 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - from files c99.php, c99shell.php, c99_w4cking.php, Shell [ci] .Biz was here.php, acid.php, c100 v. 777shell v. Undetectable #18a Modded by 777 - Don.php, c66.php, c99-shadows-mod.php, c99.php, c99shell.php"
    family = "Webshell"
    hacker = "None"
    hash0 = "61a92ce63369e2fa4919ef0ff7c51167"
    hash1 = "d3f38a6dc54a73d304932d9227a739ec"
    hash2 = "9c34adbc8fd8d908cbb341734830f971"
    hash3 = "f2fa878de03732fbf5c86d656467ff50"
    hash4 = "b8f261a3cdf23398d573aaf55eaf63b5"
    hash5 = "27786d1e0b1046a1a7f67ee41c64bf4c"
    hash6 = "0f5b9238d281bc6ac13406bb24ac2a5b"
    hash7 = "68c0629d08b1664f5bcce7d7f5f71d22"
    hash8 = "157b4ac3c7ba3a36e546e81e9279eab5"
    hash9 = "048ccc01b873b40d57ce25a4c56ea717"
    judge = "unknown"
    reference = "None"
    score = 70
    super_rule = 1
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.C99.C99Shell.C99.W4Cking.Shell.Xxx.A"
    threattype = "BackDoor"
  strings:
    $s0 = "echo \"<b>HEXDUMP:</b><nobr>"
    $s4 = "if ($filestealth) {$stat = stat($d.$f);}" fullword
    $s5 = "while ($row = mysql_fetch_array($result, MYSQL_NUM)) { echo \"<tr><td>\".$r"
    $s6 = "if ((mysql_create_db ($sql_newdb)) and (!empty($sql_newdb))) {echo \"DB "
    $s8 = "echo \"<center><b>Server-status variables:</b><br><br>\";" fullword
    $s9 = "echo \"<textarea cols=80 rows=10>\".htmlspecialchars($encoded).\"</textarea>"
  condition:
    2 of them
}