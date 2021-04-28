rule dofloo {
meta:
    author = "vxpeek@gmail.com"

strings:
    $str1 = "3AES"
    $str2 = "Hacker"

    $online_str_1 = "VERSONEX:Linux-%s-mips|%d|%d MHz|%dMB|%dMB|%s"
    $online_str_2 = "VERSONEX:Linux-%s|%d|%d MHz|%dMB|%dMB|%s"
    $online_str_3 = "VERSONEX:Linux-%s-arm|%d|%d MHz|%dMB|%dMB|%s"
	$online_str_4 = "VERSONEX:Linux-%s|%d|%d|%dMB|%s|%s"

condition:
    all of ($str*) and 1 of ($online_str_*)
}
