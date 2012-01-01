<?php
date_default_timezone_set('Asia/Seoul');
error_reporting(E_ALL);
ini_set("display_errors", 1);

	$clients = glob("*.exe");
	if(sizeof($clients) == 1)
		die("Place a ragnarok client into this folder\n");
	
	foreach ($clients as $i => $client) {
		$filename = basename($client);
		echo "$i  : $filename\n";
	}
	fwrite(STDOUT, "\nInject dll into which client? : ");
	$choice = trim(fgets(STDIN));
	if (!isset($clients[$choice])){
		die("Bad Choice\n");
	}
	$client = basename($clients[$choice]);
	$rename = basename($clients[$choice], ".exe");
	exec("p.exe $client wpp.dll");
	rename($client.".patched", $rename."_wpp.exe");
	echo "Copy patched client and wpp.dll to RO folder <3\n";
	require("include/robin.class.php");
	require("include/plen_extract.php");
	
?>