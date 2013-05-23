<?php
date_default_timezone_set('Asia/Seoul');
error_reporting(E_ALL);
ini_set("display_errors", 1);

require("parser_cls.php");

echo "       _____         _       _      _____                      \n";
echo "      |  _  |___ ___| |_ ___| |_   |  _  |___ ___ ___ ___ ___  \n";
echo "      |   __| .'|  _| '_| -_|  _|  |   __| .'|  _|_ -| -_|  _| \n";
echo "      |__|  |__,|___|_,_|___|_|    |__|  |__,|_| |___|___|_|   \n";
echo "         Yommys Amazing Ragnarok Packet Analyzer Framework\n\n";

echo "Which source of packets?\n";
echo " 1: Live Network Capture\n";
echo " 2: WPE .pac file\n";
echo " 3: WireShark k12\n";
fwrite(STDOUT, "\nwhich source of packets? ");
$source = trim(fgets(STDIN));

$parser = new parser();

if($source == "1"){
	// ########  Socket System  #######
	$connected = false;		// socket connected
	$listening = true;		// socket listening
	$sock = socket_create(AF_INET,SOCK_STREAM,SOL_TCP);
	if(!@socket_bind($sock,'127.0.0.1',13554)) {
		die("\n## Socket already in use ##\n");
	}
	socket_listen($sock);
	//socket_set_nonblock($sock);

	while(true){
		$parser->packet_num = 0;
		echo "\nwaiting for connection from client...";
		while($connected == false){
			if(($socket = socket_accept($sock)) !== false){
				echo "\nClient connected <3\n";
				$connected = true;
			}
		}

		if(function_exists("PP_ENTRY_TEXT")) {
			PP_ENTRY_TEXT($parser);
		}

		while($listening){
			if (($parser->stream = @socket_read($socket, 2048, PHP_BINARY_READ)) === false) {
				echo "\nClient disconnected!\n";
				socket_close($socket);
				$connected = false;
				break;
			}
			if($parser->stream) {
				if(strlen($parser->stream)) {
					$parser->parse_stream();
				}
			}
		}
	}
} elseif($source == "2"){
	// ########  WPE System  #######
	$capture 		= $parser->load_pac();
	$file           = file_get_contents($capture);
	if(function_exists('PP_ENTRY_TEXT')) {
		echo PP_ENTRY_TEXT($parser);
	}
	$fpos       = 0;
	$totalsar   = unpack("L", substr($file, $fpos, 4));
	$fpos       += 4;

	//$packetlog	= fopen("logs/packet_log_".date("YmdGis").".txt", 'w');

	// parse pac file, sending each packet to the parser
	// fpos = file pointer

	for ($packet_num = 0; $packet_num < 5; $packet_num++) {
		$packet_len =	$parser->unpack2("L", substr($file, $fpos, 4)); $fpos+=4;
		$packet_data =	substr($file, $fpos, $packet_len); $fpos+=$packet_len;
		$socket_id =	$parser->unpack2("L", substr($file, $fpos, 4)); $fpos+=4;
		$ip_send_len =	$parser->unpack2("L", substr($file, $fpos, 4)); $fpos+=4;
		$ip_send =		substr($file, $fpos, $ip_send_len); $fpos+=$ip_send_len;
		$ip_recv_len =	$parser->unpack2("L", substr($file, $fpos, 4)); $fpos+=4;
		$ip_recv =		substr($file, $fpos, $ip_recv_len); $fpos+=$ip_recv_len;
		$length_len = 	$parser->unpack2("L", substr($file, $fpos, 4)); $fpos+=4;
		$length =		substr($file, $fpos, $length_len); $fpos+=$length_len;
		$dir_len = 		$parser->unpack2("L", substr($file, $fpos, 4)); $fpos+=4;
		$dir = 			substr($file, $fpos, $dir_len); $fpos+=$dir_len;
		//echo $ip_send . " " . $ip_recv . "\n";
		$parser->stream = $packet_data;
		$parser->parse_stream();
	}
} elseif($source == "3"){
	$capture 		= $parser->load_wireshark();
	$file           = fopen($capture, "r");
	if(function_exists('PP_ENTRY_TEXT')) {
		echo PP_ENTRY_TEXT($parser);
	}
	if($file){
		while (($line = fgets($file, 4096)) !== false) {
			if(strlen(trim($line)) > 168){
				$line = str_replace("|","",trim(substr($line, 168)));
				$parser->stream = pack("H*", $line);
				$parser->parse_stream();
			}
		}
	}
}







?>
