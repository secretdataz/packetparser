<?php
//date_default_timezone_set('Asia/Seoul');
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
echo " - Packet Capture\n";
echo " 2: WPE .pac file\n";
echo " 3: WireShark k12\n";
echo " 4: PacketParser Debug Log\n";
fwrite(STDOUT, "\nwhich source of packets? ");
$source = trim(fgets(STDIN));



if($source == "1"){
	$parser = new parser();
	
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
	$parser = new parser();
	
	// ########  WPE System  #######
	$capture 		= $parser->load_input("captures/wpe", "*.pac", "WPE");
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
	$parser = new parser(false);
	// ######## WireShark System  #######
	$capture 		= $parser->load_input("captures/wireshark_k12", "*.txt", "WireShark");
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
} elseif($source == "4"){
	$parser = new parser(false);
	// ########  PacketParser System  #######
	$capture 		= $parser->load_input("captures/packetparser", "*.txt", "PacketParser");
	$file           = fopen($capture, "r");
	if(function_exists('PP_ENTRY_TEXT')) {
		echo PP_ENTRY_TEXT($parser);
	}
	if($file){
		while (($line = fgets($file, 4096)) !== false) {
			//if(strlen(trim($line)) > 168){
				//$line = str_replace("|","",trim(substr($line, 168)));
				$line = trim($line);
				$parser->stream = pack("H*", $line);
				$parser->parse_stream();
			//}
		}
	}
}



// php must be the worst language for handling values

function bcand($x, $y)
{
       return _bcbitwise_internal($x, $y, '_bcand');
}
function _bcand($x, $y)
{
       return $x & $y;
}
function _bcbitwise_internal($x, $y, $op)
{
       $bx = bc2bin($x);
       $by = bc2bin($y);

       // Pad $bx and $by so that both are the same length.

       equalbinpad($bx, $by);

       $ix=0;
       $ret = '';

       for($ix = 0; $ix < strlen($bx); $ix++)
       {
               $xd = substr($bx, $ix, 1);
               $yd = substr($by, $ix, 1);
               $ret .= call_user_func($op, $xd, $yd);
       }

       return bin2bc($ret);
}
function equalbinpad(&$x, &$y)
{
       $xlen = strlen($x);
         $ylen = strlen($y);

       $length = max($xlen, $ylen);
         fixedbinpad($x, $length);
       fixedbinpad($y, $length);
}
function fixedbinpad(&$num, $length)
{
       $pad = '';
       for($ii = 0; $ii < $length-strlen($num); $ii++)
       {
               $pad .= bc2bin('0');
       }

       $num = $pad . $num;
}
function bc2bin($num)
{
       return dec2base($num, 128);
}
function bin2bc($num)
{
       return base2dec($num, 128);
}
function dec2base($dec,$base,$digits=FALSE) {
   if($base<2 or $base>256) die("Invalid Base: ".$base);
   bcscale(0);
   $value="";
   if(!$digits) $digits=digits($base);
   while($dec>$base-1) {
       $rest=bcmod($dec,$base);
       $dec=bcdiv($dec,$base);
       $value=$digits[$rest].$value;
   }
   $value=$digits[intval($dec)].$value;
   return (string) $value;
}
function base2dec($value,$base,$digits=FALSE) {
   if($base<2 or $base>256) die("Invalid Base: ".$base);
   bcscale(0);
   if($base<37) $value=strtolower($value);
   if(!$digits) $digits=digits($base);
   $size=strlen($value);
   $dec="0";
   for($loop=0;$loop<$size;$loop++) {
       $element=strpos($digits,$value[$loop]);
       $power=bcpow($base,$size-$loop-1);
       $dec=bcadd($dec,bcmul($element,$power));
   }
   return (string) $dec;
}
function digits($base) {
   if($base>64) {
       $digits="";
       for($loop=0;$loop<256;$loop++) {
           $digits.=chr($loop);
       }
   } else {
       $digits ="0123456789abcdefghijklmnopqrstuvwxyz";
       $digits.="ABCDEFGHIJKLMNOPQRSTUVWXYZ-_";
   }
   $digits=substr($digits,0,$base);
   return (string) $digits;
}










?>
