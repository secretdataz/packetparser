<?php
date_default_timezone_set('Asia/Seoul');
error_reporting(E_ALL);
ini_set("display_errors", 1);

	include("robin.class.php");
	$clients = glob("clients/*.exe");
	if(sizeof($clients) == 0)
		die("Place a ragnarok client into the \"clients\" folder\n");
	
	foreach ($clients as $i => $client) {
		$filename = basename($client);
		echo "$i  : $filename\n";
	}
	fwrite(STDOUT, "\nExtract packet_len from which client? : ");
	$choice = trim(fgets(STDIN));
	if (!isset($clients[$choice])){
		die("Bad Choice\n");
	}
	//$client = basename($clients[$choice]);
	
	
	$exe = new RObin();
	$exe->load($clients[$choice],true);
	
        if($exe->clientdate() >= 20120710){
			// strange addition, new function called
			$called = false;
			$code =  "\x55"
					."\x8B\xEC"
					."\x83\xEC\xAB"
					."\x56"
					."\x8B\xF1"
					."\xE8\xAB\xAB\xAB\xAB"
					."\xB8";
					
		} else {
			$code =  "\x55"
					."\x8B\xEC"
					."\x83\xE4\xF8"
					."\x83\xEC\xAB"
					."\x56"
					."\x8B\xF1"
					."\xB8";
		}
        $offset = $exe->code($code, "\xAB");
        if ($offset === false) {
            echo "Failed in part 1";
            return false;
        }
		echo "\r\npacket Length @ " . dechex($offset) . "#\r\n";
        $fp = fopen("plens\\recvpackets_" . basename($clients[$choice], ".exe") . ".txt", 'w');
        fwrite($fp,"Extracted With DiffGen2\n\n");

        // time to walk some code
        $ptr = 0;
        $done = 0;
        $ac = 0;
		$pak = 0;
		$len = 0;
		
        while(!$done) {
            $ins = bin2hex($exe->read($offset + $ptr, 1));
            switch($ins){
                case "50": // push    eax
                case "51": // push    ecx
                case "52": // push    edx
                case "55": // push    ebp
                case "56": // push    esi
                case "57": // push    edi
                    $ptr += 1;
                    break;
                case "68":
                    $ac += 1;
                    if($ac == 3)
                        $len = $exe->read($offset + $ptr + 1, 4, "L");
                    if($ac == 4)
                        $pak = $exe->read($offset + $ptr + 1, 4, "L");
                    $ptr += 5;
                    break;
                case "6a":
                    $ac += 1;
                    if($ac == 3)
                        $len = $exe->read($offset + $ptr + 1, 1, "c");
                    if($ac == 4)
                        $pak = $exe->read($offset + $ptr + 1, 1, "c");
                    $ptr += 2;
                    break;
                case "8b": // mov     ecx, esi
                case "33": // xor     edx, edx
                    $ptr += 2;
                    break;
                case "83": // sub     esp, 1Ch
                    $ptr += 3;
                    break;
                case "b8": // mov     eax, 4
                    $len = $exe->read($offset + $ptr + 1, 4, "L");
					//echo "length:".dechex($len)."\r\n";
                    $ptr += 5;
                    break;
                case "b9": // mov     ecx, 2Fh
                    $len = "-1";
                    $ptr += 5;
                    break;
                case "ba": // mov     edx, 1
                    $ptr += 5;
                    break;
                case "89": // mov     [esp+20h+var_C], eax
                    if(bin2hex($exe->read($offset + $ptr + 1, 1)) == "7c") {
                        $pak = $pak2; // packet length read from edi
                    }
                case "8d":
                    $ptr += 3;
                    break;
                case "c7":
                    $pak = $exe->read($offset + $ptr + 3, 4, "L");
                    $ptr += 7;
					//echo "packet:".dechex($pak)."\r\n";
                    break;
                case "bf": // packet length moved to edi
                    $pak2 = $exe->read($offset + $ptr + 1, 4, "L");
                    $ptr += 5;
                    break;
                case "e8":
					if($exe->clientdate() >= 20120710 && $called == false){
						$called = true;
						$pak = null;
						$len = null;
						$ac = 0;
						$ptr += 5;
						break;
					}
					if(!@$pak && !@$len){
						$ptr += 5;
						break;
					}
                    if(!@$pak || !@$len){
                        $ptr = dechex($offset+$ptr);
                        echo "pak or len not set $ins @ $ptr #";
                        $done = 1;
                        break;
                    }
					if($len == "-1"){
						fwrite($fp, "0". strtoupper(str_pad(dechex($pak), 3, "0", STR_PAD_LEFT)).",0\n");
					} else {
						fwrite($fp, "0". strtoupper(str_pad(dechex($pak), 3, "0", STR_PAD_LEFT)).",$len\n");
					}
                    $pak = null;
                    $len = null;
                    $ac = 0;
                    $ptr += 5;
                    break;
                case "5d":
                case "5f":
                case "5e":
                case "c3":
                    $done = 1;
                    break;
                default:
                    $ptr = dechex($offset+$ptr);
                    echo "unknown opcode $ins @ $ptr #";
                    $done = 1;
                    break;
            }
        }
		if($exe->clientdate() >= 20120710){
			$code =  "\x55"
					."\x8B\xEC"
					."\x83\xEC\xAB"
					."\x56"
					."\xB8\xAB\x00\x00\x00"
					."\x8B\xF1";
			$offset = $exe->code($code, "\xAB");
			if ($offset === false) {
				echo "Failed in part 2";
				return false;
			}
			echo "New Table @ " . dechex($offset) . "#\r\n";
			fwrite($fp, "\n\n## New Table ##\n\n");
			// time to walk some code
			$ptr = 0;
			$done = 0;
			$ac = 0;
			$pak = 0;
			$len = 0;
			
			while(!$done) {
				$ins = bin2hex($exe->read($offset + $ptr, 1));
				switch($ins){
					case "50": // push    eax
					case "51": // push    ecx
					case "52": // push    edx
					case "55": // push    ebp
					case "56": // push    esi
					case "57": // push    edi
						$ptr += 1;
						break;
					case "68":
						$ac += 1;
						if($ac == 3)
							$len = $exe->read($offset + $ptr + 1, 4, "L");
						if($ac == 4)
							$pak = $exe->read($offset + $ptr + 1, 4, "L");
						$ptr += 5;
						break;
					case "6a":
						$ac += 1;
						if($ac == 3)
							$len = $exe->read($offset + $ptr + 1, 1, "c");
						if($ac == 4)
							$pak = $exe->read($offset + $ptr + 1, 1, "c");
						$ptr += 2;
						break;
					case "8b": // mov     ecx, esi
					case "33": // xor     edx, edx
						$ptr += 2;
						break;
					case "83": // sub     esp, 1Ch
						$ptr += 3;
						break;
					case "b8": // mov     eax, 4
						$len = $exe->read($offset + $ptr + 1, 4, "L");
						$ptr += 5;
						break;
					case "b9": // mov     ecx, 2Fh
						$len = "-1";
						$ptr += 5;
						break;
					case "ba": // mov     edx, 1
						$ptr += 5;
						break;
					case "89": // mov     [esp+20h+var_C], eax
						if(bin2hex($exe->read($offset + $ptr + 1, 1)) == "7c") {
							$pak = $pak2; // packet length read from edi
						}
					case "8d":
						$ptr += 3;
						break;
					case "c7":
						$pak = $exe->read($offset + $ptr + 3, 4, "L");
						$ptr += 7;
						break;
					case "bf": // packet length moved to edi
						$pak2 = $exe->read($offset + $ptr + 1, 4, "L");
						$ptr += 5;
						break;
					case "e8":
						if($exe->clientdate() >= 20120710 && $called == false){
							$called = true;
							$pak = null;
							$len = null;
							$ac = 0;
							$ptr += 5;
							break;
						}
						if(!@$pak && !@$len){
							$ptr += 5;
							break;
						}
						if(!@$pak || !@$len){
							$ptr = dechex($offset+$ptr);
							echo "pak or len not set $ins @ $ptr #";
							$done = 1;
							break;
						}
						if($len == "-1"){
							fwrite($fp, "0". strtoupper(str_pad(dechex($pak), 3, "0", STR_PAD_LEFT)).",0\n");
						} else {
							fwrite($fp, "0". strtoupper(str_pad(dechex($pak), 3, "0", STR_PAD_LEFT)).",$len\n");
						}
						$pak = null;
						$len = null;
						$ac = 0;
						$ptr += 5;
						break;
					case "5d":
					case "5f":
					case "5e":
					case "c3":
						$done = 1;
						break;
					default:
						$ptr = dechex($offset+$ptr);
						echo "unknown opcode $ins @ $ptr #";
						$done = 1;
						break;
				}
			}
		}
		// read some encryption keys
		$code = "\x02".//prefix for finding - part of earlier instruction
				"\x68\xAB\xAB\xAB\xAB". // key 1
				"\x68\xAB\xAB\xAB\xAB". // key 2
				"\x68\xAB\xAB\xAB\xAB". // key 3
				"\xE8\xAB\xAB\xAB\xAB". // call to init
				"\x8B\xC8"; //mov ecx, eax
		
		$offset = $exe->code($code, "\xAB");
        if ($offset === false) {
            echo "Failed in part 3";
            return false;
        }
		
		echo "Encryption Keys @ " . dechex($offset) . "#\r\n\r\n";
		$key3 = dechex($exe->read($offset + 1, 4, "L"));
		$key2 = dechex($exe->read($offset + 6, 4, "L"));
		$key1 = dechex($exe->read($offset + 11, 4, "L"));
		
		fwrite($fp, "\r\n\r\nEncryption:0x$key1,0x$key2,0x$key3;\r\n");
		
        fclose($fp);
?>