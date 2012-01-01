<?php
	$exe = new RObin();
	$exe->load($client,false);
	
	$code = "\x55\x8B\xEC\x83\xE4\xF8\x83\xEC\xAB\x56\x8B\xF1\xB8";
	$offset = $exe->code($code, "\xAB");
	if ($offset === false) {
		echo "Failed in part 1";
		return false;
	}
	// time to walk some code
	$ptr = 0;
	$done = 0;
	$ac = 0;
	$len_table = array();
	while(!$done) {
		$ins = bin2hex($exe->read($offset + $ptr, 1));
		switch($ins){
			case "50": // push	eax
			case "51": // push	ecx
			case "52": // push	edx
			case "55": // push	ebp
			case "56": // push	esi
			case "57": // push	edi
				$ptr += 1;
				break;
			case "68":
				$ac += 1;
				if($ac == 3)
					$len = $exe->read($offset + $ptr + 1, 4, "L");
				if($ac == 4){
					$pak = $exe->read($offset + $ptr + 1, 4, "L");
					//echo "1";
				}
				$ptr += 5;
				break;
			case "6a":
				$ac += 1;
				if($ac == 3)
					$len = $exe->read($offset + $ptr + 1, 1, "c");
				if($ac == 4){
					$pak = $exe->read($offset + $ptr + 1, 1, "c");
					//echo "2";
				}
				$ptr += 2;
				break;
			case "8b": // mov	 ecx, esi
			case "33": // xor	 edx, edx
				$ptr += 2;
				break;
			case "83": // sub	 esp, 1Ch
				$ptr += 3;
				break;
			case "b8": // mov	 eax, 4
				$len = $exe->read($offset + $ptr + 1, 4, "L");
				//echo "len:$len => ";
				$ptr += 5;
				break;
			case "b9": // mov	 ecx, 2Fh
				$len = "0";
				$ptr += 5;
				break;
			case "ba": // mov	 edx, 1
				$ptr += 5;
				break;
			case "89": // mov	 [esp+20h+var_C], eax
				if(bin2hex($exe->read($offset + $ptr + 1, 1)) == "7c") {
					$pak = $pak2; // packet length read from edi
					//echo "3";
				}
			case "8d":
				$ptr += 4;
				break;
			case "c7":
				$pak = $exe->read($offset + $ptr + 4, 4, "L");
				//echo "pak:$pak\n";
				$ptr += 8;
				break;
			case "bf": // packet length moved to edi
				$pak2 = $exe->read($offset + $ptr + 1, 4, "L");
				$ptr += 5;
				break;
			case "e8":
				if(!$pak || $len === null){
					$ptr = dechex($offset+$ptr);
					echo "pak or len not set $ins @ $ptr #";
					$done = 1;
					break;
				}
				if($len == -1)
					$len = "0";
				//echo "Adding $pak -> $len\n";
				$len_table[$pak] = $len;
				
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
	ksort($len_table);
	echo "\n";
	$outtxt = fopen("plen/plen_".$exe->clientdate().".txt", 'w');
	foreach($len_table as $key => $val) {
		$key = strtoupper(str_pad(dechex($key), 4, "0", STR_PAD_LEFT));
		fwrite($outtxt, "$key,$val\n");
		//echo "$key => $val\n";
	}
	fclose($outtxt);
?>