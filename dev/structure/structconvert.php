<?php
date_default_timezone_set('Asia/Seoul');
error_reporting(E_ALL);
ini_set("display_errors", 1);
$intxt = fopen("struct.txt", 'r') or exit("Unable to open struct.txt");
//$outtxt = fopen("../../mode/full_info.php", 'w');
$outtxt = fopen("full_info.php", 'w');
$desc = fopen("func.txt", 'w');
fwrite($outtxt, "<?php\n");
$packetid = null;
$aegisname =  null;
$descline = null;
$line_num = 1;
while (!feof($intxt)) {
	$line = fgets($intxt);
	$line_num++;
    // packet id comment
    if (preg_match('%^(// (packet 0x(.*)))%', $line, $m)) {
        $packetid = trim($m[2]);
		$descline = strtoupper(str_pad(trim($m[3]), 4, "0", STR_PAD_LEFT));
        continue;
	}
    // start of main struct
    if(preg_match('/^struct (.*?) \{/', $line, $m)) {
        if(!$packetid)
            die("cant find packet id after $packetid");
        $aegisname = $m[1];
        $string  = "// $packetid\n";
		$string .= "function $aegisname(\$parser) {\n";
		$string .= "\techo \"\$parser->packet_desc ";
		$descline .= ",$aegisname\n";
		fwrite($desc,$descline);
		$newstruct = true;
		fwrite($outtxt, $string);
        continue;
	}
    // end of main struct
    if (preg_match('/^\}/', $line, $m)) {
        $packetid = null;
		if($newstruct){
			$string = "\\n\";\n";
			fwrite($outtxt, $string);
			$newstruct = false;
		}
		//$string = "\t\$parser->end_packet();\n}\n\n";
		$string = "}\n\n";
		fwrite($outtxt, $string);
        continue;
    }
    // types in main struct
    if (preg_match('%^\s\s/\* this\+(\wx\w*) \*/ (unsigned short|short|unsigned char|char|bool|unsigned long|long|unsigned int|int|int64|float) (\w*)(?:\[(\d*|\.*)\])*%', $line, $m)) {
        $m[3] = trim($m[3]);
		if($m[3] == "PacketType")
			continue;
		$prepend = "";
		if(!$newstruct){
			$prepend = "\techo \"\$parser->nl ";
		}
		$newstruct = false;
        switch($m[2]) {
            case 'unsigned short':
            case 'short':
				$string = $prepend."$m[3]=\".\$parser->word().\"\\n\";\n";
                break;
            case 'unsigned long':
            case 'long':
            case 'int':
            case 'unsigned int':
				$string = $prepend."$m[3]=\".\$parser->long().\"\\n\";\n";
                break;
			
			case 'int64':
				$string = $prepend."$m[3]=\".\$parser->int64().\"\\n\";\n";
				break;
			case 'float':
				$string = $prepend."$m[3]=\".\$parser->long().\"\\n\";\n";
				break;
			
            case 'unsigned char':
            case 'char':
            case 'bool':
                $string = $prepend."$m[3]=\".\$parser->byte().\"\\n\";\n";
                if(@$m[4])
                    $string = $prepend."$m[3]=\".\$parser->string($m[4]).\"\\n\";\n";
                if(@$m[4]=="...")
                    $string = $prepend."$m[3]=\".\$parser->string(\$parser->packet_length - \$parser->packet_pointer).\"\\n\";\n";
                break;
        }
        fwrite($outtxt, $string);
        continue;
    }
    // start of 2nd level struct
    if (preg_match('%^\s\s/\* this\+(\wx\w*) \*/ struct (\w*) (\w*)(?:\[(\d*|\.*)\])* \{(?: // Size (\d*))*%', $line, $m)) {
		if($newstruct){
			$string = "\";\n";
			fwrite($outtxt, $string);
			$newstruct = false;
		}
        if(!@$m[4]){
            $mode1 = 1;
            continue;
        } elseif($m[4] == "...") {
            $mode1 = 2;
            $stlen = $m[5]; // inner len
            $varname = $m[3];
            $string  = "\t\$$varname = (\$parser->packet_length - \$parser->packet_pointer) / $stlen;\n";
            $string .= "\tfor (\$i = 0; \$i < \$$varname; \$i++) {\n";
            fwrite($outtxt, $string);
            continue;
        } else {
            $mode1 = 2;
            $stlen = $m[5]; // inner len
            $count = $m[4];
            $string = "\tfor (\$i = 0; \$i < $count; \$i++) {\n";
            fwrite($outtxt, $string);
            continue;
        }
    }
    // end of 2nd level struct
    if (preg_match('/^\s\s\}/', $line, $m)) {
        if($mode1 == 2){
            $string = "\t}\n";
            fwrite($outtxt, $string);
        }
        $mode = null;
        continue;
    }
    // second level stuct type
    if (preg_match('%^\s\s\s\s/\* this\+(\wx\w*) \*/ (unsigned short|short|unsigned char|char|bool|unsigned long|long|unsigned int|int|int64|float) (\w*)(?:\[(\d*|\.*)\])*%', $line, $m)) {
        $m[3] = trim($m[3]);
        switch($m[2]) {
            case 'unsigned short':
            case 'short':
                $string = "\t\techo \"\$parser->nl $m[3]=\".\$parser->word().\"\\n\";\n";
                break;
            case 'unsigned long':
            case 'long':
            case 'int':
            case 'unsigned int':
                $string = "\t\techo \"\$parser->nl $m[3]=\".\$parser->long().\"\\n\";\n";
                break;
			case 'int64':
				$string = "\t\techo \"\$parser->nl $m[3]=\".\$parser->int64().\"\\n\";\n";
				break;
			case 'float':
				$string = "\t\techo \"\$parser->nl $m[3]=\".\$parser->long().\"\\n\";\n";
				break;
            case 'unsigned char':
            case 'char':
            case 'bool':
                $string = "\t\techo \"\$parser->nl $m[3]=\".\$parser->byte().\"\\n\";\n";
                if(@$m[4])
                    $string = "\t\techo \"\$parser->nl $m[3]=\".\$parser->string($m[4]).\"\\n\";\n";
                break;
        }
        fwrite($outtxt, $string);
        continue;
    }
    // start of 3rd level struct
    if (preg_match('%^\s\s\s\s/\* this\+(\wx\w*) \*/ struct (\w*) (\w*)(?:\[(\d*|\.*)\])* \{(?: // Size (\d*))*%', $line, $m)) {
        if(!@$m[4]){
            $mode2 = 1;
            continue;
        } else {
            $mode2 = 2;
            $stlen = $m[5]; // inner len
            $count = $m[4];
            $string = "\tfor (\$i = 0; \$i < $count; \$i++) {\n";
            fwrite($outtxt, $string);
            continue;
        }
    }
    // end of 3rd level struct
    if (preg_match('/^\s\s\s\s\}/', $line, $m)) {
        if($mode2 == 2){
            $string = "\t\t}\n";
            fwrite($outtxt, $string);
        }
        $mode2 = null;
        continue;
    }
    // 3rd level stuct type
    if (preg_match('%^\s\s\s\s\s\s/\* this\+(\wx\w*) \*/ (unsigned short|short|unsigned char|char|bool|unsigned long|long|unsigned int|int|int64|float) (\w*)(?:\[(\d*|\.*)\])*%', $line, $m)) {
        $m[3] = trim($m[3]);
        switch($m[2]) {
            case 'unsigned short':
            case 'short':
                $string = "\t\techo \"\$parser->nl $m[3]=\".\$parser->word().\"\\n\";\n";
                break;
            case 'unsigned long':
            case 'long':
            case 'int':
            case 'unsigned int':
                $string = "\t\techo \"\$parser->nl $m[3]=\".\$parser->long().\"\\n\";\n";
                break;
			case 'int64':
				$string = "\t\techo \"\$parser->nl $m[3]=\".\$parser->int64().\"\\n\";\n";
				break;
			case 'float':
				$string = "\t\techo \"\$parser->nl $m[3]=\".\$parser->long().\"\\n\";\n";
				break;
            case 'unsigned char':
            case 'char':
            case 'bool':
                $string = "\t\techo \"\$parser->nl $m[3]=\".\$parser->bytr().\"\\n\";\n";
                if(@$m[4])
                    $string = "\t\techo \"\$parser->nl $m[3]=\".\$parser->string($m[4]).\"\\n\";\n";
                break;
        }
        fwrite($outtxt, $string);
        continue;
    }
    // remove blank lines
    if (preg_match('/^\n/', $line, $m)) {
        continue;
    }
    // $aegisname
    echo "unsupported line # $line_num $line";
}
fwrite($outtxt, "?>\n");
fclose($intxt);
fclose($desc);
fclose($outtxt);
?>