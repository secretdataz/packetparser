<?php
// Ragnarok Packet Analyzer Class
// Yommy 2013 <3

class parser {
	// Packet being parsed
	public $stream;
	public $packet, $packet_id, $packet_length, $packet_pointer, $packet_desc;
	public $packet_num, $packet_dir, $prev_packet, $prev_packet_dir;
	
	public $mode	= array();		// mode settings
	
	// Static Data
	public $unit		= array();      // array to store seen units for later use
	public $job			= array();      // jobs , mobs , mercs,  npc ids
	public $item		= array();      // items
	public $vars		= array();      // vars
	public $skill		= array();      // skills
	public $efst		= array();      // status
	
	// Packet Info
	public $p_lens		= array();      // packet length array
	public $p_funcs		= array();      // packet analyzer functions
	
	// 
	public $aid = null;
	public $aid_packet = false;
	public $nl = "|     |     |      |                                                    |";
	public $br = "|.....|.....|......|....................................................|...............................\n";
	
	// logging
	public $console_log;
	public $packet_log;
	public $debug = true;
	
	// encryption
	public $enc_state = 0;
	public $enc_key1;
	public $enc_key2;
	public $enc_key3;
	
	public $enc_key1_; // original keys
	public $enc_key2_;
	public $enc_key3_;
	
	

	function __construct($debug = true) {
		$this->console_log = fopen("output_log/".date("Ymd-Gis").".txt", "w+");
		$this->debug = $debug;
		if($this->debug)
			$this->packet_log  = fopen("debug/".date("Ymd-Gis").".txt", "w+");
		
		// Load Packet Info
		$this->load_data("./data/packet/func.txt",		"p_funcs");
		$this->load_plen();
		// Load Static Data
		$this->load_data("./data/enum/jobtype.txt",	"job");
		$this->load_data("./data/enum/item.txt",		"item");
		$this->load_data("./data/enum/var.txt",		"vars");
		$this->load_data("./data/enum/skill.txt",		"skill");
		$this->load_data("./data/enum/efst.txt",		"efst");
		
		//$this->load_data("./data/packet/plen.txt",		"p_lens");
		//print_r($this->p_lens);
		
		$this->load_mode();
	}

	function echo_save($text){
		echo $text;
		fwrite($this->console_log, $text);
	}
	
	function end_packet() {
		if($this->packet_pointer < $this->packet_length) {
			$extra_bytes = $this->packet_length - $this->packet_pointer;
			// should be output from mode/*.php
			$this->echo_save("$this->nl $extra_bytes bytes not analyzed\n");
		}
	}
	function load_data($filename, $arr) {
		$starttime = microtime(true);
		//$filename = "$filename";
		$txtfile = fopen($filename, 'r') or exit("Unable to open $filename");
		while (!feof($txtfile)) {
			if(preg_match('/(.*),(.*)/', fgets($txtfile), $regs)) {
				$this->{$arr}[$regs[1]] = trim($regs[2]);
			}
		}
		fclose($txtfile);
		$totaltime = microtime(true) - $starttime;
		$this->echo_save(str_pad("load_data($filename)", 34, " ")." Time: " . round($totaltime, 3) . "s\n");
	}
	
	function load_plen() {
		$shuffle = array();
		$shuffle[0] = "PACKET_SHUFFLES_SUCK_BALLS";
		$shuffle[1] = "PACKET_CZ_REQUEST_ACT2";
		$shuffle[2] = "PACKET_CZ_USE_SKILL2";
		$shuffle[3] = "PACKET_CZ_REQUEST_MOVE2";
		$shuffle[4] = "PACKET_CZ_REQUEST_TIME2";
		$shuffle[5] = "PACKET_CZ_CHANGE_DIRECTION2";
		$shuffle[6] = "PACKET_CZ_ITEM_PICKUP2";
		$shuffle[7] = "PACKET_CZ_ITEM_THROW2";
		$shuffle[8] = "PACKET_CZ_MOVE_ITEM_FROM_BODY_TO_STORE2";
		$shuffle[9] = "PACKET_CZ_MOVE_ITEM_FROM_STORE_TO_BODY2";
		$shuffle[10] = "PACKET_CZ_USE_SKILL_TOGROUND2";
		$shuffle[11] = "PACKET_CZ_USE_SKILL_TOGROUND_WITHTALKBOX2";
		$shuffle[12] = "PACKET_CZ_REQNAME2";
		$shuffle[13] = "PACKET_CZ_REQNAME_BYGID2";
		$shuffle[14] = "PACKET_CZ_SSILIST_ITEM_CLICK";
		$shuffle[15] = "PACKET_CZ_SEARCH_STORE_INFO_NEXT_PAGE";
		$shuffle[16] = "PACKET_CZ_SEARCH_STORE_INFO";
		$shuffle[17] = "PACKET_CZ_REQ_TRADE_BUYING_STORE";
		$shuffle[18] = "PACKET_CZ_REQ_CLICK_TO_BUYING_STORE";
		$shuffle[19] = "PACKET_CZ_REQ_CLOSE_BUYING_STORE";
		$shuffle[20] = "PACKET_CZ_REQ_OPEN_BUYING_STORE";
		$shuffle[21] = "PACKET_CZ_PARTY_BOOKING_REQ_REGISTER";
		$shuffle[22] = "PACKET_CZ_JOIN_BATTLE_FIELD";
		$shuffle[23] = "PACKET_CZ_ITEMLISTWIN_RES";
		$shuffle[24] = "PACKET_CZ_ENTER2";
		$shuffle[25] = "PACKET_CZ_PARTY_JOIN_REQ";
		$shuffle[26] = "PACKET_CZ_GANGSI_RANK";
		$shuffle[27] = "PACKET_CZ_ADD_FRIENDS";
		$shuffle[28] = "PACKET_CZ_COMMAND_MER";
		$shuffle[29] = "PACKET_CZ_ACK_STORE_PASSWORD";
	
		$this->echo_save("\nPacket Length Tables -\n");
		$lengths = glob("./data/packet/{plen*.txt,recvpackets*.txt}", GLOB_BRACE);
		if (sizeof($lengths) == 0) {
			die("Place packet lengths inside the data/packet folder\n");
		}
		foreach ($lengths as $i => $length) {
			$this->echo_save(" " . $i . ": " . basename($length,".txt") . "\r\n");
		}
		fwrite(STDOUT, "\nWhich plen to use? ");
		$choice = trim(fgets(STDIN));
		if (isset($lengths[$choice])) {
			$length = $lengths[$choice];
			$shuffle_id = 0;
			$starttime = microtime(true);
			$txtfile = fopen($length, 'r') or exit("Unable to open $length");
			
			while (!feof($txtfile)) {
				$line = fgets($txtfile);
				
				if(preg_match('/(.*),(.*)/', $line, $regs)) {
					$this->p_lens[$regs[1]] = trim($regs[2]);
					if($shuffle_id && $shuffle_id < 30){
						$this->p_funcs[$regs[1]] = trim($shuffle[$shuffle_id]);
						//$this->echo_save("Re-Mapped $regs[1] to $shuffle[$shuffle_id]\r\n");
						$shuffle_id++;
					}
				}
				
				if(preg_match('/## New Table ##/', $line, $regs)) {
					$shuffle_id = 1;
					$this->echo_save(" -= Re-Mapped Shuffled Packet_ID's =-\r\n");
				}
				
				if (preg_match('/Encryption:(.*),(.*),(.*);/s', $line, $regs)) {
					$this->echo_save(" -= Packet_ID Encryption Keys Loaded =-\r\n");
					$this->enc_key1_ = hexdec($regs[1]);
					$this->enc_key2_ = hexdec($regs[2]);
					$this->enc_key3_ = hexdec($regs[3]);
				}
			}
			fclose($txtfile);
			$totaltime = microtime(true) - $starttime;
			$this->echo_save(str_pad("load_plen($length)", 34, " ")." Time: " . round($totaltime, 3) . "s\n");
			
		} else {
			die("Bad choice\n");
		}
	}
	
	function load_input($folder, $file, $name) {
		$this->echo_save("\n$name Packet Captures -\n");
		$caps = glob("./$folder/$file");
		if (sizeof($caps) == 0)
			die("Place packet captures inside the $folder folder\n");
		foreach ($caps as $i => $cap) {
			$this->echo_save($i . ": " . basename($cap) . "\n");
		}
		fwrite(STDOUT, "\nParse which capture? ");
		$choice = trim(fgets(STDIN));
		if (isset($caps[$choice])) {
			return $caps[$choice];
		} else {
			die("Bad choice\n");
		}
	}
	
	function load_mode() {
		$this->echo_save("\nPacket Analyze Modes -\n");
		$modes = glob("./mode/*.php");
		if (sizeof($modes) == 0) {
			die("Place modes inside the mode folder\n");
		}
		foreach ($modes as $i => $mode) {
			$this->echo_save(" " . $i . ": " . basename($mode,".php") . "\r\n");
		}
		fwrite(STDOUT, "\nWhich mode to use? ");
		$choice = trim(fgets(STDIN));
		if (isset($modes[$choice])) {
			$mode = $modes[$choice];
			require_once($mode);
			if(function_exists('PP_MODE_INIT')) {
				PP_MODE_INIT($this); // initialize mode settings
			}
		} else {
			die("Bad choice\n");
		}
	}
	
	function byte($pointer = null) {
		if($pointer) {
			$data = $this->unpack2("C", substr($this->packet, $pointer, 1));
		} else {
			$data = $this->unpack2("C", substr($this->packet, $this->packet_pointer, 1));
			$this->packet_pointer += 1;
		}
		return $data;
	}

	function word($pointer = null) {
		if($pointer) {
			$data = $this->unpack2("S", substr($this->packet, $pointer, 2));
		} else {
			$data = $this->unpack2("S", substr($this->packet, $this->packet_pointer, 2));
			$this->packet_pointer += 2;
		}
		return $data;
	}

	function long($pointer = null) {
		if($pointer) {
			$data = $this->unpack2("L", substr($this->packet, $pointer, 4));
		} else {
			$data = $this->unpack2("L", substr($this->packet, $this->packet_pointer, 4));
			$this->packet_pointer += 4;
		}
		return $data;
	}

	function string($len, $pointer = null) {
		if($pointer) {
			$data1 = substr($this->packet, $pointer, $len);
		} else {
			$data1 = substr($this->packet, $this->packet_pointer, $len);
			$this->packet_pointer += $len;
		}
		$data2 = explode("\0", $data1);  // do not return after null char 00 :)
		$data3 = trim($data2[0]);
		return $data3;
	}

	function ip($pointer = null) {
		if($pointer) {
			$data = long2ip($this->unpack2("L", substr($this->packet, $pointer, 4)));
		} else {
			$data = long2ip($this->unpack2("L", substr($this->packet, $this->packet_pointer, 4)));
			$this->packet_pointer += 4;
		}
		return $data;
	}
	
	function unixtime($pointer = null) {
		if($pointer) {
			$data = $this->unpack2("L", substr($this->packet, $pointer, 4));
		} else {
			$data = $this->unpack2("L", substr($this->packet, $this->packet_pointer, 4));
			$this->packet_pointer += 4;
		}
		$data = date(DATE_ATOM, $data);
		return $data;
	}

	function xyxy($pointer = null) {
		if($pointer) {
			$bin = substr($this->packet, $pointer, 6);
		} else {
			$bin = substr($this->packet, $this->packet_pointer, 6);
			$this->packet_pointer += 6;
		}
		$X = $this->get_val($bin, 0);
		$Y = $this->get_val($bin, 1);
		$X2 = $this->get_val($bin, 2);
		$Y2 = $this->get_val($bin, 3);
		$temp = "$X,$Y to $X2,$Y2";
		return $temp;
	}

	function xy($pointer = null) {
		if($pointer) {
			$bin = substr($this->packet, $pointer, 3);
		} else {
			$bin = substr($this->packet, $this->packet_pointer, 3);
			$this->packet_pointer += 3;
		}
		$X = $this->get_val($bin, 0);
		$Y = $this->get_val($bin, 1);
		$temp = "$X,$Y";
		return $temp;
	}
	
	function get_val(&$bin, $startbyte) {
		$startbit = $startbyte * 2;
		return ((((ord($bin{$startbyte}) << $startbit) & 0xFF) >> $startbit) << (2 + $startbit)) | (ord($bin{$startbyte + 1}) >> (6 - $startbit));
		// mindfuck O_O
	}
	
	function unpack2($format, $string) {
		// custom unpack();
		// returns value if only a single element in array
		$temp = unpack($format, $string);
		if(count($temp) == 1) {
			return $temp[1];
		} else {
			return $temp;
		}
	}
	
	function decryptMessageID($messageID){
		// saving last information for debug log
		$oldmid = $messageID;
		$oldkey = ($this->enc_key1 >> 16) & 0x7FFF;
		
		// calculating the encryption key
		$messageID = hexdec($messageID);
		$this->enc_key1 = ($this->enc_key1 * $this->enc_key2 + $this->enc_key3) & 0xFFFFFFFF;
		
		// xoring the message id
		$messageID = ($messageID ^ (($this->enc_key1 >> 16) & 0x7FFF)) & 0xFFFF;
		
		$messageID = strtoupper(str_pad(dechex($messageID),4,"0",STR_PAD_LEFT)); // sting format to allow array lookup
		$this->echo_save("$this->nl Encrypted MID : $oldmid -> $messageID \n");
		return $messageID;
	}
	
	function parse_stream() {
		// Get packet Direction from begining of stream
		if($this->debug) {
			fwrite($this->packet_log, bin2hex($this->stream) . "\n");
		}
		if(substr($this->stream,0,2) == "RR") {
			$this->packet_dir = "R";
			$this->stream = substr($this->stream,2);
			if(!strlen($this->stream))
				return;
		} elseif(substr($this->stream,0,2) == "SS") {
			$this->packet_dir = "S";
			$this->stream = substr($this->stream,2);
			if(!strlen($this->stream))
				return;
		}
		// Check for a partial packet from previous stream
		if($this->prev_packet && $this->packet_dir == $this->prev_packet_dir) {
			//echo "previous partial packet pre-concatenated\n";
			$this->stream = $this->prev_packet . $this->stream;
			$this->prev_packet = false;
			$this->prev_packet_dir = false;
		}
		// increase packet number, and format for output
		$this->packet_num = str_pad(++$this->packet_num, 3, "0", STR_PAD_LEFT);
		
		while(strlen($this->stream)) {
			// take packet id from packet, and format for array lookup
			$this->packet_id = str_pad(strtoupper(dechex($this->unpack2("S", $this->stream))),4,"0",STR_PAD_LEFT);
			
			// next packet is ZC
			if($this->packet_id == "5252") { // RR
				$this->packet_dir = "R";
				$this->stream = substr($this->stream, 2);
				continue;
			}
			// next packet is CZ
			if($this->packet_id == "5353") { // SS
				$this->packet_dir = "S";
				$this->stream = substr($this->stream, 2);
				continue;
			}
			// catch this stupid Account ID aegis sends
			if(!$this->aid_packet && $this->aid && $this->unpack2("L", $this->stream) == $this->aid) {
				if(function_exists('PP_AEGIS_GID')) {
					PP_AEGIS_GID($this);
				}
				$this->aid_packet = true; //aid packet has been caught, 
				$this->stream = substr($this->stream, 4);
				continue;
			}
			// Store Account_ID for checking
			if(!$this->aid && $this->packet_id == "0069") {
				$this->aid = $this->unpack2("@8/L", $this->stream);
			}
			
			if($this->enc_state && $this->packet_dir == "S") {
				$this->packet_id = $this->decryptMessageID($this->packet_id);
			}
			
			if(!$this->enc_state && $this->packet_id == "0071") {
				$this->enc_key1 = $this->enc_key1_;
				$this->enc_key2 = $this->enc_key2_;
				$this->enc_key3 = $this->enc_key3_;
				$this->enc_state = 1;
				$this->echo_save("$this->nl Encryption Started\n");
			}
			
			
			// ####
			if(array_key_exists($this->packet_id, $this->p_lens)) {
				$this->packet_length = $this->p_lens[$this->packet_id];
				if($this->packet_length == "0" || $this->packet_length == "-1") {
					// Get packet length from packet
					$this->packet_length = $this->unpack2("@2/S", $this->stream);
				}
				//echo "#".strlen($this->stream)."#".$this->packet_length."#\n";
				if(strlen($this->stream) < $this->packet_length) {
					// Packet is not complete
					if(function_exists('PP_PACKET_SPLIT')) {
						PP_PACKET_SPLIT($this); // output data of split packet
					}
					$this->prev_packet = $this->stream;
					$this->prev_packet_dir = $this->packet_dir;
					break;
				}
				
				// copy and remove single packet from stream
				$this->packet = substr($this->stream,0,$this->packet_length);
				$this->stream = substr($this->stream,$this->packet_length);
				
				if(!array_key_exists($this->packet_id, $this->p_funcs)) {
					$this->p_funcs[$this->packet_id] = "PP_FUNC_NOT_DEFINED";
				}
				// packet_desc should be made in mode/full_info.php - but here is fine for now
				$this->packet_desc = str_pad($this->p_funcs[$this->packet_id], 50, " ");
				if(!$this->packet_dir)
					$this->packet_dir = " ";
				$this->packet_desc = "| $this->packet_num |  $this->packet_dir  | $this->packet_id | $this->packet_desc |";
				$this->packet_pointer = 2; // packet_id // pointer used for extra byte checking
				if(function_exists($this->p_funcs[$this->packet_id])) {
					if(function_exists('PP_TIME_OUTPUT') && $this->mode["time_output"]) {
						PP_TIME_OUTPUT($this);
					}
					$this->p_funcs[$this->packet_id]($this);
					if($this->mode["extra_bytes"]) {
						$this->end_packet();
					}
				}
			} else {
				// cannot find packet length
				//die("Packet length not found for $this->packet_id\nMake sure data/packet/plen is correct for client\n\n");
				if(function_exists('PP_PLEN_ERROR')) {
					PP_PLEN_ERROR($this);
				}
				return;
			}
		}
		if(function_exists("PP_LINE_BREAK")) {
			PP_LINE_BREAK($this); // echo a line break
		}
	}
}
?>