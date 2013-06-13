<?php
// packet_parser functions
function PP_MODE_INIT($parser) {
	$parser->mode["mode_name"] = "full_info";	//
	$parser->mode["extra_bytes"] = true;		// warning about extra packet data
	$parser->mode["time_output"] = false;		// echo time after every packet
	$parser->mode["time_started"] = false;		// 
	
	$parser->nl = "|     |     |      |                                                    |";
	$parser->br = "|.....|.....|......|....................................................|...............................\n";
	

	if($parser->mode["time_output"]){
		$parser->mode["start_time"] = microtime(true);
	}
}

function PP_FUNC_NOT_DEFINED($parser) {
	$parser->echo_save($parser->packet_desc . "\n");
}

function PP_AEGIS_GID($parser) {
	if(!$parser->packet_dir) {
		$parser->packet_dir = " ";
	}
	$parser->echo_save("| $parser->packet_num |  $parser->packet_dir  |      | Account_ID\n");
}

function PP_PLEN_ERROR($parser) {
	$remainder = strlen($parser->stream);
	$parser->echo_save("| $parser->packet_num |     | $parser->packet_id | Packet_ID Not Found                                | Skipping $remainder Bytes \n");
	$parser->echo_save($parser->br);
}

function PP_PACKET_SPLIT($parser) {
	if(!$parser->packet_dir) {
		$parser->packet_dir = " ";
	}
	$parser->echo_save("| $parser->packet_num |  $parser->packet_dir  | $parser->packet_id | Packet Not Complete                                |\n");
}

function PP_LINE_BREAK($parser) {
	$parser->echo_save($parser->br);
}

function PP_TIME_OUTPUT($parser) {
	if(!$parser->mode["time_started"]) {
		$parser->mode["time_started"] = true;
		$parser->mode["start_time"] = microtime(true);
	}
	$packet_time = microtime(true) - $parser->mode["start_time"];
	list($usec, $sec) = explode(" ", microtime());
	$parser->echo_save("| The next packet at ".$packet_time."  -   ".$sec."  \n");
	$parser->echo_save($parser->br);
}

function PP_ENTRY_TEXT($parser) {
	$parser->echo_save("T-----T-----T------T----------------------------------------------------T----------------------------------------------T\n");
	$parser->echo_save("| Num | Way |  ID  | Packet description                                 | Extra information                             \n");
	$parser->echo_save("I-----I-----I------I----------------------------------------------------I----------------------------------------------I\n");
}

// packet 0x64
function PACKET_CA_LOGIN($parser) {
	$parser->echo_save($parser->packet_desc . "Version=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "ID=".$parser->string(24) . "\n");
	$parser->echo_save($parser->nl . "Passwd=".$parser->string(24) . "\n");
	$parser->echo_save($parser->nl . "clienttype=".$parser->byte() . "\n");
}

// packet 0x65
function PACKET_CH_ENTER($parser) {
	$parser->echo_save($parser->packet_desc . "AID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "AuthCode=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "userLevel=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "clientType=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "Sex=".$parser->byte() . "\n");
}

// packet 0x66
function PACKET_CH_SELECT_CHAR($parser) {
	$parser->echo_save($parser->packet_desc . "CharNum=".$parser->byte() . "\n");
}

// packet 0x67
function PACKET_CH_MAKE_CHAR($parser) {
	$parser->echo_save($parser->packet_desc . "name=".$parser->string(24) . "\n");
	$parser->echo_save($parser->nl . "Str=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "Agi=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "Vit=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "Int=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "Dex=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "Luk=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "CharNum=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "headPal=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "head=".$parser->word() . "\n");
}

// packet 0x68
function PACKET_CH_DELETE_CHAR($parser) {
	$parser->echo_save($parser->packet_desc . "GID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "key=".$parser->string(40) . "\n");
}

// packet 0x69
function PACKET_AC_ACCEPT_LOGIN($parser) {
	$parser->echo_save($parser->packet_desc . "PacketLength=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "AuthCode=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "AID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "userLevel=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "lastLoginIP=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "lastLoginTime=".$parser->string(26) . "\n");
	$parser->echo_save($parser->nl . "Sex=".$parser->byte() . "\n");
	$ServerList = ($parser->packet_length - $parser->packet_pointer) / 32;
	for ($i = 0; $i < $ServerList; $i++) {
		$parser->echo_save($parser->nl . "ip=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "port=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "name=".$parser->string(20) . "\n");
		$parser->echo_save($parser->nl . "usercount=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "state=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "property=".$parser->word() . "\n");
	}
}

// packet 0x6a
function PACKET_AC_REFUSE_LOGIN($parser) {
	$parser->echo_save($parser->packet_desc . "ErrorCode=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "blockDate=".$parser->string(20) . "\n");
}

// packet 0x6b
function PACKET_HC_ACCEPT_ENTER_NEO_UNION($parser) {
	$parser->echo_save($parser->packet_desc . "PacketLength=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "TotalSlotNum=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "PremiumStartSlot=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "PremiumEndSlot=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "dummy1_beginbilling=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "code=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "time1=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "time2=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "dummy2_endbilling=".$parser->string(7) . "\n");
	$charInfo = ($parser->packet_length - $parser->packet_pointer) / 144;
	for ($i = 0; $i < $charInfo; $i++) {
		$parser->echo_save($parser->nl . "GID=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "exp=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "money=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "jobexp=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "joblevel=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "bodystate=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "healthstate=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "effectstate=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "virtue=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "honor=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "jobpoint=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "hp=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "maxhp=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "sp=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "maxsp=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "speed=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "job=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "head=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "weapon=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "level=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "sppoint=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "accessory=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "shield=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "accessory2=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "accessory3=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "headpalette=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "bodypalette=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "name=".$parser->string(24) . "\n");
		$parser->echo_save($parser->nl . "Str=".$parser->byte() . "\n");
		$parser->echo_save($parser->nl . "Agi=".$parser->byte() . "\n");
		$parser->echo_save($parser->nl . "Vit=".$parser->byte() . "\n");
		$parser->echo_save($parser->nl . "Int=".$parser->byte() . "\n");
		$parser->echo_save($parser->nl . "Dex=".$parser->byte() . "\n");
		$parser->echo_save($parser->nl . "Luk=".$parser->byte() . "\n");
		$parser->echo_save($parser->nl . "CharNum=".$parser->byte() . "\n");
		$parser->echo_save($parser->nl . "haircolor=".$parser->byte() . "\n");
		$parser->echo_save($parser->nl . "bIsChangedCharName=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "lastMap=".$parser->string(16) . "\n");
		$parser->echo_save($parser->nl . "DeleteDate=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "Robe=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "SlotAddon=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "RenameAddon=".$parser->long() . "\n");
	}
}

// packet 0x6c
function PACKET_HC_REFUSE_ENTER($parser) {
	$parser->echo_save($parser->packet_desc . "ErrorCode=".$parser->byte() . "\n");
}

// packet 0x6d
function PACKET_HC_ACCEPT_MAKECHAR_NEO_UNION($parser) {
	$parser->echo_save($parser->packet_desc  . "\n");
		$parser->echo_save($parser->nl . "GID=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "exp=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "money=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "jobexp=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "joblevel=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "bodystate=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "healthstate=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "effectstate=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "virtue=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "honor=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "jobpoint=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "hp=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "maxhp=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "sp=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "maxsp=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "speed=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "job=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "head=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "weapon=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "level=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "sppoint=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "accessory=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "shield=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "accessory2=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "accessory3=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "headpalette=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "bodypalette=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "name=".$parser->string(24) . "\n");
		$parser->echo_save($parser->nl . "Str=".$parser->byte() . "\n");
		$parser->echo_save($parser->nl . "Agi=".$parser->byte() . "\n");
		$parser->echo_save($parser->nl . "Vit=".$parser->byte() . "\n");
		$parser->echo_save($parser->nl . "Int=".$parser->byte() . "\n");
		$parser->echo_save($parser->nl . "Dex=".$parser->byte() . "\n");
		$parser->echo_save($parser->nl . "Luk=".$parser->byte() . "\n");
		$parser->echo_save($parser->nl . "CharNum=".$parser->byte() . "\n");
		$parser->echo_save($parser->nl . "haircolor=".$parser->byte() . "\n");
		$parser->echo_save($parser->nl . "bIsChangedCharName=".$parser->word() . "\n");
}

// packet 0x6e
function PACKET_HC_REFUSE_MAKECHAR($parser) {
	$parser->echo_save($parser->packet_desc . "ErrorCode=".$parser->byte() . "\n");
}

// packet 0x6f
function PACKET_HC_ACCEPT_DELETECHAR($parser) {
	$parser->echo_save($parser->packet_desc . "\n");
}

// packet 0x70
function PACKET_HC_REFUSE_DELETECHAR($parser) {
	$parser->echo_save($parser->packet_desc . "ErrorCode=".$parser->byte() . "\n");
}

// packet 0x71
function PACKET_HC_NOTIFY_ZONESVR($parser) {
	$parser->echo_save($parser->packet_desc . "GID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "mapName=".$parser->string(16) . "\n");
		$parser->echo_save($parser->nl . "ip=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "port=".$parser->word() . "\n");
}

// packet 0x72
function PACKET_CZ_ENTER($parser) {
	$parser->echo_save($parser->packet_desc . "AID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "GID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "AuthCode=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "clientTime=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "Sex=".$parser->byte() . "\n");
}

// packet 0x73
function PACKET_ZC_ACCEPT_ENTER($parser) {
	$parser->echo_save($parser->packet_desc . "startTime=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "PosDir=".$parser->string(3) . "\n");
	$parser->echo_save($parser->nl . "xSize=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "ySize=".$parser->byte() . "\n");
}

// packet 0x74
function PACKET_ZC_REFUSE_ENTER($parser) {
	$parser->echo_save($parser->packet_desc . "ErrorCode=".$parser->byte() . "\n");
}

// packet 0x75
function PACKET_ZC_NOTIFY_INITCHAR($parser) {
	$parser->echo_save($parser->packet_desc . "PacketLength=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "GID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "Style=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "Item=".$parser->byte() . "\n");
}

// packet 0x76
function PACKET_ZC_NOTIFY_UPDATECHAR($parser) {
	$parser->echo_save($parser->packet_desc . "GID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "Style=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "Item=".$parser->byte() . "\n");
}

// packet 0x77
function PACKET_ZC_NOTIFY_UPDATEPLAYER($parser) {
	$parser->echo_save($parser->packet_desc . "Style=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "Item=".$parser->byte() . "\n");
}

// packet 0x78
function PACKET_ZC_NOTIFY_STANDENTRY($parser) {
	$parser->echo_save($parser->packet_desc . "objecttype=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "GID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "speed=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "bodyState=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "healthState=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "effectState=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "job=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "head=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "weapon=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "accessory=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "shield=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "accessory2=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "accessory3=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "headpalette=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "bodypalette=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "headDir=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "GUID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "GEmblemVer=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "honor=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "virtue=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "isPKModeON=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "sex=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "PosDir=".$parser->string(3) . "\n");
	$parser->echo_save($parser->nl . "xSize=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "ySize=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "state=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "clevel=".$parser->word() . "\n");
}

// packet 0x79
function PACKET_ZC_NOTIFY_NEWENTRY($parser) {
	$parser->echo_save($parser->packet_desc . "GID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "speed=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "bodyState=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "healthState=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "effectState=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "job=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "head=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "weapon=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "accessory=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "shield=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "accessory2=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "accessory3=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "headpalette=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "bodypalette=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "headDir=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "GUID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "GEmblemVer=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "honor=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "virtue=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "isPKModeON=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "sex=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "PosDir=".$parser->string(3) . "\n");
	$parser->echo_save($parser->nl . "xSize=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "ySize=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "clevel=".$parser->word() . "\n");
}

// packet 0x7a
function PACKET_ZC_NOTIFY_ACTENTRY($parser) {
	$parser->echo_save($parser->packet_desc . "GID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "speed=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "bodyState=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "healthState=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "effectState=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "job=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "head=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "weapon=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "accessory=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "shield=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "accessory2=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "accessory3=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "headpalette=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "bodypalette=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "headDir=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "GUID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "GEmblemVer=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "honor=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "virtue=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "isPKModeON=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "sex=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "PosDir=".$parser->string(3) . "\n");
	$parser->echo_save($parser->nl . "xSize=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "ySize=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "action=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "actStartTime=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "clevel=".$parser->word() . "\n");
}

// packet 0x7b
function PACKET_ZC_NOTIFY_MOVEENTRY($parser) {
	$parser->echo_save($parser->packet_desc . "GID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "speed=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "bodyState=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "healthState=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "effectState=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "job=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "head=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "weapon=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "accessory=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "moveStartTime=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "shield=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "accessory2=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "accessory3=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "headpalette=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "bodypalette=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "headDir=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "GUID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "GEmblemVer=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "honor=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "virtue=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "isPKModeON=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "sex=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "MoveData=".$parser->string(6) . "\n");
	$parser->echo_save($parser->nl . "xSize=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "ySize=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "clevel=".$parser->word() . "\n");
}

// packet 0x7c
function PACKET_ZC_NOTIFY_STANDENTRY_NPC($parser) {
	$parser->echo_save($parser->packet_desc . "objecttype=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "GID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "speed=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "bodyState=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "healthState=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "effectState=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "head=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "weapon=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "accessory=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "job=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "shield=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "accessory2=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "accessory3=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "headpalette=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "bodypalette=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "headDir=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "isPKModeON=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "sex=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "PosDir=".$parser->string(3) . "\n");
	$parser->echo_save($parser->nl . "xSize=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "ySize=".$parser->byte() . "\n");
}

// packet 0x7d
function PACKET_CZ_NOTIFY_ACTORINIT($parser) {
	$parser->echo_save($parser->packet_desc . "\n");
}

// packet 0x7e
function PACKET_CZ_REQUEST_TIME($parser) {
	$parser->echo_save($parser->packet_desc . "clientTime=".$parser->long() . "\n");
}

// packet 0x7f
function PACKET_ZC_NOTIFY_TIME($parser) {
	$parser->echo_save($parser->packet_desc . "time=".$parser->long() . "\n");
}

// packet 0x80
function PACKET_ZC_NOTIFY_VANISH($parser) {
	$parser->echo_save($parser->packet_desc . "GID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "type=".$parser->byte() . "\n");
}

// packet 0x81
function PACKET_SC_NOTIFY_BAN($parser) {
	$parser->echo_save($parser->packet_desc . "ErrorCode=".$parser->byte() . "\n");
}

// packet 0x82
function PACKET_CZ_REQUEST_QUIT($parser) {
	$parser->echo_save($parser->packet_desc . "\n");
}

// packet 0x83
function PACKET_ZC_ACCEPT_QUIT($parser) {
	$parser->echo_save($parser->packet_desc . "\n");
}

// packet 0x84
function PACKET_ZC_REFUSE_QUIT($parser) {
	$parser->echo_save($parser->packet_desc . "\n");
}

// packet 0x85
function PACKET_CZ_REQUEST_MOVE($parser) {
	$parser->echo_save($parser->packet_desc . "dest=".$parser->string(3) . "\n");
}

// packet 0x86
function PACKET_ZC_NOTIFY_MOVE($parser) {
	$parser->echo_save($parser->packet_desc . "GID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "MoveData=".$parser->string(6) . "\n");
	$parser->echo_save($parser->nl . "moveStartTime=".$parser->long() . "\n");
}

// packet 0x87
function PACKET_ZC_NOTIFY_PLAYERMOVE($parser) {
	$parser->echo_save($parser->packet_desc . "moveStartTime=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "MoveData=".$parser->string(6) . "\n");
}

// packet 0x88
function PACKET_ZC_STOPMOVE($parser) {
	$parser->echo_save($parser->packet_desc . "AID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "xPos=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "yPos=".$parser->word() . "\n");
}

// packet 0x89
function PACKET_CZ_REQUEST_ACT($parser) {
	$parser->echo_save($parser->packet_desc . "targetGID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "action=".$parser->byte() . "\n");
}

// packet 0x8a
function PACKET_ZC_NOTIFY_ACT($parser) {
	$parser->echo_save($parser->packet_desc . "GID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "targetGID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "startTime=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "attackMT=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "attackedMT=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "damage=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "count=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "action=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "leftDamage=".$parser->word() . "\n");
}

// packet 0x8b
function PACKET_ZC_NOTIFY_ACT_POSITION($parser) {
	$parser->echo_save($parser->packet_desc . "GID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "targetGID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "startTime=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "xPos=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "yPos=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "damage=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "count=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "action=".$parser->byte() . "\n");
}

// packet 0x8c
function PACKET_CZ_REQUEST_CHAT($parser) {
	$parser->echo_save($parser->packet_desc . "PacketLength=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "msg=".$parser->string($parser->packet_length - $parser->packet_pointer) . "\n");
}

// packet 0x8d
function PACKET_ZC_NOTIFY_CHAT($parser) {
	$parser->echo_save($parser->packet_desc . "PacketLength=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "GID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "msg=".$parser->string($parser->packet_length - $parser->packet_pointer) . "\n");
}

// packet 0x8e
function PACKET_ZC_NOTIFY_PLAYERCHAT($parser) {
	$parser->echo_save($parser->packet_desc . "PacketLength=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "msg=".$parser->string($parser->packet_length - $parser->packet_pointer) . "\n");
}

// packet 0x8f
function PACKET_SERVER_ENTRY_ACK($parser) {
	$parser->echo_save($parser->packet_desc . "Header=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "AID=".$parser->long() . "\n");
}

// packet 0x90
function PACKET_CZ_CONTACTNPC($parser) {
	$parser->echo_save($parser->packet_desc . "NAID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "type=".$parser->byte() . "\n");
}

// packet 0x91
function PACKET_ZC_NPCACK_MAPMOVE($parser) {
	$parser->echo_save($parser->packet_desc . "mapName=".$parser->string(16) . "\n");
	$parser->echo_save($parser->nl . "xPos=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "yPos=".$parser->word() . "\n");
}

// packet 0x92
function PACKET_ZC_NPCACK_SERVERMOVE($parser) {
	$parser->echo_save($parser->packet_desc . "mapName=".$parser->string(16) . "\n");
	$parser->echo_save($parser->nl . "xPos=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "yPos=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "ip=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "port=".$parser->word() . "\n");
}

// packet 0x93
function PACKET_ZC_NPCACK_ENABLE($parser) {
	$parser->echo_save($parser->packet_desc . "\n");
}

// packet 0x94
function PACKET_CZ_REQNAME($parser) {
	$parser->echo_save($parser->packet_desc . "AID=".$parser->long() . "\n");
}

// packet 0x95
function PACKET_ZC_ACK_REQNAME($parser) {
	$parser->echo_save($parser->packet_desc . "AID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "CName=".$parser->string(24) . "\n");
}

// packet 0x96
function PACKET_CZ_WHISPER($parser) {
	$parser->echo_save($parser->packet_desc . "PacketLength=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "receiver=".$parser->string(24) . "\n");
	$parser->echo_save($parser->nl . "msg=".$parser->string($parser->packet_length - $parser->packet_pointer) . "\n");
}

// packet 0x97
function PACKET_ZC_WHISPER($parser) {
	$parser->echo_save($parser->packet_desc . "PacketLength=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "sender=".$parser->string(24) . "\n");
	$parser->echo_save($parser->nl . "msg=".$parser->string($parser->packet_length - $parser->packet_pointer) . "\n");
}

// packet 0x98
function PACKET_ZC_ACK_WHISPER($parser) {
	$parser->echo_save($parser->packet_desc . "result=".$parser->byte() . "\n");
}

// packet 0x99
function PACKET_CZ_BROADCAST($parser) {
	$parser->echo_save($parser->packet_desc . "PacketLength=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "msg=".$parser->string($parser->packet_length - $parser->packet_pointer) . "\n");
}

// packet 0x9a
function PACKET_ZC_BROADCAST($parser) {
	$parser->echo_save($parser->packet_desc . "PacketLength=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "msg=".$parser->string($parser->packet_length - $parser->packet_pointer) . "\n");
}

// packet 0x9b
function PACKET_CZ_CHANGE_DIRECTION($parser) {
	$parser->echo_save($parser->packet_desc . "headDir=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "dir=".$parser->byte() . "\n");
}

// packet 0x9c
function PACKET_ZC_CHANGE_DIRECTION($parser) {
	$parser->echo_save($parser->packet_desc . "AID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "headDir=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "dir=".$parser->byte() . "\n");
}

// packet 0x9d
function PACKET_ZC_ITEM_ENTRY($parser) {
	$parser->echo_save($parser->packet_desc . "ITAID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "ITID=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "IsIdentified=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "xPos=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "yPos=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "count=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "subX=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "subY=".$parser->byte() . "\n");
}

// packet 0x9e
function PACKET_ZC_ITEM_FALL_ENTRY($parser) {
	$parser->echo_save($parser->packet_desc . "ITAID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "ITID=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "IsIdentified=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "xPos=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "yPos=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "subX=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "subY=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "count=".$parser->word() . "\n");
}

// packet 0x9f
function PACKET_CZ_ITEM_PICKUP($parser) {
	$parser->echo_save($parser->packet_desc . "ITAID=".$parser->long() . "\n");
}

// packet 0xa0
function PACKET_ZC_ITEM_PICKUP_ACK($parser) {
	$parser->echo_save($parser->packet_desc . "Index=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "count=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "ITID=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "IsIdentified=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "IsDamaged=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "refiningLevel=".$parser->byte() . "\n");
		$parser->echo_save($parser->nl . "card1=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "card2=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "card3=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "card4=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "location=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "type=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "result=".$parser->byte() . "\n");
}

// packet 0xa1
function PACKET_ZC_ITEM_DISAPPEAR($parser) {
	$parser->echo_save($parser->packet_desc . "ITAID=".$parser->long() . "\n");
}

// packet 0xa2
function PACKET_CZ_ITEM_THROW($parser) {
	$parser->echo_save($parser->packet_desc . "Index=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "count=".$parser->word() . "\n");
}

// packet 0xa3
function PACKET_ZC_NORMAL_ITEMLIST($parser) {
	$parser->echo_save($parser->packet_desc . "PacketLength=".$parser->word() . "\n");
	$itemInfo = ($parser->packet_length - $parser->packet_pointer) / 10;
	for ($i = 0; $i < $itemInfo; $i++) {
		$parser->echo_save($parser->nl . "index=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "ITID=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "type=".$parser->byte() . "\n");
		$parser->echo_save($parser->nl . "IsIdentified=".$parser->byte() . "\n");
		$parser->echo_save($parser->nl . "count=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "WearState=".$parser->word() . "\n");
	}
}

// packet 0xa4
function PACKET_ZC_EQUIPMENT_ITEMLIST($parser) {
	$parser->echo_save($parser->packet_desc . "PacketLength=".$parser->word() . "\n");
	$itemInfo = ($parser->packet_length - $parser->packet_pointer) / 20;
	for ($i = 0; $i < $itemInfo; $i++) {
		$parser->echo_save($parser->nl . "index=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "ITID=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "type=".$parser->byte() . "\n");
		$parser->echo_save($parser->nl . "IsIdentified=".$parser->byte() . "\n");
		$parser->echo_save($parser->nl . "location=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "WearState=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "IsDamaged=".$parser->byte() . "\n");
		$parser->echo_save($parser->nl . "RefiningLevel=".$parser->byte() . "\n");
		$parser->echo_save($parser->nl . "card1=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "card2=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "card3=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "card4=".$parser->word() . "\n");
	}
}

// packet 0xa5
function PACKET_ZC_STORE_NORMAL_ITEMLIST($parser) {
	$parser->echo_save($parser->packet_desc . "PacketLength=".$parser->word() . "\n");
	$itemInfo = ($parser->packet_length - $parser->packet_pointer) / 10;
	for ($i = 0; $i < $itemInfo; $i++) {
		$parser->echo_save($parser->nl . "index=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "ITID=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "type=".$parser->byte() . "\n");
		$parser->echo_save($parser->nl . "IsIdentified=".$parser->byte() . "\n");
		$parser->echo_save($parser->nl . "count=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "WearState=".$parser->word() . "\n");
	}
}

// packet 0xa6
function PACKET_ZC_STORE_EQUIPMENT_ITEMLIST($parser) {
	$parser->echo_save($parser->packet_desc . "PacketLength=".$parser->word() . "\n");
	$itemInfo = ($parser->packet_length - $parser->packet_pointer) / 20;
	for ($i = 0; $i < $itemInfo; $i++) {
		$parser->echo_save($parser->nl . "index=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "ITID=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "type=".$parser->byte() . "\n");
		$parser->echo_save($parser->nl . "IsIdentified=".$parser->byte() . "\n");
		$parser->echo_save($parser->nl . "location=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "WearState=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "IsDamaged=".$parser->byte() . "\n");
		$parser->echo_save($parser->nl . "RefiningLevel=".$parser->byte() . "\n");
		$parser->echo_save($parser->nl . "card1=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "card2=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "card3=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "card4=".$parser->word() . "\n");
	}
}

// packet 0xa7
function PACKET_CZ_USE_ITEM($parser) {
	$parser->echo_save($parser->packet_desc . "index=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "AID=".$parser->long() . "\n");
}

// packet 0xa8
function PACKET_ZC_USE_ITEM_ACK($parser) {
	$parser->echo_save($parser->packet_desc . "index=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "count=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "result=".$parser->byte() . "\n");
}

// packet 0xa9
function PACKET_CZ_REQ_WEAR_EQUIP($parser) {
	$parser->echo_save($parser->packet_desc . "index=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "wearLocation=".$parser->word() . "\n");
}

// packet 0xaa
function PACKET_ZC_REQ_WEAR_EQUIP_ACK($parser) {
	$parser->echo_save($parser->packet_desc . "index=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "wearLocation=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "wItemSpriteNumber=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "result=".$parser->byte() . "\n");
}

// packet 0xab
function PACKET_CZ_REQ_TAKEOFF_EQUIP($parser) {
	$parser->echo_save($parser->packet_desc . "index=".$parser->word() . "\n");
}

// packet 0xac
function PACKET_ZC_REQ_TAKEOFF_EQUIP_ACK($parser) {
	$parser->echo_save($parser->packet_desc . "index=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "wearLocation=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "result=".$parser->byte() . "\n");
}

// packet 0xaf
function PACKET_ZC_ITEM_THROW_ACK($parser) {
	$parser->echo_save($parser->packet_desc . "Index=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "count=".$parser->word() . "\n");
}

// packet 0xb0
function PACKET_ZC_PAR_CHANGE($parser) {
	$parser->echo_save($parser->packet_desc . "varID=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "count=".$parser->long() . "\n");
}

// packet 0xb1
function PACKET_ZC_LONGPAR_CHANGE($parser) {
	$parser->echo_save($parser->packet_desc . "varID=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "amount=".$parser->long() . "\n");
}

// packet 0xb2
function PACKET_CZ_RESTART($parser) {
	$parser->echo_save($parser->packet_desc . "type=".$parser->byte() . "\n");
}

// packet 0xb3
function PACKET_ZC_RESTART_ACK($parser) {
	$parser->echo_save($parser->packet_desc . "type=".$parser->byte() . "\n");
}

// packet 0xb4
function PACKET_ZC_SAY_DIALOG($parser) {
	$parser->echo_save($parser->packet_desc . "PacketLength=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "NAID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "msg=".$parser->string($parser->packet_length - $parser->packet_pointer) . "\n");
}

// packet 0xb5
function PACKET_ZC_WAIT_DIALOG($parser) {
	$parser->echo_save($parser->packet_desc . "NAID=".$parser->long() . "\n");
}

// packet 0xb6
function PACKET_ZC_CLOSE_DIALOG($parser) {
	$parser->echo_save($parser->packet_desc . "NAID=".$parser->long() . "\n");
}

// packet 0xb7
function PACKET_ZC_MENU_LIST($parser) {
	$parser->echo_save($parser->packet_desc . "PacketLength=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "NAID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "msg=".$parser->string($parser->packet_length - $parser->packet_pointer) . "\n");
}

// packet 0xb8
function PACKET_CZ_CHOOSE_MENU($parser) {
	$parser->echo_save($parser->packet_desc . "NAID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "num=".$parser->byte() . "\n");
}

// packet 0xb9
function PACKET_CZ_REQ_NEXT_SCRIPT($parser) {
	$parser->echo_save($parser->packet_desc . "NAID=".$parser->long() . "\n");
}

// packet 0xba
function PACKET_CZ_REQ_STATUS($parser) {
	$parser->echo_save($parser->packet_desc . "\n");
}

// packet 0xbb
function PACKET_CZ_STATUS_CHANGE($parser) {
	$parser->echo_save($parser->packet_desc . "statusID=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "changeAmount=".$parser->byte() . "\n");
}

// packet 0xbc
function PACKET_ZC_STATUS_CHANGE_ACK($parser) {
	$parser->echo_save($parser->packet_desc . "statusID=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "result=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "value=".$parser->byte() . "\n");
}

// packet 0xbd
function PACKET_ZC_STATUS($parser) {
	$parser->echo_save($parser->packet_desc . "point=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "str=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "standardStr=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "agi=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "standardAgi=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "vit=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "standardVit=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "Int=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "standardInt=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "dex=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "standardDex=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "luk=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "standardLuk=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "attPower=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "refiningPower=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "max_mattPower=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "min_mattPower=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "itemdefPower=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "plusdefPower=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "mdefPower=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "plusmdefPower=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "hitSuccessValue=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "avoidSuccessValue=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "plusAvoidSuccessValue=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "criticalSuccessValue=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "ASPD=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "plusASPD=".$parser->word() . "\n");
}

// packet 0xbe
function PACKET_ZC_STATUS_CHANGE($parser) {
	$parser->echo_save($parser->packet_desc . "statusID=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "value=".$parser->byte() . "\n");
}

// packet 0xbf
function PACKET_CZ_REQ_EMOTION($parser) {
	$parser->echo_save($parser->packet_desc . "type=".$parser->byte() . "\n");
}

// packet 0xc0
function PACKET_ZC_EMOTION($parser) {
	$parser->echo_save($parser->packet_desc . "GID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "type=".$parser->byte() . "\n");
}

// packet 0xc1
function PACKET_CZ_REQ_USER_COUNT($parser) {
	$parser->echo_save($parser->packet_desc . "\n");
}

// packet 0xc2
function PACKET_ZC_USER_COUNT($parser) {
	$parser->echo_save($parser->packet_desc . "count=".$parser->long() . "\n");
}

// packet 0xc3
function PACKET_ZC_SPRITE_CHANGE($parser) {
	$parser->echo_save($parser->packet_desc . "GID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "type=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "value=".$parser->byte() . "\n");
}

// packet 0xc4
function PACKET_ZC_SELECT_DEALTYPE($parser) {
	$parser->echo_save($parser->packet_desc . "NAID=".$parser->long() . "\n");
}

// packet 0xc5
function PACKET_CZ_ACK_SELECT_DEALTYPE($parser) {
	$parser->echo_save($parser->packet_desc . "NAID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "type=".$parser->byte() . "\n");
}

// packet 0xc6
function PACKET_ZC_PC_PURCHASE_ITEMLIST($parser) {
	$parser->echo_save($parser->packet_desc . "PacketLength=".$parser->word() . "\n");
	$itemList = ($parser->packet_length - $parser->packet_pointer) / 11;
	for ($i = 0; $i < $itemList; $i++) {
		$parser->echo_save($parser->nl . "price=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "discountprice=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "type=".$parser->byte() . "\n");
		$parser->echo_save($parser->nl . "ITID=".$parser->word() . "\n");
	}
}

// packet 0xc7
function PACKET_ZC_PC_SELL_ITEMLIST($parser) {
	$parser->echo_save($parser->packet_desc . "PacketLength=".$parser->word() . "\n");
	$itemList = ($parser->packet_length - $parser->packet_pointer) / 10;
	for ($i = 0; $i < $itemList; $i++) {
		$parser->echo_save($parser->nl . "index=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "price=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "overchargeprice=".$parser->long() . "\n");
	}
}

// packet 0xc8
function PACKET_CZ_PC_PURCHASE_ITEMLIST($parser) {
	$parser->echo_save($parser->packet_desc . "PacketLength=".$parser->word() . "\n");
	$itemList = ($parser->packet_length - $parser->packet_pointer) / 4;
	for ($i = 0; $i < $itemList; $i++) {
		$parser->echo_save($parser->nl . "count=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "ITID=".$parser->word() . "\n");
	}
}

// packet 0xc9
function PACKET_CZ_PC_SELL_ITEMLIST($parser) {
	$parser->echo_save($parser->packet_desc . "PacketLength=".$parser->word() . "\n");
	$itemList = ($parser->packet_length - $parser->packet_pointer) / 4;
	for ($i = 0; $i < $itemList; $i++) {
		$parser->echo_save($parser->nl . "index=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "count=".$parser->word() . "\n");
	}
}

// packet 0xca
function PACKET_ZC_PC_PURCHASE_RESULT($parser) {
	$parser->echo_save($parser->packet_desc . "result=".$parser->byte() . "\n");
}

// packet 0xcb
function PACKET_ZC_PC_SELL_RESULT($parser) {
	$parser->echo_save($parser->packet_desc . "result=".$parser->byte() . "\n");
}

// packet 0xcc
function PACKET_CZ_DISCONNECT_CHARACTER($parser) {
	$parser->echo_save($parser->packet_desc . "AID=".$parser->long() . "\n");
}

// packet 0xcd
function PACKET_ZC_ACK_DISCONNECT_CHARACTER($parser) {
	$parser->echo_save($parser->packet_desc . "result=".$parser->byte() . "\n");
}

// packet 0xce
function PACKET_CZ_DISCONNECT_ALL_CHARACTER($parser) {
	$parser->echo_save($parser->packet_desc . "\n");
}

// packet 0xcf
function PACKET_CZ_SETTING_WHISPER_PC($parser) {
	$parser->echo_save($parser->packet_desc . "name=".$parser->string(24) . "\n");
	$parser->echo_save($parser->nl . "type=".$parser->byte() . "\n");
}

// packet 0xd0
function PACKET_CZ_SETTING_WHISPER_STATE($parser) {
	$parser->echo_save($parser->packet_desc . "type=".$parser->byte() . "\n");
}

// packet 0xd1
function PACKET_ZC_SETTING_WHISPER_PC($parser) {
	$parser->echo_save($parser->packet_desc . "type=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "result=".$parser->byte() . "\n");
}

// packet 0xd2
function PACKET_ZC_SETTING_WHISPER_STATE($parser) {
	$parser->echo_save($parser->packet_desc . "type=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "result=".$parser->byte() . "\n");
}

// packet 0xd3
function PACKET_CZ_REQ_WHISPER_LIST($parser) {
	$parser->echo_save($parser->packet_desc . "\n");
}

// packet 0xd4
function PACKET_ZC_WHISPER_LIST($parser) {
	$parser->echo_save($parser->packet_desc . "PacketLength=".$parser->word() . "\n");
	$wisperList = ($parser->packet_length - $parser->packet_pointer) / 24;
	for ($i = 0; $i < $wisperList; $i++) {
		$parser->echo_save($parser->nl . "name=".$parser->string(24) . "\n");
	}
}

// packet 0xd5
function PACKET_CZ_CREATE_CHATROOM($parser) {
	$parser->echo_save($parser->packet_desc . "PacketLength=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "size=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "type=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "passwd=".$parser->string(8) . "\n");
	$parser->echo_save($parser->nl . "title=".$parser->string($parser->packet_length - $parser->packet_pointer) . "\n");
}

// packet 0xd6
function PACKET_ZC_ACK_CREATE_CHATROOM($parser) {
	$parser->echo_save($parser->packet_desc . "result=".$parser->byte() . "\n");
}

// packet 0xd7
function PACKET_ZC_ROOM_NEWENTRY($parser) {
	$parser->echo_save($parser->packet_desc . "PacketLength=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "AID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "roomID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "maxcount=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "curcount=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "type=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "title=".$parser->string($parser->packet_length - $parser->packet_pointer) . "\n");
}

// packet 0xd8
function PACKET_ZC_DESTROY_ROOM($parser) {
	$parser->echo_save($parser->packet_desc . "roomID=".$parser->long() . "\n");
}

// packet 0xd9
function PACKET_CZ_REQ_ENTER_ROOM($parser) {
	$parser->echo_save($parser->packet_desc . "roomID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "passwd=".$parser->string(8) . "\n");
}

// packet 0xda
function PACKET_ZC_REFUSE_ENTER_ROOM($parser) {
	$parser->echo_save($parser->packet_desc . "result=".$parser->byte() . "\n");
}

// packet 0xdb
function PACKET_ZC_ENTER_ROOM($parser) {
	$parser->echo_save($parser->packet_desc . "PacketLength=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "roomID=".$parser->long() . "\n");
	$memberList = ($parser->packet_length - $parser->packet_pointer) / 28;
	for ($i = 0; $i < $memberList; $i++) {
		$parser->echo_save($parser->nl . "role=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "name=".$parser->string(24) . "\n");
	}
}

// packet 0xdc
function PACKET_ZC_MEMBER_NEWENTRY($parser) {
	$parser->echo_save($parser->packet_desc . "curcount=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "name=".$parser->string(24) . "\n");
}

// packet 0xdd
function PACKET_ZC_MEMBER_EXIT($parser) {
	$parser->echo_save($parser->packet_desc . "curcount=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "name=".$parser->string(24) . "\n");
	$parser->echo_save($parser->nl . "type=".$parser->byte() . "\n");
}

// packet 0xde
function PACKET_CZ_CHANGE_CHATROOM($parser) {
	$parser->echo_save($parser->packet_desc . "PacketLength=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "size=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "type=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "passwd=".$parser->string(8) . "\n");
	$parser->echo_save($parser->nl . "title=".$parser->string($parser->packet_length - $parser->packet_pointer) . "\n");
}

// packet 0xdf
function PACKET_ZC_CHANGE_CHATROOM($parser) {
	$parser->echo_save($parser->packet_desc . "PacketLength=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "AID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "roomID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "maxcount=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "curcount=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "type=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "title=".$parser->string($parser->packet_length - $parser->packet_pointer) . "\n");
}

// packet 0xe0
function PACKET_CZ_REQ_ROLE_CHANGE($parser) {
	$parser->echo_save($parser->packet_desc . "role=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "name=".$parser->string(24) . "\n");
}

// packet 0xe1
function PACKET_ZC_ROLE_CHANGE($parser) {
	$parser->echo_save($parser->packet_desc . "role=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "name=".$parser->string(24) . "\n");
}

// packet 0xe2
function PACKET_CZ_REQ_EXPEL_MEMBER($parser) {
	$parser->echo_save($parser->packet_desc . "name=".$parser->string(24) . "\n");
}

// packet 0xe3
function PACKET_CZ_EXIT_ROOM($parser) {
	$parser->echo_save($parser->packet_desc . "\n");
}

// packet 0xe4
function PACKET_CZ_REQ_EXCHANGE_ITEM($parser) {
	$parser->echo_save($parser->packet_desc . "AID=".$parser->long() . "\n");
}

// packet 0xe5
function PACKET_ZC_REQ_EXCHANGE_ITEM($parser) {
	$parser->echo_save($parser->packet_desc . "name=".$parser->string(24) . "\n");
}

// packet 0xe6
function PACKET_CZ_ACK_EXCHANGE_ITEM($parser) {
	$parser->echo_save($parser->packet_desc . "result=".$parser->byte() . "\n");
}

// packet 0xe7
function PACKET_ZC_ACK_EXCHANGE_ITEM($parser) {
	$parser->echo_save($parser->packet_desc . "result=".$parser->byte() . "\n");
}

// packet 0xe8
function PACKET_CZ_ADD_EXCHANGE_ITEM($parser) {
	$parser->echo_save($parser->packet_desc . "index=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "count=".$parser->long() . "\n");
}

// packet 0xe9
function PACKET_ZC_ADD_EXCHANGE_ITEM($parser) {
	$parser->echo_save($parser->packet_desc . "count=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "ITID=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "IsIdentified=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "IsDamaged=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "refiningLevel=".$parser->byte() . "\n");
		$parser->echo_save($parser->nl . "card1=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "card2=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "card3=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "card4=".$parser->word() . "\n");
}

// packet 0xea
function PACKET_ZC_ACK_ADD_EXCHANGE_ITEM($parser) {
	$parser->echo_save($parser->packet_desc . "Index=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "result=".$parser->byte() . "\n");
}

// packet 0xeb
function PACKET_CZ_CONCLUDE_EXCHANGE_ITEM($parser) {
	$parser->echo_save($parser->packet_desc . "\n");
}

// packet 0xec
function PACKET_ZC_CONCLUDE_EXCHANGE_ITEM($parser) {
	$parser->echo_save($parser->packet_desc . "who=".$parser->byte() . "\n");
}

// packet 0xed
function PACKET_CZ_CANCEL_EXCHANGE_ITEM($parser) {
	$parser->echo_save($parser->packet_desc . "\n");
}

// packet 0xee
function PACKET_ZC_CANCEL_EXCHANGE_ITEM($parser) {
	$parser->echo_save($parser->packet_desc . "\n");
}

// packet 0xef
function PACKET_CZ_EXEC_EXCHANGE_ITEM($parser) {
	$parser->echo_save($parser->packet_desc . "\n");
}

// packet 0xf0
function PACKET_ZC_EXEC_EXCHANGE_ITEM($parser) {
	$parser->echo_save($parser->packet_desc . "result=".$parser->byte() . "\n");
}

// packet 0xf1
function PACKET_ZC_EXCHANGEITEM_UNDO($parser) {
	$parser->echo_save($parser->packet_desc . "\n");
}

// packet 0xf2
function PACKET_ZC_NOTIFY_STOREITEM_COUNTINFO($parser) {
	$parser->echo_save($parser->packet_desc . "curCount=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "maxCount=".$parser->word() . "\n");
}

// packet 0xf3
function PACKET_CZ_MOVE_ITEM_FROM_BODY_TO_STORE($parser) {
	$parser->echo_save($parser->packet_desc . "index=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "count=".$parser->long() . "\n");
}

// packet 0xf4
function PACKET_ZC_ADD_ITEM_TO_STORE($parser) {
	$parser->echo_save($parser->packet_desc . "index=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "count=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "ITID=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "IsIdentified=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "IsDamaged=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "refiningLevel=".$parser->byte() . "\n");
		$parser->echo_save($parser->nl . "card1=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "card2=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "card3=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "card4=".$parser->word() . "\n");
}

// packet 0xf5
function PACKET_CZ_MOVE_ITEM_FROM_STORE_TO_BODY($parser) {
	$parser->echo_save($parser->packet_desc . "index=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "count=".$parser->long() . "\n");
}

// packet 0xf6
function PACKET_ZC_DELETE_ITEM_FROM_STORE($parser) {
	$parser->echo_save($parser->packet_desc . "index=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "count=".$parser->long() . "\n");
}

// packet 0xf7
function PACKET_CZ_CLOSE_STORE($parser) {
	$parser->echo_save($parser->packet_desc . "\n");
}

// packet 0xf8
function PACKET_ZC_CLOSE_STORE($parser) {
	$parser->echo_save($parser->packet_desc . "\n");
}

// packet 0xf9
function PACKET_CZ_MAKE_GROUP($parser) {
	$parser->echo_save($parser->packet_desc . "groupName=".$parser->string(24) . "\n");
}

// packet 0xfa
function PACKET_ZC_ACK_MAKE_GROUP($parser) {
	$parser->echo_save($parser->packet_desc . "result=".$parser->byte() . "\n");
}

// packet 0xfb
function PACKET_ZC_GROUP_LIST($parser) {
	$parser->echo_save($parser->packet_desc . "PacketLength=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "groupName=".$parser->string(24) . "\n");
	$groupInfo = ($parser->packet_length - $parser->packet_pointer) / 46;
	for ($i = 0; $i < $groupInfo; $i++) {
		$parser->echo_save($parser->nl . "AID=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "characterName=".$parser->string(24) . "\n");
		$parser->echo_save($parser->nl . "mapName=".$parser->string(16) . "\n");
		$parser->echo_save($parser->nl . "role=".$parser->byte() . "\n");
		$parser->echo_save($parser->nl . "state=".$parser->byte() . "\n");
	}
}

// packet 0xfc
function PACKET_CZ_REQ_JOIN_GROUP($parser) {
	$parser->echo_save($parser->packet_desc . "AID=".$parser->long() . "\n");
}

// packet 0xfd
function PACKET_ZC_ACK_REQ_JOIN_GROUP($parser) {
	$parser->echo_save($parser->packet_desc . "characterName=".$parser->string(24) . "\n");
	$parser->echo_save($parser->nl . "answer=".$parser->byte() . "\n");
}

// packet 0xfe
function PACKET_ZC_REQ_JOIN_GROUP($parser) {
	$parser->echo_save($parser->packet_desc . "GRID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "groupName=".$parser->string(24) . "\n");
}

// packet 0xff
function PACKET_CZ_JOIN_GROUP($parser) {
	$parser->echo_save($parser->packet_desc . "GRID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "answer=".$parser->long() . "\n");
}

// packet 0x100
function PACKET_CZ_REQ_LEAVE_GROUP($parser) {
	$parser->echo_save($parser->packet_desc . "\n");
}

// packet 0x101
function PACKET_ZC_GROUPINFO_CHANGE($parser) {
	$parser->echo_save($parser->packet_desc . "expOption=".$parser->long() . "\n");
}

// packet 0x102
function PACKET_CZ_CHANGE_GROUPEXPOPTION($parser) {
	$parser->echo_save($parser->packet_desc . "expOption=".$parser->long() . "\n");
}

// packet 0x103
function PACKET_CZ_REQ_EXPEL_GROUP_MEMBER($parser) {
	$parser->echo_save($parser->packet_desc . "AID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "characterName=".$parser->string(24) . "\n");
}

// packet 0x104
function PACKET_ZC_ADD_MEMBER_TO_GROUP($parser) {
	$parser->echo_save($parser->packet_desc . "AID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "Role=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "xPos=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "yPos=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "state=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "groupName=".$parser->string(24) . "\n");
	$parser->echo_save($parser->nl . "characterName=".$parser->string(24) . "\n");
	$parser->echo_save($parser->nl . "mapName=".$parser->string(16) . "\n");
}

// packet 0x105
function PACKET_ZC_DELETE_MEMBER_FROM_GROUP($parser) {
	$parser->echo_save($parser->packet_desc . "AID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "characterName=".$parser->string(24) . "\n");
	$parser->echo_save($parser->nl . "result=".$parser->byte() . "\n");
}

// packet 0x106
function PACKET_ZC_NOTIFY_HP_TO_GROUPM($parser) {
	$parser->echo_save($parser->packet_desc . "AID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "hp=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "maxhp=".$parser->word() . "\n");
}

// packet 0x107
function PACKET_ZC_NOTIFY_POSITION_TO_GROUPM($parser) {
	$parser->echo_save($parser->packet_desc . "AID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "xPos=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "yPos=".$parser->word() . "\n");
}

// packet 0x108
function PACKET_CZ_REQUEST_CHAT_PARTY($parser) {
	$parser->echo_save($parser->packet_desc . "PacketLength=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "msg=".$parser->string($parser->packet_length - $parser->packet_pointer) . "\n");
}

// packet 0x109
function PACKET_ZC_NOTIFY_CHAT_PARTY($parser) {
	$parser->echo_save($parser->packet_desc . "PacketLength=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "AID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "msg=".$parser->string($parser->packet_length - $parser->packet_pointer) . "\n");
}

// packet 0x10a
function PACKET_ZC_MVP_GETTING_ITEM($parser) {
	$parser->echo_save($parser->packet_desc . "ITID=".$parser->word() . "\n");
}

// packet 0x10b
function PACKET_ZC_MVP_GETTING_SPECIAL_EXP($parser) {
	$parser->echo_save($parser->packet_desc . "exp=".$parser->long() . "\n");
}

// packet 0x10c
function PACKET_ZC_MVP($parser) {
	$parser->echo_save($parser->packet_desc . "AID=".$parser->long() . "\n");
}

// packet 0x10d
function PACKET_ZC_THROW_MVPITEM($parser) {
	$parser->echo_save($parser->packet_desc . "\n");
}

// packet 0x10e
function PACKET_ZC_SKILLINFO_UPDATE($parser) {
	$parser->echo_save($parser->packet_desc . "SKID=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "level=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "spcost=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "attackRange=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "upgradable=".$parser->byte() . "\n");
}

// packet 0x10f
function PACKET_ZC_SKILLINFO_LIST($parser) {
	$parser->echo_save($parser->packet_desc . "PacketLength=".$parser->word() . "\n");
	$skillList = ($parser->packet_length - $parser->packet_pointer) / 37;
	for ($i = 0; $i < $skillList; $i++) {
		$parser->echo_save($parser->nl . "SKID=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "type=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "level=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "spcost=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "attackRange=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "skillName=".$parser->string(24) . "\n");
		$parser->echo_save($parser->nl . "upgradable=".$parser->byte() . "\n");
	}
}

// packet 0x110
function PACKET_ZC_ACK_TOUSESKILL($parser) {
	$parser->echo_save($parser->packet_desc . "SKID=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "NUM=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "result=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "cause=".$parser->byte() . "\n");
}

// packet 0x111
function PACKET_ZC_ADD_SKILL($parser) {
	$parser->echo_save($parser->packet_desc  . "\n");
		$parser->echo_save($parser->nl . "SKID=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "type=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "level=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "spcost=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "attackRange=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "skillName=".$parser->string(24) . "\n");
		$parser->echo_save($parser->nl . "upgradable=".$parser->byte() . "\n");
}

// packet 0x112
function PACKET_CZ_UPGRADE_SKILLLEVEL($parser) {
	$parser->echo_save($parser->packet_desc . "SKID=".$parser->word() . "\n");
}

// packet 0x113
function PACKET_CZ_USE_SKILL($parser) {
	$parser->echo_save($parser->packet_desc . "selectedLevel=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "SKID=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "targetID=".$parser->long() . "\n");
}

// packet 0x114
function PACKET_ZC_NOTIFY_SKILL($parser) {
	$parser->echo_save($parser->packet_desc . "SKID=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "AID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "targetID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "startTime=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "attackMT=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "attackedMT=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "damage=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "level=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "count=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "action=".$parser->byte() . "\n");
}

// packet 0x115
function PACKET_ZC_NOTIFY_SKILL_POSITION($parser) {
	$parser->echo_save($parser->packet_desc . "SKID=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "AID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "targetID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "startTime=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "attackMT=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "attackedMT=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "xPos=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "yPos=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "damage=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "level=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "count=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "action=".$parser->byte() . "\n");
}

// packet 0x116
function PACKET_CZ_USE_SKILL_TOGROUND($parser) {
	$parser->echo_save($parser->packet_desc . "selectedLevel=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "SKID=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "xPos=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "yPos=".$parser->word() . "\n");
}

// packet 0x117
function PACKET_ZC_NOTIFY_GROUNDSKILL($parser) {
	$parser->echo_save($parser->packet_desc . "SKID=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "AID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "level=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "xPos=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "yPos=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "startTime=".$parser->long() . "\n");
}

// packet 0x118
function PACKET_CZ_CANCEL_LOCKON($parser) {
	$parser->echo_save($parser->packet_desc . "\n");
}

// packet 0x119
function PACKET_ZC_STATE_CHANGE($parser) {
	$parser->echo_save($parser->packet_desc . "AID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "bodyState=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "healthState=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "effectState=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "isPKModeON=".$parser->byte() . "\n");
}

// packet 0x11a
function PACKET_ZC_USE_SKILL($parser) {
	$parser->echo_save($parser->packet_desc . "SKID=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "level=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "targetAID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "srcAID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "result=".$parser->byte() . "\n");
}

// packet 0x11b
function PACKET_CZ_SELECT_WARPPOINT($parser) {
	$parser->echo_save($parser->packet_desc . "SKID=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "mapName=".$parser->string(16) . "\n");
}

// packet 0x11c
function PACKET_ZC_WARPLIST($parser) {
	$parser->echo_save($parser->packet_desc . "SKID=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "mapName=".$parser->string(16) . "\n");
}

// packet 0x11d
function PACKET_CZ_REMEMBER_WARPPOINT($parser) {
	$parser->echo_save($parser->packet_desc . "\n");
}

// packet 0x11e
function PACKET_ZC_ACK_REMEMBER_WARPPOINT($parser) {
	$parser->echo_save($parser->packet_desc . "errorCode=".$parser->byte() . "\n");
}

// packet 0x11f
function PACKET_ZC_SKILL_ENTRY($parser) {
	$parser->echo_save($parser->packet_desc . "AID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "creatorAID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "xPos=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "yPos=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "job=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "isVisible=".$parser->byte() . "\n");
}

// packet 0x120
function PACKET_ZC_SKILL_DISAPPEAR($parser) {
	$parser->echo_save($parser->packet_desc . "AID=".$parser->long() . "\n");
}

// packet 0x121
function PACKET_ZC_NOTIFY_CARTITEM_COUNTINFO($parser) {
	$parser->echo_save($parser->packet_desc . "curCount=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "maxCount=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "curWeight=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "maxWeight=".$parser->long() . "\n");
}

// packet 0x122
function PACKET_ZC_CART_EQUIPMENT_ITEMLIST($parser) {
	$parser->echo_save($parser->packet_desc . "PacketLength=".$parser->word() . "\n");
	$itemInfo = ($parser->packet_length - $parser->packet_pointer) / 20;
	for ($i = 0; $i < $itemInfo; $i++) {
		$parser->echo_save($parser->nl . "index=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "ITID=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "type=".$parser->byte() . "\n");
		$parser->echo_save($parser->nl . "IsIdentified=".$parser->byte() . "\n");
		$parser->echo_save($parser->nl . "location=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "WearState=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "IsDamaged=".$parser->byte() . "\n");
		$parser->echo_save($parser->nl . "RefiningLevel=".$parser->byte() . "\n");
		$parser->echo_save($parser->nl . "card1=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "card2=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "card3=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "card4=".$parser->word() . "\n");
	}
}

// packet 0x123
function PACKET_ZC_CART_NORMAL_ITEMLIST($parser) {
	$parser->echo_save($parser->packet_desc . "PacketLength=".$parser->word() . "\n");
	$itemInfo = ($parser->packet_length - $parser->packet_pointer) / 10;
	for ($i = 0; $i < $itemInfo; $i++) {
		$parser->echo_save($parser->nl . "index=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "ITID=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "type=".$parser->byte() . "\n");
		$parser->echo_save($parser->nl . "IsIdentified=".$parser->byte() . "\n");
		$parser->echo_save($parser->nl . "count=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "WearState=".$parser->word() . "\n");
	}
}

// packet 0x124
function PACKET_ZC_ADD_ITEM_TO_CART($parser) {
	$parser->echo_save($parser->packet_desc . "index=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "count=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "ITID=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "IsIdentified=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "IsDamaged=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "refiningLevel=".$parser->byte() . "\n");
		$parser->echo_save($parser->nl . "card1=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "card2=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "card3=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "card4=".$parser->word() . "\n");
}

// packet 0x125
function PACKET_ZC_DELETE_ITEM_FROM_CART($parser) {
	$parser->echo_save($parser->packet_desc . "index=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "count=".$parser->long() . "\n");
}

// packet 0x126
function PACKET_CZ_MOVE_ITEM_FROM_BODY_TO_CART($parser) {
	$parser->echo_save($parser->packet_desc . "index=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "count=".$parser->long() . "\n");
}

// packet 0x127
function PACKET_CZ_MOVE_ITEM_FROM_CART_TO_BODY($parser) {
	$parser->echo_save($parser->packet_desc . "index=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "count=".$parser->long() . "\n");
}

// packet 0x128
function PACKET_CZ_MOVE_ITEM_FROM_STORE_TO_CART($parser) {
	$parser->echo_save($parser->packet_desc . "index=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "count=".$parser->long() . "\n");
}

// packet 0x129
function PACKET_CZ_MOVE_ITEM_FROM_CART_TO_STORE($parser) {
	$parser->echo_save($parser->packet_desc . "index=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "count=".$parser->long() . "\n");
}

// packet 0x12a
function PACKET_CZ_REQ_CARTOFF($parser) {
	$parser->echo_save($parser->packet_desc . "\n");
}

// packet 0x12b
function PACKET_ZC_CARTOFF($parser) {
	$parser->echo_save($parser->packet_desc . "\n");
}

// packet 0x12c
function PACKET_ZC_ACK_ADDITEM_TO_CART($parser) {
	$parser->echo_save($parser->packet_desc . "result=".$parser->byte() . "\n");
}

// packet 0x12d
function PACKET_ZC_OPENSTORE($parser) {
	$parser->echo_save($parser->packet_desc . "itemcount=".$parser->word() . "\n");
}

// packet 0x12e
function PACKET_CZ_REQ_CLOSESTORE($parser) {
	$parser->echo_save($parser->packet_desc . "\n");
}

// packet 0x12f
function PACKET_CZ_REQ_OPENSTORE($parser) {
	$parser->echo_save($parser->packet_desc . "PacketLength=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "storeName=".$parser->string(80) . "\n");
	$storeList = ($parser->packet_length - $parser->packet_pointer) / 8;
	for ($i = 0; $i < $storeList; $i++) {
		$parser->echo_save($parser->nl . "index=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "count=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "Price=".$parser->long() . "\n");
	}
}

// packet 0x130
function PACKET_CZ_REQ_BUY_FROMMC($parser) {
	$parser->echo_save($parser->packet_desc . "AID=".$parser->long() . "\n");
}

// packet 0x131
function PACKET_ZC_STORE_ENTRY($parser) {
	$parser->echo_save($parser->packet_desc . "makerAID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "storeName=".$parser->string(80) . "\n");
}

// packet 0x132
function PACKET_ZC_DISAPPEAR_ENTRY($parser) {
	$parser->echo_save($parser->packet_desc . "makerAID=".$parser->long() . "\n");
}

// packet 0x133
function PACKET_ZC_PC_PURCHASE_ITEMLIST_FROMMC($parser) {
	$parser->echo_save($parser->packet_desc . "PacketLength=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "AID=".$parser->long() . "\n");
	$itemList = ($parser->packet_length - $parser->packet_pointer) / 22;
	for ($i = 0; $i < $itemList; $i++) {
		$parser->echo_save($parser->nl . "price=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "count=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "index=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "type=".$parser->byte() . "\n");
		$parser->echo_save($parser->nl . "ITID=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "IsIdentified=".$parser->byte() . "\n");
		$parser->echo_save($parser->nl . "IsDamaged=".$parser->byte() . "\n");
		$parser->echo_save($parser->nl . "refiningLevel=".$parser->byte() . "\n");
		$parser->echo_save($parser->nl . "card1=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "card2=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "card3=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "card4=".$parser->word() . "\n");
	}
}

// packet 0x134
function PACKET_CZ_PC_PURCHASE_ITEMLIST_FROMMC($parser) {
	$parser->echo_save($parser->packet_desc . "PacketLength=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "AID=".$parser->long() . "\n");
	$itemList = ($parser->packet_length - $parser->packet_pointer) / 4;
	for ($i = 0; $i < $itemList; $i++) {
		$parser->echo_save($parser->nl . "count=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "index=".$parser->word() . "\n");
	}
}

// packet 0x135
function PACKET_ZC_PC_PURCHASE_RESULT_FROMMC($parser) {
	$parser->echo_save($parser->packet_desc . "index=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "curcount=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "result=".$parser->byte() . "\n");
}

// packet 0x136
function PACKET_ZC_PC_PURCHASE_MYITEMLIST($parser) {
	$parser->echo_save($parser->packet_desc . "PacketLength=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "AID=".$parser->long() . "\n");
	$itemList = ($parser->packet_length - $parser->packet_pointer) / 22;
	for ($i = 0; $i < $itemList; $i++) {
		$parser->echo_save($parser->nl . "price=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "index=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "count=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "type=".$parser->byte() . "\n");
		$parser->echo_save($parser->nl . "ITID=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "IsIdentified=".$parser->byte() . "\n");
		$parser->echo_save($parser->nl . "IsDamaged=".$parser->byte() . "\n");
		$parser->echo_save($parser->nl . "refiningLevel=".$parser->byte() . "\n");
		$parser->echo_save($parser->nl . "card1=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "card2=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "card3=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "card4=".$parser->word() . "\n");
	}
}

// packet 0x137
function PACKET_ZC_DELETEITEM_FROM_MCSTORE($parser) {
	$parser->echo_save($parser->packet_desc . "index=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "count=".$parser->word() . "\n");
}

// packet 0x138
function PACKET_CZ_PKMODE_CHANGE($parser) {
	$parser->echo_save($parser->packet_desc . "isTurnOn=".$parser->byte() . "\n");
}

// packet 0x139
function PACKET_ZC_ATTACK_FAILURE_FOR_DISTANCE($parser) {
	$parser->echo_save($parser->packet_desc . "targetAID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "targetXPos=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "targetYPos=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "xPos=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "yPos=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "currentAttRange=".$parser->word() . "\n");
}

// packet 0x13a
function PACKET_ZC_ATTACK_RANGE($parser) {
	$parser->echo_save($parser->packet_desc . "currentAttRange=".$parser->word() . "\n");
}

// packet 0x13b
function PACKET_ZC_ACTION_FAILURE($parser) {
	$parser->echo_save($parser->packet_desc . "errorCode=".$parser->word() . "\n");
}

// packet 0x13c
function PACKET_ZC_EQUIP_ARROW($parser) {
	$parser->echo_save($parser->packet_desc . "index=".$parser->word() . "\n");
}

// packet 0x13d
function PACKET_ZC_RECOVERY($parser) {
	$parser->echo_save($parser->packet_desc . "varID=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "amount=".$parser->word() . "\n");
}

// packet 0x13e
function PACKET_ZC_USESKILL_ACK($parser) {
	$parser->echo_save($parser->packet_desc . "AID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "targetID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "xPos=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "yPos=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "SKID=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "property=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "delayTime=".$parser->long() . "\n");
}

// packet 0x13f
function PACKET_CZ_ITEM_CREATE($parser) {
	$parser->echo_save($parser->packet_desc . "itemName=".$parser->string(24) . "\n");
}

// packet 0x140
function PACKET_CZ_MOVETO_MAP($parser) {
	$parser->echo_save($parser->packet_desc . "mapName=".$parser->string(16) . "\n");
	$parser->echo_save($parser->nl . "xPos=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "yPos=".$parser->word() . "\n");
}

// packet 0x141
function PACKET_ZC_COUPLESTATUS($parser) {
	$parser->echo_save($parser->packet_desc . "statusType=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "defaultStatus=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "plusStatus=".$parser->long() . "\n");
}

// packet 0x142
function PACKET_ZC_OPEN_EDITDLG($parser) {
	$parser->echo_save($parser->packet_desc . "NAID=".$parser->long() . "\n");
}

// packet 0x143
function PACKET_CZ_INPUT_EDITDLG($parser) {
	$parser->echo_save($parser->packet_desc . "NAID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "value=".$parser->long() . "\n");
}

// packet 0x144
function PACKET_ZC_COMPASS($parser) {
	$parser->echo_save($parser->packet_desc . "NAID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "type=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "xPos=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "yPos=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "id=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "color=".$parser->long() . "\n");
}

// packet 0x145
function PACKET_ZC_SHOW_IMAGE($parser) {
	$parser->echo_save($parser->packet_desc . "imageName=".$parser->string(16) . "\n");
	$parser->echo_save($parser->nl . "type=".$parser->byte() . "\n");
}

// packet 0x146
function PACKET_CZ_CLOSE_DIALOG($parser) {
	$parser->echo_save($parser->packet_desc . "NAID=".$parser->long() . "\n");
}

// packet 0x147
function PACKET_ZC_AUTORUN_SKILL($parser) {
	$parser->echo_save($parser->packet_desc  . "\n");
		$parser->echo_save($parser->nl . "SKID=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "type=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "level=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "spcost=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "attackRange=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "skillName=".$parser->string(24) . "\n");
		$parser->echo_save($parser->nl . "upgradable=".$parser->byte() . "\n");
}

// packet 0x148
function PACKET_ZC_RESURRECTION($parser) {
	$parser->echo_save($parser->packet_desc . "AID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "type=".$parser->word() . "\n");
}

// packet 0x149
function PACKET_CZ_REQ_GIVE_MANNER_POINT($parser) {
	$parser->echo_save($parser->packet_desc . "otherAID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "type=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "point=".$parser->word() . "\n");
}

// packet 0x14a
function PACKET_ZC_ACK_GIVE_MANNER_POINT($parser) {
	$parser->echo_save($parser->packet_desc . "result=".$parser->long() . "\n");
}

// packet 0x14b
function PACKET_ZC_NOTIFY_MANNER_POINT_GIVEN($parser) {
	$parser->echo_save($parser->packet_desc . "type=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "otherCharName=".$parser->string(24) . "\n");
}

// packet 0x14c
function PACKET_ZC_MYGUILD_BASIC_INFO($parser) {
	$parser->echo_save($parser->packet_desc . "PacketLength=".$parser->word() . "\n");
	$relatedGuildList = ($parser->packet_length - $parser->packet_pointer) / 32;
	for ($i = 0; $i < $relatedGuildList; $i++) {
		$parser->echo_save($parser->nl . "GDID=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "relation=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "GuildName=".$parser->string(24) . "\n");
	}
}

// packet 0x14d
function PACKET_CZ_REQ_GUILD_MENUINTERFACE($parser) {
	$parser->echo_save($parser->packet_desc . "\n");
}

// packet 0x14e
function PACKET_ZC_ACK_GUILD_MENUINTERFACE($parser) {
	$parser->echo_save($parser->packet_desc . "guildMemuFlag=".$parser->long() . "\n");
}

// packet 0x14f
function PACKET_CZ_REQ_GUILD_MENU($parser) {
	$parser->echo_save($parser->packet_desc . "Type=".$parser->long() . "\n");
}

// packet 0x150
function PACKET_ZC_GUILD_INFO($parser) {
	$parser->echo_save($parser->packet_desc . "GDID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "level=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "userNum=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "maxUserNum=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "userAverageLevel=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "exp=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "maxExp=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "point=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "honor=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "virtue=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "emblemVersion=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "guildname=".$parser->string(24) . "\n");
	$parser->echo_save($parser->nl . "masterName=".$parser->string(24) . "\n");
	$parser->echo_save($parser->nl . "manageLand=".$parser->string(16) . "\n");
}

// packet 0x151
function PACKET_CZ_REQ_GUILD_EMBLEM_IMG($parser) {
	$parser->echo_save($parser->packet_desc . "GDID=".$parser->long() . "\n");
}

// packet 0x152
function PACKET_ZC_GUILD_EMBLEM_IMG($parser) {
	$parser->echo_save($parser->packet_desc . "PacketLength=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "GDID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "emblemVersion=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "img=".$parser->string($parser->packet_length - $parser->packet_pointer) . "\n");
}

// packet 0x153
function PACKET_CZ_REGISTER_GUILD_EMBLEM_IMG($parser) {
	$parser->echo_save($parser->packet_desc . "PacketLength=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "img=".$parser->string($parser->packet_length - $parser->packet_pointer) . "\n");
}

// packet 0x154
function PACKET_ZC_MEMBERMGR_INFO($parser) {
	$parser->echo_save($parser->packet_desc . "PacketLength=".$parser->word() . "\n");
	$memberInfo = ($parser->packet_length - $parser->packet_pointer) / 104;
	for ($i = 0; $i < $memberInfo; $i++) {
		$parser->echo_save($parser->nl . "AID=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "GID=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "HeadType=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "HeadPalette=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "Sex=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "Job=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "Level=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "MemberExp=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "CurrentState=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "GPositionID=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "Memo=".$parser->string(50) . "\n");
		$parser->echo_save($parser->nl . "CharName=".$parser->string(24) . "\n");
	}
}

// packet 0x155
function PACKET_CZ_REQ_CHANGE_MEMBERPOS($parser) {
	$parser->echo_save($parser->packet_desc . "PacketLength=".$parser->word() . "\n");
	$memberInfo = ($parser->packet_length - $parser->packet_pointer) / 12;
	for ($i = 0; $i < $memberInfo; $i++) {
		$parser->echo_save($parser->nl . "AID=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "GID=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "positionID=".$parser->long() . "\n");
	}
}

// packet 0x156
function PACKET_ZC_ACK_REQ_CHANGE_MEMBERS($parser) {
	$parser->echo_save($parser->packet_desc . "PacketLength=".$parser->word() . "\n");
	$memberInfo = ($parser->packet_length - $parser->packet_pointer) / 12;
	for ($i = 0; $i < $memberInfo; $i++) {
		$parser->echo_save($parser->nl . "AID=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "GID=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "positionID=".$parser->long() . "\n");
	}
}

// packet 0x157
function PACKET_CZ_REQ_OPEN_MEMBER_INFO($parser) {
	$parser->echo_save($parser->packet_desc . "AID=".$parser->long() . "\n");
}

// packet 0x158
function PACKET_ZC_ACK_OPEN_MEMBER_INFO($parser) {
	$parser->echo_save($parser->packet_desc . "\n");
}

// packet 0x159
function PACKET_CZ_REQ_LEAVE_GUILD($parser) {
	$parser->echo_save($parser->packet_desc . "GDID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "AID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "GID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "reasonDesc=".$parser->string(40) . "\n");
}

// packet 0x15a
function PACKET_ZC_ACK_LEAVE_GUILD($parser) {
	$parser->echo_save($parser->packet_desc . "charName=".$parser->string(24) . "\n");
	$parser->echo_save($parser->nl . "reasonDesc=".$parser->string(40) . "\n");
}

// packet 0x15b
function PACKET_CZ_REQ_BAN_GUILD($parser) {
	$parser->echo_save($parser->packet_desc . "GDID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "AID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "GID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "reasonDesc=".$parser->string(40) . "\n");
}

// packet 0x15c
function PACKET_ZC_ACK_BAN_GUILD($parser) {
	$parser->echo_save($parser->packet_desc . "charName=".$parser->string(24) . "\n");
	$parser->echo_save($parser->nl . "reasonDesc=".$parser->string(40) . "\n");
	$parser->echo_save($parser->nl . "account=".$parser->string(24) . "\n");
}

// packet 0x15d
function PACKET_CZ_REQ_DISORGANIZE_GUILD($parser) {
	$parser->echo_save($parser->packet_desc . "key=".$parser->string(40) . "\n");
}

// packet 0x15e
function PACKET_ZC_ACK_DISORGANIZE_GUILD_RESULT($parser) {
	$parser->echo_save($parser->packet_desc . "reason=".$parser->long() . "\n");
}

// packet 0x15f
function PACKET_ZC_ACK_DISORGANIZE_GUILD($parser) {
	$parser->echo_save($parser->packet_desc . "reasonDesc=".$parser->string(40) . "\n");
}

// packet 0x160
function PACKET_ZC_POSITION_INFO($parser) {
	$parser->echo_save($parser->packet_desc . "PacketLength=".$parser->word() . "\n");
	$memberInfo = ($parser->packet_length - $parser->packet_pointer) / 16;
	for ($i = 0; $i < $memberInfo; $i++) {
		$parser->echo_save($parser->nl . "positionID=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "right=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "ranking=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "payRate=".$parser->long() . "\n");
	}
}

// packet 0x161
function PACKET_CZ_REG_CHANGE_GUILD_POSITIONINFO($parser) {
	$parser->echo_save($parser->packet_desc . "PacketLength=".$parser->word() . "\n");
	$memberList = ($parser->packet_length - $parser->packet_pointer) / 40;
	for ($i = 0; $i < $memberList; $i++) {
		$parser->echo_save($parser->nl . "positionID=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "right=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "ranking=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "payRate=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "posName=".$parser->string(24) . "\n");
	}
}

// packet 0x162
function PACKET_ZC_GUILD_SKILLINFO($parser) {
	$parser->echo_save($parser->packet_desc . "PacketLength=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "skillPoint=".$parser->word() . "\n");
	$skillList = ($parser->packet_length - $parser->packet_pointer) / 37;
	for ($i = 0; $i < $skillList; $i++) {
		$parser->echo_save($parser->nl . "SKID=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "type=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "level=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "spcost=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "attackRange=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "skillName=".$parser->string(24) . "\n");
		$parser->echo_save($parser->nl . "upgradable=".$parser->byte() . "\n");
	}
}

// packet 0x163
function PACKET_ZC_BAN_LIST($parser) {
	$parser->echo_save($parser->packet_desc . "PacketLength=".$parser->word() . "\n");
	$banList = ($parser->packet_length - $parser->packet_pointer) / 88;
	for ($i = 0; $i < $banList; $i++) {
		$parser->echo_save($parser->nl . "charname=".$parser->string(24) . "\n");
		$parser->echo_save($parser->nl . "account=".$parser->string(24) . "\n");
		$parser->echo_save($parser->nl . "reason=".$parser->string(40) . "\n");
	}
}

// packet 0x164
function PACKET_ZC_OTHER_GUILD_LIST($parser) {
	$parser->echo_save($parser->packet_desc . "PacketLength=".$parser->word() . "\n");
	$guildList = ($parser->packet_length - $parser->packet_pointer) / 36;
	for ($i = 0; $i < $guildList; $i++) {
		$parser->echo_save($parser->nl . "guildname=".$parser->string(24) . "\n");
		$parser->echo_save($parser->nl . "guildLevel=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "guildMemberSize=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "guildRanking=".$parser->long() . "\n");
	}
}

// packet 0x165
function PACKET_CZ_REQ_MAKE_GUILD($parser) {
	$parser->echo_save($parser->packet_desc . "GID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "GName=".$parser->string(24) . "\n");
}

// packet 0x166
function PACKET_ZC_POSITION_ID_NAME_INFO($parser) {
	$parser->echo_save($parser->packet_desc . "PacketLength=".$parser->word() . "\n");
	$memberList = ($parser->packet_length - $parser->packet_pointer) / 28;
	for ($i = 0; $i < $memberList; $i++) {
		$parser->echo_save($parser->nl . "positionID=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "posName=".$parser->string(24) . "\n");
	}
}

// packet 0x167
function PACKET_ZC_RESULT_MAKE_GUILD($parser) {
	$parser->echo_save($parser->packet_desc . "result=".$parser->byte() . "\n");
}

// packet 0x168
function PACKET_CZ_REQ_JOIN_GUILD($parser) {
	$parser->echo_save($parser->packet_desc . "AID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "MyAID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "MyGID=".$parser->long() . "\n");
}

// packet 0x169
function PACKET_ZC_ACK_REQ_JOIN_GUILD($parser) {
	$parser->echo_save($parser->packet_desc . "answer=".$parser->byte() . "\n");
}

// packet 0x16a
function PACKET_ZC_REQ_JOIN_GUILD($parser) {
	$parser->echo_save($parser->packet_desc . "GDID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "guildName=".$parser->string(24) . "\n");
}

// packet 0x16b
function PACKET_CZ_JOIN_GUILD($parser) {
	$parser->echo_save($parser->packet_desc . "GDID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "answer=".$parser->long() . "\n");
}

// packet 0x16c
function PACKET_ZC_UPDATE_GDID($parser) {
	$parser->echo_save($parser->packet_desc . "GDID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "emblemVersion=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "right=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "isMaster=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "InterSID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "GName=".$parser->string(24) . "\n");
}

// packet 0x16d
function PACKET_ZC_UPDATE_CHARSTAT($parser) {
	$parser->echo_save($parser->packet_desc . "AID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "GID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "status=".$parser->long() . "\n");
}

// packet 0x16e
function PACKET_CZ_GUILD_NOTICE($parser) {
	$parser->echo_save($parser->packet_desc . "GDID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "subject=".$parser->string(60) . "\n");
	$parser->echo_save($parser->nl . "notice=".$parser->string(120) . "\n");
}

// packet 0x16f
function PACKET_ZC_GUILD_NOTICE($parser) {
	$parser->echo_save($parser->packet_desc . "subject=".$parser->string(60) . "\n");
	$parser->echo_save($parser->nl . "notice=".$parser->string(120) . "\n");
}

// packet 0x170
function PACKET_CZ_REQ_ALLY_GUILD($parser) {
	$parser->echo_save($parser->packet_desc . "AID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "MyAID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "MyGID=".$parser->long() . "\n");
}

// packet 0x171
function PACKET_ZC_REQ_ALLY_GUILD($parser) {
	$parser->echo_save($parser->packet_desc . "otherAID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "guildName=".$parser->string(24) . "\n");
}

// packet 0x172
function PACKET_CZ_ALLY_GUILD($parser) {
	$parser->echo_save($parser->packet_desc . "otherAID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "answer=".$parser->long() . "\n");
}

// packet 0x173
function PACKET_ZC_ACK_REQ_ALLY_GUILD($parser) {
	$parser->echo_save($parser->packet_desc . "answer=".$parser->byte() . "\n");
}

// packet 0x174
function PACKET_ZC_ACK_CHANGE_GUILD_POSITIONINFO($parser) {
	$parser->echo_save($parser->packet_desc . "PacketLength=".$parser->word() . "\n");
	$memberList = ($parser->packet_length - $parser->packet_pointer) / 30;
	for ($i = 0; $i < $memberList; $i++) {
		$parser->echo_save($parser->nl . "positionID=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "right=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "ranking=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "payRate=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "posName=".$parser->string(24) . "\n");
	}
}

// packet 0x175
function PACKET_CZ_REQ_GUILD_MEMBER_INFO($parser) {
	$parser->echo_save($parser->packet_desc . "GID=".$parser->long() . "\n");
}

// packet 0x176
function PACKET_ZC_ACK_GUILD_MEMBER_INFO($parser) {
	$parser->echo_save($parser->packet_desc  . "\n");
		$parser->echo_save($parser->nl . "AID=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "GID=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "head=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "headPalette=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "sex=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "job=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "level=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "contributionExp=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "currentState=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "positionID=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "intro=".$parser->string(50) . "\n");
		$parser->echo_save($parser->nl . "charname=".$parser->string(24) . "\n");
}

// packet 0x177
function PACKET_ZC_ITEMIDENTIFY_LIST($parser) {
	$parser->echo_save($parser->packet_desc . "PacketLength=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "ITIDList=".$parser->word() . "\n");
}

// packet 0x178
function PACKET_CZ_REQ_ITEMIDENTIFY($parser) {
	$parser->echo_save($parser->packet_desc . "index=".$parser->word() . "\n");
}

// packet 0x179
function PACKET_ZC_ACK_ITEMIDENTIFY($parser) {
	$parser->echo_save($parser->packet_desc . "index=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "result=".$parser->byte() . "\n");
}

// packet 0x17a
function PACKET_CZ_REQ_ITEMCOMPOSITION_LIST($parser) {
	$parser->echo_save($parser->packet_desc . "cardIndex=".$parser->word() . "\n");
}

// packet 0x17b
function PACKET_ZC_ITEMCOMPOSITION_LIST($parser) {
	$parser->echo_save($parser->packet_desc . "PacketLength=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "ITIDList=".$parser->word() . "\n");
}

// packet 0x17c
function PACKET_CZ_REQ_ITEMCOMPOSITION($parser) {
	$parser->echo_save($parser->packet_desc . "cardIndex=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "equipIndex=".$parser->word() . "\n");
}

// packet 0x17d
function PACKET_ZC_ACK_ITEMCOMPOSITION($parser) {
	$parser->echo_save($parser->packet_desc . "equipIndex=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "cardIndex=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "result=".$parser->byte() . "\n");
}

// packet 0x17e
function PACKET_CZ_GUILD_CHAT($parser) {
	$parser->echo_save($parser->packet_desc . "PacketLength=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "msg=".$parser->string($parser->packet_length - $parser->packet_pointer) . "\n");
}

// packet 0x17f
function PACKET_ZC_GUILD_CHAT($parser) {
	$parser->echo_save($parser->packet_desc . "PacketLength=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "msg=".$parser->string($parser->packet_length - $parser->packet_pointer) . "\n");
}

// packet 0x180
function PACKET_CZ_REQ_HOSTILE_GUILD($parser) {
	$parser->echo_save($parser->packet_desc . "AID=".$parser->long() . "\n");
}

// packet 0x181
function PACKET_ZC_ACK_REQ_HOSTILE_GUILD($parser) {
	$parser->echo_save($parser->packet_desc . "result=".$parser->byte() . "\n");
}

// packet 0x182
function PACKET_ZC_MEMBER_ADD($parser) {
	$parser->echo_save($parser->packet_desc  . "\n");
		$parser->echo_save($parser->nl . "AID=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "GID=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "head=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "headPalette=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "sex=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "job=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "level=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "contributionExp=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "currentState=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "positionID=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "intro=".$parser->string(50) . "\n");
		$parser->echo_save($parser->nl . "charname=".$parser->string(24) . "\n");
}

// packet 0x183
function PACKET_CZ_REQ_DELETE_RELATED_GUILD($parser) {
	$parser->echo_save($parser->packet_desc . "OpponentGDID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "Relation=".$parser->long() . "\n");
}

// packet 0x184
function PACKET_ZC_DELETE_RELATED_GUILD($parser) {
	$parser->echo_save($parser->packet_desc . "OpponentGDID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "Relation=".$parser->long() . "\n");
}

// packet 0x185
function PACKET_ZC_ADD_RELATED_GUILD($parser) {
	$parser->echo_save($parser->packet_desc  . "\n");
		$parser->echo_save($parser->nl . "relation=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "GDID=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "guildname=".$parser->string(24) . "\n");
}

// packet 0x186
function PACKET_COLLECTORDEAD($parser) {
	$parser->echo_save($parser->packet_desc . "ServerID=".$parser->long() . "\n");
}

// packet 0x187
function PACKET_PING($parser) {
	$parser->echo_save($parser->packet_desc . "AID=".$parser->long() . "\n");
}

// packet 0x188
function PACKET_ZC_ACK_ITEMREFINING($parser) {
	$parser->echo_save($parser->packet_desc . "result=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "itemIndex=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "refiningLevel=".$parser->word() . "\n");
}

// packet 0x189
function PACKET_ZC_NOTIFY_MAPINFO($parser) {
	$parser->echo_save($parser->packet_desc . "type=".$parser->word() . "\n");
}

// packet 0x18a
function PACKET_CZ_REQ_DISCONNECT($parser) {
	$parser->echo_save($parser->packet_desc . "type=".$parser->word() . "\n");
}

// packet 0x18b
function PACKET_ZC_ACK_REQ_DISCONNECT($parser) {
	$parser->echo_save($parser->packet_desc . "result=".$parser->word() . "\n");
}

// packet 0x18c
function PACKET_ZC_MONSTER_INFO($parser) {
	$parser->echo_save($parser->packet_desc . "job=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "level=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "size=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "hp=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "def=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "raceType=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "mdefPower=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "property=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "water=".$parser->byte() . "\n");
		$parser->echo_save($parser->nl . "earth=".$parser->byte() . "\n");
		$parser->echo_save($parser->nl . "fire=".$parser->byte() . "\n");
		$parser->echo_save($parser->nl . "wind=".$parser->byte() . "\n");
		$parser->echo_save($parser->nl . "poison=".$parser->byte() . "\n");
		$parser->echo_save($parser->nl . "saint=".$parser->byte() . "\n");
		$parser->echo_save($parser->nl . "dark=".$parser->byte() . "\n");
		$parser->echo_save($parser->nl . "mental=".$parser->byte() . "\n");
		$parser->echo_save($parser->nl . "undead=".$parser->byte() . "\n");
}

// packet 0x18d
function PACKET_ZC_MAKABLEITEMLIST($parser) {
	$parser->echo_save($parser->packet_desc . "PacketLength=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "ITID=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "material_ID=".$parser->word() . "\n");
}

// packet 0x18e
function PACKET_CZ_REQMAKINGITEM($parser) {
	$parser->echo_save($parser->packet_desc  . "\n");
		$parser->echo_save($parser->nl . "ITID=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "material_ID=".$parser->word() . "\n");
}

// packet 0x18f
function PACKET_ZC_ACK_REQMAKINGITEM($parser) {
	$parser->echo_save($parser->packet_desc . "result=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "ITID=".$parser->word() . "\n");
}

// packet 0x190
function PACKET_CZ_USE_SKILL_TOGROUND_WITHTALKBOX($parser) {
	$parser->echo_save($parser->packet_desc . "selectedLevel=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "SKID=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "xPos=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "yPos=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "contents=".$parser->string(80) . "\n");
}

// packet 0x191
function PACKET_ZC_TALKBOX_CHATCONTENTS($parser) {
	$parser->echo_save($parser->packet_desc . "AID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "contents=".$parser->string(80) . "\n");
}

// packet 0x192
function PACKET_ZC_UPDATE_MAPINFO($parser) {
	$parser->echo_save($parser->packet_desc . "xPos=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "yPos=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "type=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "mapName=".$parser->string(16) . "\n");
}

// packet 0x193
function PACKET_CZ_REQNAME_BYGID($parser) {
	$parser->echo_save($parser->packet_desc . "GID=".$parser->long() . "\n");
}

// packet 0x194
function PACKET_ZC_ACK_REQNAME_BYGID($parser) {
	$parser->echo_save($parser->packet_desc . "GID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "CName=".$parser->string(24) . "\n");
}

// packet 0x195
function PACKET_ZC_ACK_REQNAMEALL($parser) {
	$parser->echo_save($parser->packet_desc . "AID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "CName=".$parser->string(24) . "\n");
	$parser->echo_save($parser->nl . "PName=".$parser->string(24) . "\n");
	$parser->echo_save($parser->nl . "GName=".$parser->string(24) . "\n");
	$parser->echo_save($parser->nl . "RName=".$parser->string(24) . "\n");
}

// packet 0x196
function PACKET_ZC_MSG_STATE_CHANGE($parser) {
	$parser->echo_save($parser->packet_desc . "index=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "AID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "state=".$parser->byte() . "\n");
}

// packet 0x197
function PACKET_CZ_RESET($parser) {
	$parser->echo_save($parser->packet_desc . "type=".$parser->word() . "\n");
}

// packet 0x198
function PACKET_CZ_CHANGE_MAPTYPE($parser) {
	$parser->echo_save($parser->packet_desc . "xPos=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "yPos=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "type=".$parser->word() . "\n");
}

// packet 0x199
function PACKET_ZC_NOTIFY_MAPPROPERTY($parser) {
	$parser->echo_save($parser->packet_desc . "type=".$parser->word() . "\n");
}

// packet 0x19a
function PACKET_ZC_NOTIFY_RANKING($parser) {
	$parser->echo_save($parser->packet_desc . "AID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "ranking=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "total=".$parser->long() . "\n");
}

// packet 0x19b
function PACKET_ZC_NOTIFY_EFFECT($parser) {
	$parser->echo_save($parser->packet_desc . "AID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "effectID=".$parser->long() . "\n");
}

// packet 0x19d
function PACKET_CZ_CHANGE_EFFECTSTATE($parser) {
	$parser->echo_save($parser->packet_desc . "EffectState=".$parser->long() . "\n");
}

// packet 0x19e
function PACKET_ZC_START_CAPTURE($parser) {
	$parser->echo_save($parser->packet_desc . "\n");
}

// packet 0x19f
function PACKET_CZ_TRYCAPTURE_MONSTER($parser) {
	$parser->echo_save($parser->packet_desc . "targetAID=".$parser->long() . "\n");
}

// packet 0x1a0
function PACKET_ZC_TRYCAPTURE_MONSTER($parser) {
	$parser->echo_save($parser->packet_desc . "result=".$parser->byte() . "\n");
}

// packet 0x1a1
function PACKET_CZ_COMMAND_PET($parser) {
	$parser->echo_save($parser->packet_desc . "cSub=".$parser->byte() . "\n");
}

// packet 0x1a2
function PACKET_ZC_PROPERTY_PET($parser) {
	$parser->echo_save($parser->packet_desc . "szName=".$parser->string(24) . "\n");
	$parser->echo_save($parser->nl . "bModified=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "nLevel=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "nFullness=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "nRelationship=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "ITID=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "job=".$parser->word() . "\n");
}

// packet 0x1a3
function PACKET_ZC_FEED_PET($parser) {
	$parser->echo_save($parser->packet_desc . "cRet=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "ITID=".$parser->word() . "\n");
}

// packet 0x1a4
function PACKET_ZC_CHANGESTATE_PET($parser) {
	$parser->echo_save($parser->packet_desc . "type=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "GID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "data=".$parser->long() . "\n");
}

// packet 0x1a5
function PACKET_CZ_RENAME_PET($parser) {
	$parser->echo_save($parser->packet_desc . "szName=".$parser->string(24) . "\n");
}

// packet 0x1a6
function PACKET_ZC_PETEGG_LIST($parser) {
	$parser->echo_save($parser->packet_desc . "PacketLength=".$parser->word() . "\n");
	$eggList = ($parser->packet_length - $parser->packet_pointer) / 2;
	for ($i = 0; $i < $eggList; $i++) {
		$parser->echo_save($parser->nl . "index=".$parser->word() . "\n");
	}
}

// packet 0x1a7
function PACKET_CZ_SELECT_PETEGG($parser) {
	$parser->echo_save($parser->packet_desc . "index=".$parser->word() . "\n");
}

// packet 0x1a8
function PACKET_CZ_PETEGG_INFO($parser) {
	$parser->echo_save($parser->packet_desc . "index=".$parser->word() . "\n");
}

// packet 0x1a9
function PACKET_CZ_PET_ACT($parser) {
	$parser->echo_save($parser->packet_desc . "data=".$parser->long() . "\n");
}

// packet 0x1aa
function PACKET_ZC_PET_ACT($parser) {
	$parser->echo_save($parser->packet_desc . "GID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "data=".$parser->long() . "\n");
}

// packet 0x1ab
function PACKET_ZC_PAR_CHANGE_USER($parser) {
	$parser->echo_save($parser->packet_desc . "AID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "varID=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "count=".$parser->long() . "\n");
}

// packet 0x1ac
function PACKET_ZC_SKILL_UPDATE($parser) {
	$parser->echo_save($parser->packet_desc . "AID=".$parser->long() . "\n");
}

// packet 0x1ad
function PACKET_ZC_MAKINGARROW_LIST($parser) {
	$parser->echo_save($parser->packet_desc . "PacketLength=".$parser->word() . "\n");
	$arrowList = ($parser->packet_length - $parser->packet_pointer) / 2;
	for ($i = 0; $i < $arrowList; $i++) {
		$parser->echo_save($parser->nl . "index=".$parser->word() . "\n");
	}
}

// packet 0x1ae
function PACKET_CZ_REQ_MAKINGARROW($parser) {
	$parser->echo_save($parser->packet_desc . "id=".$parser->word() . "\n");
}

// packet 0x1af
function PACKET_CZ_REQ_CHANGECART($parser) {
	$parser->echo_save($parser->packet_desc . "num=".$parser->word() . "\n");
}

// packet 0x1b0
function PACKET_ZC_NPCSPRITE_CHANGE($parser) {
	$parser->echo_save($parser->packet_desc . "GID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "type=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "value=".$parser->long() . "\n");
}

// packet 0x1b1
function PACKET_ZC_SHOWDIGIT($parser) {
	$parser->echo_save($parser->packet_desc . "type=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "value=".$parser->long() . "\n");
}

// packet 0x1b2
function PACKET_CZ_REQ_OPENSTORE2($parser) {
	$parser->echo_save($parser->packet_desc . "PacketLength=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "storeName=".$parser->string(80) . "\n");
	$parser->echo_save($parser->nl . "result=".$parser->byte() . "\n");
	$storeList = ($parser->packet_length - $parser->packet_pointer) / 8;
	for ($i = 0; $i < $storeList; $i++) {
		$parser->echo_save($parser->nl . "index=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "count=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "Price=".$parser->long() . "\n");
	}
}

// packet 0x1b3
function PACKET_ZC_SHOW_IMAGE2($parser) {
	$parser->echo_save($parser->packet_desc . "imageName=".$parser->string(64) . "\n");
	$parser->echo_save($parser->nl . "type=".$parser->byte() . "\n");
}

// packet 0x1b4
function PACKET_ZC_CHANGE_GUILD($parser) {
	$parser->echo_save($parser->packet_desc . "AID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "GDID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "emblemVersion=".$parser->word() . "\n");
}

// packet 0x1b5
function PACKET_SC_BILLING_INFO($parser) {
	$parser->echo_save($parser->packet_desc . "dwAmountRemain=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "dwQuantityRemain=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "dwReserved1=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "dwReserved2=".$parser->long() . "\n");
}

// packet 0x1b6
function PACKET_ZC_GUILD_INFO2($parser) {
	$parser->echo_save($parser->packet_desc . "GDID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "level=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "userNum=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "maxUserNum=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "userAverageLevel=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "exp=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "maxExp=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "point=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "honor=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "virtue=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "emblemVersion=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "guildname=".$parser->string(24) . "\n");
	$parser->echo_save($parser->nl . "masterName=".$parser->string(24) . "\n");
	$parser->echo_save($parser->nl . "manageLand=".$parser->string(16) . "\n");
	$parser->echo_save($parser->nl . "zeny=".$parser->long() . "\n");
}

// packet 0x1b7
function PACKET_CZ_GUILD_ZENY($parser) {
	$parser->echo_save($parser->packet_desc . "zeny=".$parser->long() . "\n");
}

// packet 0x1b8
function PACKET_ZC_GUILD_ZENY_ACK($parser) {
	$parser->echo_save($parser->packet_desc . "ret=".$parser->byte() . "\n");
}

// packet 0x1b9
function PACKET_ZC_DISPEL($parser) {
	$parser->echo_save($parser->packet_desc . "AID=".$parser->long() . "\n");
}

// packet 0x1ba
function PACKET_CZ_REMOVE_AID($parser) {
	$parser->echo_save($parser->packet_desc . "AccountName=".$parser->string(24) . "\n");
}

// packet 0x1bb
function PACKET_CZ_SHIFT($parser) {
	$parser->echo_save($parser->packet_desc . "CharacterName=".$parser->string(24) . "\n");
}

// packet 0x1bc
function PACKET_CZ_RECALL($parser) {
	$parser->echo_save($parser->packet_desc . "AccountName=".$parser->string(24) . "\n");
}

// packet 0x1bd
function PACKET_CZ_RECALL_GID($parser) {
	$parser->echo_save($parser->packet_desc . "CharacterName=".$parser->string(24) . "\n");
}

// packet 0x1be
function PACKET_AC_ASK_PNGAMEROOM($parser) {
	$parser->echo_save($parser->packet_desc . "\n");
}

// packet 0x1bf
function PACKET_CA_REPLY_PNGAMEROOM($parser) {
	$parser->echo_save($parser->packet_desc . "Permission=".$parser->byte() . "\n");
}

// packet 0x1c0
function PACKET_CZ_REQ_REMAINTIME($parser) {
	$parser->echo_save($parser->packet_desc . "\n");
}

// packet 0x1c1
function PACKET_ZC_REPLY_REMAINTIME($parser) {
	$parser->echo_save($parser->packet_desc . "Result=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "ExpirationDate=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "RemainTime=".$parser->long() . "\n");
}

// packet 0x1c2
function PACKET_ZC_INFO_REMAINTIME($parser) {
	$parser->echo_save($parser->packet_desc . "Type=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "RemainTime=".$parser->long() . "\n");
}

// packet 0x1c3
function PACKET_ZC_BROADCAST2($parser) {
	$parser->echo_save($parser->packet_desc . "PacketLength=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "fontColor=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "fontType=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "fontSize=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "fontAlign=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "fontY=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "msg=".$parser->string($parser->packet_length - $parser->packet_pointer) . "\n");
}

// packet 0x1c4
function PACKET_ZC_ADD_ITEM_TO_STORE2($parser) {
	$parser->echo_save($parser->packet_desc . "index=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "count=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "ITID=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "type=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "IsIdentified=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "IsDamaged=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "refiningLevel=".$parser->byte() . "\n");
		$parser->echo_save($parser->nl . "card1=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "card2=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "card3=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "card4=".$parser->word() . "\n");
}

// packet 0x1c5
function PACKET_ZC_ADD_ITEM_TO_CART2($parser) {
	$parser->echo_save($parser->packet_desc . "index=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "count=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "ITID=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "type=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "IsIdentified=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "IsDamaged=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "refiningLevel=".$parser->byte() . "\n");
		$parser->echo_save($parser->nl . "card1=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "card2=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "card3=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "card4=".$parser->word() . "\n");
}

// packet 0x1c6
function PACKET_CS_REQ_ENCRYPTION($parser) {
	$parser->echo_save($parser->packet_desc . "encCount=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "decCount=".$parser->byte() . "\n");
}

// packet 0x1c7
function PACKET_SC_ACK_ENCRYPTION($parser) {
	$parser->echo_save($parser->packet_desc . "\n");
}

// packet 0x1c8
function PACKET_ZC_USE_ITEM_ACK2($parser) {
	$parser->echo_save($parser->packet_desc . "index=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "id=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "AID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "count=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "result=".$parser->byte() . "\n");
}

// packet 0x1c9
function PACKET_ZC_SKILL_ENTRY2($parser) {
	$parser->echo_save($parser->packet_desc . "AID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "creatorAID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "xPos=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "yPos=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "job=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "isVisible=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "isContens=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "msg=".$parser->string(80) . "\n");
}

// packet 0x1ca
function PACKET_CZ_REQMAKINGHOMUN($parser) {
	$parser->echo_save($parser->packet_desc . "result=".$parser->byte() . "\n");
}

// packet 0x1cb
function PACKET_CZ_MONSTER_TALK($parser) {
	$parser->echo_save($parser->packet_desc . "GID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "stateId=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "skillId=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "arg1=".$parser->byte() . "\n");
}

// packet 0x1cc
function PACKET_ZC_MONSTER_TALK($parser) {
	$parser->echo_save($parser->packet_desc . "GID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "stateId=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "skillId=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "arg1=".$parser->byte() . "\n");
}

// packet 0x1cd
function PACKET_ZC_AUTOSPELLLIST($parser) {
	$parser->echo_save($parser->packet_desc . "SKID=".$parser->long() . "\n");
}

// packet 0x1ce
function PACKET_CZ_SELECTAUTOSPELL($parser) {
	$parser->echo_save($parser->packet_desc . "SKID=".$parser->long() . "\n");
}

// packet 0x1cf
function PACKET_ZC_DEVOTIONLIST($parser) {
	$parser->echo_save($parser->packet_desc . "myAID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "AID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "range=".$parser->word() . "\n");
}

// packet 0x1d0
function PACKET_ZC_SPIRITS($parser) {
	$parser->echo_save($parser->packet_desc . "AID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "num=".$parser->word() . "\n");
}

// packet 0x1d1
function PACKET_ZC_BLADESTOP($parser) {
	$parser->echo_save($parser->packet_desc . "srcAID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "destAID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "flag=".$parser->long() . "\n");
}

// packet 0x1d2
function PACKET_ZC_COMBODELAY($parser) {
	$parser->echo_save($parser->packet_desc . "AID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "delayTime=".$parser->long() . "\n");
}

// packet 0x1d3
function PACKET_ZC_SOUND($parser) {
	$parser->echo_save($parser->packet_desc . "fileName=".$parser->string(24) . "\n");
	$parser->echo_save($parser->nl . "act=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "term=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "NAID=".$parser->long() . "\n");
}

// packet 0x1d4
function PACKET_ZC_OPEN_EDITDLGSTR($parser) {
	$parser->echo_save($parser->packet_desc . "NAID=".$parser->long() . "\n");
}

// packet 0x1d5
function PACKET_CZ_INPUT_EDITDLGSTR($parser) {
	$parser->echo_save($parser->packet_desc . "PacketLength=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "NAID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "msg=".$parser->string($parser->packet_length - $parser->packet_pointer) . "\n");
}

// packet 0x1d6
function PACKET_ZC_NOTIFY_MAPPROPERTY2($parser) {
	$parser->echo_save($parser->packet_desc . "type=".$parser->word() . "\n");
}

// packet 0x1d7
function PACKET_ZC_SPRITE_CHANGE2($parser) {
	$parser->echo_save($parser->packet_desc . "GID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "type=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "value=".$parser->long() . "\n");
}

// packet 0x1d8
function PACKET_ZC_NOTIFY_STANDENTRY2($parser) {
	$parser->echo_save($parser->packet_desc . "GID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "speed=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "bodyState=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "healthState=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "effectState=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "job=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "head=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "weapon=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "accessory=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "accessory2=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "accessory3=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "headpalette=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "bodypalette=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "headDir=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "GUID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "GEmblemVer=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "honor=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "virtue=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "isPKModeON=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "sex=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "PosDir=".$parser->string(3) . "\n");
	$parser->echo_save($parser->nl . "xSize=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "ySize=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "state=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "clevel=".$parser->word() . "\n");
}

// packet 0x1d9
function PACKET_ZC_NOTIFY_NEWENTRY2($parser) {
	$parser->echo_save($parser->packet_desc . "GID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "speed=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "bodyState=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "healthState=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "effectState=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "job=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "head=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "weapon=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "accessory=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "accessory2=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "accessory3=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "headpalette=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "bodypalette=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "headDir=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "GUID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "GEmblemVer=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "honor=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "virtue=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "isPKModeON=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "sex=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "PosDir=".$parser->string(3) . "\n");
	$parser->echo_save($parser->nl . "xSize=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "ySize=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "clevel=".$parser->word() . "\n");
}

// packet 0x1da
function PACKET_ZC_NOTIFY_MOVEENTRY2($parser) {
	$parser->echo_save($parser->packet_desc . "GID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "speed=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "bodyState=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "healthState=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "effectState=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "job=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "head=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "weapon=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "accessory=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "moveStartTime=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "accessory2=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "accessory3=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "headpalette=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "bodypalette=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "headDir=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "GUID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "GEmblemVer=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "honor=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "virtue=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "isPKModeON=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "sex=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "MoveData=".$parser->string(6) . "\n");
	$parser->echo_save($parser->nl . "xSize=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "ySize=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "clevel=".$parser->word() . "\n");
}

// packet 0x1db
function PACKET_CA_REQ_HASH($parser) {
	$parser->echo_save($parser->packet_desc . "\n");
}

// packet 0x1dc
function PACKET_AC_ACK_HASH($parser) {
	$parser->echo_save($parser->packet_desc . "PacketLength=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "secret=".$parser->string($parser->packet_length - $parser->packet_pointer) . "\n");
}

// packet 0x1dd
function PACKET_CA_LOGIN2($parser) {
	$parser->echo_save($parser->packet_desc . "Version=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "ID=".$parser->string(24) . "\n");
	$parser->echo_save($parser->nl . "PasswdMD5=".$parser->string(16) . "\n");
	$parser->echo_save($parser->nl . "clienttype=".$parser->byte() . "\n");
}

// packet 0x1de
function PACKET_ZC_NOTIFY_SKILL2($parser) {
	$parser->echo_save($parser->packet_desc . "SKID=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "AID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "targetID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "startTime=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "attackMT=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "attackedMT=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "damage=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "level=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "count=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "action=".$parser->byte() . "\n");
}

// packet 0x1df
function PACKET_CZ_REQ_ACCOUNTNAME($parser) {
	$parser->echo_save($parser->packet_desc . "AID=".$parser->long() . "\n");
}

// packet 0x1e0
function PACKET_ZC_ACK_ACCOUNTNAME($parser) {
	$parser->echo_save($parser->packet_desc . "AID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "name=".$parser->string(24) . "\n");
}

// packet 0x1e1
function PACKET_ZC_SPIRITS2($parser) {
	$parser->echo_save($parser->packet_desc . "AID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "num=".$parser->word() . "\n");
}

// packet 0x1e2
function PACKET_ZC_REQ_COUPLE($parser) {
	$parser->echo_save($parser->packet_desc . "AID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "GID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "name=".$parser->string(24) . "\n");
}

// packet 0x1e3
function PACKET_CZ_JOIN_COUPLE($parser) {
	$parser->echo_save($parser->packet_desc . "AID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "GID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "answer=".$parser->long() . "\n");
}

// packet 0x1e4
function PACKET_ZC_START_COUPLE($parser) {
	$parser->echo_save($parser->packet_desc . "\n");
}

// packet 0x1e5
function PACKET_CZ_REQ_JOIN_COUPLE($parser) {
	$parser->echo_save($parser->packet_desc . "AID=".$parser->long() . "\n");
}

// packet 0x1e6
function PACKET_ZC_COUPLENAME($parser) {
	$parser->echo_save($parser->packet_desc . "CoupleName=".$parser->string(24) . "\n");
}

// packet 0x1e7
function PACKET_CZ_DORIDORI($parser) {
	$parser->echo_save($parser->packet_desc . "\n");
}

// packet 0x1e8
function PACKET_CZ_MAKE_GROUP2($parser) {
	$parser->echo_save($parser->packet_desc . "groupName=".$parser->string(24) . "\n");
	$parser->echo_save($parser->nl . "ItemPickupRule=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "ItemDivisionRule=".$parser->byte() . "\n");
}

// packet 0x1e9
function PACKET_ZC_ADD_MEMBER_TO_GROUP2($parser) {
	$parser->echo_save($parser->packet_desc . "AID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "Role=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "xPos=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "yPos=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "state=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "groupName=".$parser->string(24) . "\n");
	$parser->echo_save($parser->nl . "characterName=".$parser->string(24) . "\n");
	$parser->echo_save($parser->nl . "mapName=".$parser->string(16) . "\n");
	$parser->echo_save($parser->nl . "ItemPickupRule=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "ItemDivisionRule=".$parser->byte() . "\n");
}

// packet 0x1ea
function PACKET_ZC_CONGRATULATION($parser) {
	$parser->echo_save($parser->packet_desc . "AID=".$parser->long() . "\n");
}

// packet 0x1eb
function PACKET_ZC_NOTIFY_POSITION_TO_GUILDM($parser) {
	$parser->echo_save($parser->packet_desc . "AID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "xPos=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "yPos=".$parser->word() . "\n");
}

// packet 0x1ec
function PACKET_ZC_GUILD_MEMBER_MAP_CHANGE($parser) {
	$parser->echo_save($parser->packet_desc . "GDID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "AID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "mapName=".$parser->string(16) . "\n");
}

// packet 0x1ed
function PACKET_CZ_CHOPOKGI($parser) {
	$parser->echo_save($parser->packet_desc . "\n");
}

// packet 0x1ee
function PACKET_ZC_NORMAL_ITEMLIST2($parser) {
	$parser->echo_save($parser->packet_desc . "PacketLength=".$parser->word() . "\n");
	$ItemInfo = ($parser->packet_length - $parser->packet_pointer) / 18;
	for ($i = 0; $i < $ItemInfo; $i++) {
		$parser->echo_save($parser->nl . "index=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "ITID=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "type=".$parser->byte() . "\n");
		$parser->echo_save($parser->nl . "IsIdentified=".$parser->byte() . "\n");
		$parser->echo_save($parser->nl . "count=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "WearState=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "card1=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "card2=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "card3=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "card4=".$parser->word() . "\n");
	}
}

// packet 0x1ef
function PACKET_ZC_CART_NORMAL_ITEMLIST2($parser) {
	$parser->echo_save($parser->packet_desc . "PacketLength=".$parser->word() . "\n");
	$ItemInfo = ($parser->packet_length - $parser->packet_pointer) / 18;
	for ($i = 0; $i < $ItemInfo; $i++) {
		$parser->echo_save($parser->nl . "index=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "ITID=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "type=".$parser->byte() . "\n");
		$parser->echo_save($parser->nl . "IsIdentified=".$parser->byte() . "\n");
		$parser->echo_save($parser->nl . "count=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "WearState=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "card1=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "card2=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "card3=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "card4=".$parser->word() . "\n");
	}
}

// packet 0x1f0
function PACKET_ZC_STORE_NORMAL_ITEMLIST2($parser) {
	$parser->echo_save($parser->packet_desc . "PacketLength=".$parser->word() . "\n");
	$ItemInfo = ($parser->packet_length - $parser->packet_pointer) / 18;
	for ($i = 0; $i < $ItemInfo; $i++) {
		$parser->echo_save($parser->nl . "index=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "ITID=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "type=".$parser->byte() . "\n");
		$parser->echo_save($parser->nl . "IsIdentified=".$parser->byte() . "\n");
		$parser->echo_save($parser->nl . "count=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "WearState=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "card1=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "card2=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "card3=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "card4=".$parser->word() . "\n");
	}
}

// packet 0x1f1
function PACKET_AC_NOTIFY_ERROR($parser) {
	$parser->echo_save($parser->packet_desc . "PacketLength=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "msg=".$parser->string($parser->packet_length - $parser->packet_pointer) . "\n");
}

// packet 0x1f2
function PACKET_ZC_UPDATE_CHARSTAT2($parser) {
	$parser->echo_save($parser->packet_desc . "AID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "GID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "status=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "sex=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "head=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "headPalette=".$parser->word() . "\n");
}

// packet 0x1f3
function PACKET_ZC_NOTIFY_EFFECT2($parser) {
	$parser->echo_save($parser->packet_desc . "AID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "effectID=".$parser->long() . "\n");
}

// packet 0x1f4
function PACKET_ZC_REQ_EXCHANGE_ITEM2($parser) {
	$parser->echo_save($parser->packet_desc . "name=".$parser->string(24) . "\n");
	$parser->echo_save($parser->nl . "GID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "level=".$parser->word() . "\n");
}

// packet 0x1f5
function PACKET_ZC_ACK_EXCHANGE_ITEM2($parser) {
	$parser->echo_save($parser->packet_desc . "result=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "GID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "level=".$parser->word() . "\n");
}

// packet 0x1f6
function PACKET_ZC_REQ_BABY($parser) {
	$parser->echo_save($parser->packet_desc . "AID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "GID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "name=".$parser->string(24) . "\n");
}

// packet 0x1f7
function PACKET_CZ_JOIN_BABY($parser) {
	$parser->echo_save($parser->packet_desc . "AID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "GID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "answer=".$parser->long() . "\n");
}

// packet 0x1f8
function PACKET_ZC_START_BABY($parser) {
	$parser->echo_save($parser->packet_desc . "\n");
}

// packet 0x1f9
function PACKET_CZ_REQ_JOIN_BABY($parser) {
	$parser->echo_save($parser->packet_desc . "AID=".$parser->long() . "\n");
}

// packet 0x1fa
function PACKET_CA_LOGIN3($parser) {
	$parser->echo_save($parser->packet_desc . "Version=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "ID=".$parser->string(24) . "\n");
	$parser->echo_save($parser->nl . "PasswdMD5=".$parser->string(16) . "\n");
	$parser->echo_save($parser->nl . "clienttype=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "ClientInfo=".$parser->byte() . "\n");
}

// packet 0x1fb
function PACKET_CH_DELETE_CHAR2($parser) {
	$parser->echo_save($parser->packet_desc . "GID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "key=".$parser->string(50) . "\n");
}

// packet 0x1fc
function PACKET_ZC_REPAIRITEMLIST($parser) {
	$parser->echo_save($parser->packet_desc . "PacketLength=".$parser->word() . "\n");
	$itemList = ($parser->packet_length - $parser->packet_pointer) / 13;
	for ($i = 0; $i < $itemList; $i++) {
		$parser->echo_save($parser->nl . "index=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "ITID=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "refiningLevel=".$parser->byte() . "\n");
		$parser->echo_save($parser->nl . "card1=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "card2=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "card3=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "card4=".$parser->word() . "\n");
	}
}

// packet 0x1fd
function PACKET_CZ_REQ_ITEMREPAIR($parser) {
	$parser->echo_save($parser->packet_desc  . "\n");
		$parser->echo_save($parser->nl . "index=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "ITID=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "refiningLevel=".$parser->byte() . "\n");
		$parser->echo_save($parser->nl . "card1=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "card2=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "card3=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "card4=".$parser->word() . "\n");
}

// packet 0x1fe
function PACKET_ZC_ACK_ITEMREPAIR($parser) {
	$parser->echo_save($parser->packet_desc . "index=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "result=".$parser->byte() . "\n");
}

// packet 0x1ff
function PACKET_ZC_HIGHJUMP($parser) {
	$parser->echo_save($parser->packet_desc . "AID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "xPos=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "yPos=".$parser->word() . "\n");
}

// packet 0x200
function PACKET_CA_CONNECT_INFO_CHANGED($parser) {
	$parser->echo_save($parser->packet_desc . "ID=".$parser->string(24) . "\n");
}

// packet 0x201
function PACKET_ZC_FRIENDS_LIST($parser) {
	$parser->echo_save($parser->packet_desc . "PacketLength=".$parser->word() . "\n");
	$friendList = ($parser->packet_length - $parser->packet_pointer) / 32;
	for ($i = 0; $i < $friendList; $i++) {
		$parser->echo_save($parser->nl . "AID=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "GID=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "Name=".$parser->string(24) . "\n");
	}
}

// packet 0x202
function PACKET_CZ_ADD_FRIENDS($parser) {
	$parser->echo_save($parser->packet_desc . "name=".$parser->string(24) . "\n");
}

// packet 0x203
function PACKET_CZ_DELETE_FRIENDS($parser) {
	$parser->echo_save($parser->packet_desc . "AID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "GID=".$parser->long() . "\n");
}

// packet 0x204
function PACKET_CA_EXE_HASHCHECK($parser) {
	$parser->echo_save($parser->packet_desc . "HashValue=".$parser->string(16) . "\n");
}

// packet 0x205
function PACKET_ZC_DIVORCE($parser) {
	$parser->echo_save($parser->packet_desc . "name=".$parser->string(24) . "\n");
}

// packet 0x206
function PACKET_ZC_FRIENDS_STATE($parser) {
	$parser->echo_save($parser->packet_desc . "AID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "GID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "State=".$parser->byte() . "\n");
}

// packet 0x207
function PACKET_ZC_REQ_ADD_FRIENDS($parser) {
	$parser->echo_save($parser->packet_desc . "ReqAID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "ReqGID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "Name=".$parser->string(24) . "\n");
}

// packet 0x208
function PACKET_CZ_ACK_REQ_ADD_FRIENDS($parser) {
	$parser->echo_save($parser->packet_desc . "ReqAID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "ReqGID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "Result=".$parser->long() . "\n");
}

// packet 0x209
function PACKET_ZC_ADD_FRIENDS_LIST($parser) {
	$parser->echo_save($parser->packet_desc . "Result=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "AID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "GID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "Name=".$parser->string(24) . "\n");
}

// packet 0x20a
function PACKET_ZC_DELETE_FRIENDS($parser) {
	$parser->echo_save($parser->packet_desc . "AID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "GID=".$parser->long() . "\n");
}

// packet 0x20b
function PACKET_CH_EXE_HASHCHECK($parser) {
	$parser->echo_save($parser->packet_desc . "ClientType=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "HashValue=".$parser->string(16) . "\n");
}

// packet 0x20c
function PACKET_CZ_EXE_HASHCHECK($parser) {
	$parser->echo_save($parser->packet_desc . "ClientType=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "HashValue=".$parser->string(16) . "\n");
}

// packet 0x20d
function PACKET_HC_BLOCK_CHARACTER($parser) {
	$parser->echo_save($parser->packet_desc . "PacketLength=".$parser->word() . "\n");
	$characterList = ($parser->packet_length - $parser->packet_pointer) / 24;
	for ($i = 0; $i < $characterList; $i++) {
		$parser->echo_save($parser->nl . "GID=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "szExpireDate=".$parser->string(20) . "\n");
	}
}

// packet 0x20e
function PACKET_ZC_STARSKILL($parser) {
	$parser->echo_save($parser->packet_desc . "mapName=".$parser->string(24) . "\n");
	$parser->echo_save($parser->nl . "monsterID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "star=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "result=".$parser->byte() . "\n");
}

// packet 0x20f
function PACKET_CZ_REQ_PVPPOINT($parser) {
	$parser->echo_save($parser->packet_desc . "AID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "GID=".$parser->long() . "\n");
}

// packet 0x210
function PACKET_ZC_ACK_PVPPOINT($parser) {
	$parser->echo_save($parser->packet_desc . "AID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "GID=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "WinPoint=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "LosePoint=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "Point=".$parser->long() . "\n");
}

// packet 0x211
function PACKET_ZH_MOVE_PVPWORLD($parser) {
	$parser->echo_save($parser->packet_desc . "GID=".$parser->long() . "\n");
}

// packet 0x212
function PACKET_CZ_REQ_GIVE_MANNER_BYNAME($parser) {
	$parser->echo_save($parser->packet_desc . "CharName=".$parser->string(24) . "\n");
}

// packet 0x213
function PACKET_CZ_REQ_STATUS_GM($parser) {
	$parser->echo_save($parser->packet_desc . "CharName=".$parser->string(24) . "\n");
}

// packet 0x214
function PACKET_ZC_ACK_STATUS_GM($parser) {
	$parser->echo_save($parser->packet_desc . "str=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "standardStr=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "agi=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "standardAgi=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "vit=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "standardVit=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "Int=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "standardInt=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "dex=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "standardDex=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "luk=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "standardLuk=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "attPower=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "refiningPower=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "max_mattPower=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "min_mattPower=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "itemdefPower=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "plusdefPower=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "mdefPower=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "plusmdefPower=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "hitSuccessValue=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "avoidSuccessValue=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "plusAvoidSuccessValue=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "criticalSuccessValue=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "ASPD=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "plusASPD=".$parser->word() . "\n");
}

// packet 0x215
function PACKET_ZC_SKILLMSG($parser) {
	$parser->echo_save($parser->packet_desc . "MsgNo=".$parser->long() . "\n");
}

// packet 0x216
function PACKET_ZC_BABYMSG($parser) {
	$parser->echo_save($parser->packet_desc . "MsgNo=".$parser->long() . "\n");
}

// packet 0x217
function PACKET_CZ_BLACKSMITH_RANK($parser) {
	$parser->echo_save($parser->packet_desc . "\n");
}

// packet 0x218
function PACKET_CZ_ALCHEMIST_RANK($parser) {
	$parser->echo_save($parser->packet_desc . "\n");
}

// packet 0x219
function PACKET_ZC_BLACKSMITH_RANK($parser) {
	$parser->echo_save($parser->packet_desc . "Name=".$parser->string(24) . "\n");
	$parser->echo_save($parser->nl . "Point=".$parser->long() . "\n");
}

// packet 0x21a
function PACKET_ZC_ALCHEMIST_RANK($parser) {
	$parser->echo_save($parser->packet_desc . "Name=".$parser->string(24) . "\n");
	$parser->echo_save($parser->nl . "Point=".$parser->long() . "\n");
}

// packet 0x21b
function PACKET_ZC_BLACKSMITH_POINT($parser) {
	$parser->echo_save($parser->packet_desc . "Point=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "TotalPoint=".$parser->long() . "\n");
}

// packet 0x21c
function PACKET_ZC_ALCHEMIST_POINT($parser) {
	$parser->echo_save($parser->packet_desc . "Point=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "TotalPoint=".$parser->long() . "\n");
}

// packet 0x21d
function PACKET_CZ_LESSEFFECT($parser) {
	$parser->echo_save($parser->packet_desc . "isLess=".$parser->long() . "\n");
}

// packet 0x21e
function PACKET_ZC_LESSEFFECT($parser) {
	$parser->echo_save($parser->packet_desc . "isLess=".$parser->long() . "\n");
}

// packet 0x21f
function PACKET_ZC_NOTIFY_PKINFO($parser) {
	$parser->echo_save($parser->packet_desc . "winPoint=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "losePoint=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "killName=".$parser->string(24) . "\n");
	$parser->echo_save($parser->nl . "killedName=".$parser->string(24) . "\n");
		$parser->echo_save($parser->nl . "dwLowDateTime=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "dwHighDateTime=".$parser->long() . "\n");
}

// packet 0x220
function PACKET_ZC_NOTIFY_CRAZYKILLER($parser) {
	$parser->echo_save($parser->packet_desc . "AID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "isCrazyKiller=".$parser->long() . "\n");
}

// packet 0x221
function PACKET_ZC_NOTIFY_WEAPONITEMLIST($parser) {
	$parser->echo_save($parser->packet_desc . "PacketLength=".$parser->word() . "\n");
	$itemList = ($parser->packet_length - $parser->packet_pointer) / 13;
	for ($i = 0; $i < $itemList; $i++) {
		$parser->echo_save($parser->nl . "index=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "ITID=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "refiningLevel=".$parser->byte() . "\n");
		$parser->echo_save($parser->nl . "card1=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "card2=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "card3=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "card4=".$parser->word() . "\n");
	}
}

// packet 0x222
function PACKET_CZ_REQ_WEAPONREFINE($parser) {
	$parser->echo_save($parser->packet_desc . "Index=".$parser->long() . "\n");
}

// packet 0x223
function PACKET_ZC_ACK_WEAPONREFINE($parser) {
	$parser->echo_save($parser->packet_desc . "msg=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "ITID=".$parser->word() . "\n");
}

// packet 0x224
function PACKET_ZC_TAEKWON_POINT($parser) {
	$parser->echo_save($parser->packet_desc . "Point=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "TotalPoint=".$parser->long() . "\n");
}

// packet 0x225
function PACKET_CZ_TAEKWON_RANK($parser) {
	$parser->echo_save($parser->packet_desc . "\n");
}

// packet 0x226
function PACKET_ZC_TAEKWON_RANK($parser) {
	$parser->echo_save($parser->packet_desc . "Name=".$parser->string(24) . "\n");
	$parser->echo_save($parser->nl . "Point=".$parser->long() . "\n");
}

// packet 0x227
function PACKET_ZC_GAME_GUARD($parser) {
	$parser->echo_save($parser->packet_desc . "AuthData=".$parser->long() . "\n");
}

// packet 0x228
function PACKET_CZ_ACK_GAME_GUARD($parser) {
	$parser->echo_save($parser->packet_desc . "AuthData=".$parser->long() . "\n");
}

// packet 0x229
function PACKET_ZC_STATE_CHANGE3($parser) {
	$parser->echo_save($parser->packet_desc . "AID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "bodyState=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "healthState=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "effectState=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "isPKModeON=".$parser->byte() . "\n");
}

// packet 0x22a
function PACKET_ZC_NOTIFY_STANDENTRY3($parser) {
	$parser->echo_save($parser->packet_desc . "GID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "speed=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "bodyState=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "healthState=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "effectState=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "job=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "head=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "weapon=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "accessory=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "accessory2=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "accessory3=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "headpalette=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "bodypalette=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "headDir=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "GUID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "GEmblemVer=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "honor=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "virtue=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "isPKModeON=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "sex=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "PosDir=".$parser->string(3) . "\n");
	$parser->echo_save($parser->nl . "xSize=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "ySize=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "state=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "clevel=".$parser->word() . "\n");
}

// packet 0x22b
function PACKET_ZC_NOTIFY_NEWENTRY3($parser) {
	$parser->echo_save($parser->packet_desc . "GID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "speed=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "bodyState=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "healthState=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "effectState=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "job=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "head=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "weapon=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "accessory=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "accessory2=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "accessory3=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "headpalette=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "bodypalette=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "headDir=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "GUID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "GEmblemVer=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "honor=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "virtue=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "isPKModeON=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "sex=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "PosDir=".$parser->string(3) . "\n");
	$parser->echo_save($parser->nl . "xSize=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "ySize=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "clevel=".$parser->word() . "\n");
}

// packet 0x22c
function PACKET_ZC_NOTIFY_MOVEENTRY3($parser) {
	$parser->echo_save($parser->packet_desc . "objecttype=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "GID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "speed=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "bodyState=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "healthState=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "effectState=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "job=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "head=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "weapon=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "accessory=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "moveStartTime=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "accessory2=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "accessory3=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "headpalette=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "bodypalette=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "headDir=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "GUID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "GEmblemVer=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "honor=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "virtue=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "isPKModeON=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "sex=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "MoveData=".$parser->string(6) . "\n");
	$parser->echo_save($parser->nl . "xSize=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "ySize=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "clevel=".$parser->word() . "\n");
}

// packet 0x22d
function PACKET_CZ_COMMAND_MER($parser) {
	$parser->echo_save($parser->packet_desc . "type=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "command=".$parser->byte() . "\n");
}

// packet 0x22e
function PACKET_ZC_PROPERTY_HOMUN($parser) {
	$parser->echo_save($parser->packet_desc . "szName=".$parser->string(24) . "\n");
	$parser->echo_save($parser->nl . "bModified=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "nLevel=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "nFullness=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "nRelationship=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "ITID=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "atk=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "Matk=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "hit=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "critical=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "def=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "Mdef=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "flee=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "aspd=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "hp=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "maxHP=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "sp=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "maxSP=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "exp=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "maxEXP=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "SKPoint=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "ATKRange=".$parser->word() . "\n");
}

// packet 0x230
function PACKET_ZC_CHANGESTATE_MER($parser) {
	$parser->echo_save($parser->packet_desc . "type=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "state=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "GID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "data=".$parser->long() . "\n");
}

// packet 0x231
function PACKET_CZ_RENAME_MER($parser) {
	$parser->echo_save($parser->packet_desc . "name=".$parser->string(24) . "\n");
}

// packet 0x232
function PACKET_CZ_REQUEST_MOVENPC($parser) {
	$parser->echo_save($parser->packet_desc . "GID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "dest=".$parser->string(3) . "\n");
}

// packet 0x233
function PACKET_CZ_REQUEST_ACTNPC($parser) {
	$parser->echo_save($parser->packet_desc . "GID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "targetGID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "action=".$parser->byte() . "\n");
}

// packet 0x234
function PACKET_CZ_REQUEST_MOVETOOWNER($parser) {
	$parser->echo_save($parser->packet_desc . "GID=".$parser->long() . "\n");
}

// packet 0x23a
function PACKET_ZC_REQ_STORE_PASSWORD($parser) {
	$parser->echo_save($parser->packet_desc . "Info=".$parser->word() . "\n");
}

// packet 0x23b
function PACKET_CZ_ACK_STORE_PASSWORD($parser) {
	$parser->echo_save($parser->packet_desc . "Type=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "Password=".$parser->string(16) . "\n");
	$parser->echo_save($parser->nl . "NewPassword=".$parser->string(16) . "\n");
}

// packet 0x23c
function PACKET_ZC_RESULT_STORE_PASSWORD($parser) {
	$parser->echo_save($parser->packet_desc . "Result=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "ErrorCount=".$parser->word() . "\n");
}

// packet 0x23d
function PACKET_AC_EVENT_RESULT($parser) {
	$parser->echo_save($parser->packet_desc . "EventItemCount=".$parser->long() . "\n");
}

// packet 0x23e
function PACKET_HC_REQUEST_CHARACTER_PASSWORD($parser) {
	$parser->echo_save($parser->packet_desc . "Result=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "dummyValue=".$parser->long() . "\n");
}

// packet 0x23f
function PACKET_CZ_MAIL_GET_LIST($parser) {
	$parser->echo_save($parser->packet_desc . "\n");
}

// packet 0x240
function PACKET_ZC_MAIL_REQ_GET_LIST($parser) {
	$parser->echo_save($parser->packet_desc . "PacketLength=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "MailNumber=".$parser->long() . "\n");
	$mailList = ($parser->packet_length - $parser->packet_pointer) / 73;
	for ($i = 0; $i < $mailList; $i++) {
		$parser->echo_save($parser->nl . "MailID=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "HEADER=".$parser->string(40) . "\n");
		$parser->echo_save($parser->nl . "isOpen=".$parser->byte() . "\n");
		$parser->echo_save($parser->nl . "FromName=".$parser->string(24) . "\n");
		$parser->echo_save($parser->nl . "DeleteTime=".$parser->long() . "\n");
	}
}

// packet 0x241
function PACKET_CZ_MAIL_OPEN($parser) {
	$parser->echo_save($parser->packet_desc . "MailID=".$parser->long() . "\n");
}

// packet 0x242
function PACKET_ZC_MAIL_REQ_OPEN($parser) {
	$parser->echo_save($parser->packet_desc . "PacketLength=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "MailID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "Header=".$parser->string(40) . "\n");
	$parser->echo_save($parser->nl . "FromName=".$parser->string(24) . "\n");
	$parser->echo_save($parser->nl . "DeleteTime=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "Money=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "count=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "ITID=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "Type=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "IsIdentified=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "IsDamaged=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "refiningLevel=".$parser->byte() . "\n");
		$parser->echo_save($parser->nl . "card1=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "card2=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "card3=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "card4=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "msg_len=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "msg=".$parser->string($parser->packet_length - $parser->packet_pointer) . "\n");
}

// packet 0x243
function PACKET_CZ_MAIL_DELETE($parser) {
	$parser->echo_save($parser->packet_desc . "MailID=".$parser->long() . "\n");
}

// packet 0x244
function PACKET_CZ_MAIL_GET_ITEM($parser) {
	$parser->echo_save($parser->packet_desc . "MailID=".$parser->long() . "\n");
}

// packet 0x245
function PACKET_ZC_MAIL_REQ_GET_ITEM($parser) {
	$parser->echo_save($parser->packet_desc . "Result=".$parser->byte() . "\n");
}

// packet 0x246
function PACKET_CZ_MAIL_RESET_ITEM($parser) {
	$parser->echo_save($parser->packet_desc . "Type=".$parser->word() . "\n");
}

// packet 0x247
function PACKET_CZ_MAIL_ADD_ITEM($parser) {
	$parser->echo_save($parser->packet_desc . "index=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "count=".$parser->long() . "\n");
}

// packet 0x248
function PACKET_CZ_MAIL_SEND($parser) {
	$parser->echo_save($parser->packet_desc . "PacketLength=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "ReceiveName=".$parser->string(24) . "\n");
	$parser->echo_save($parser->nl . "Header=".$parser->string(40) . "\n");
	$parser->echo_save($parser->nl . "msg_len=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "msg=".$parser->string($parser->packet_length - $parser->packet_pointer) . "\n");
}

// packet 0x249
function PACKET_ZC_MAIL_REQ_SEND($parser) {
	$parser->echo_save($parser->packet_desc . "Result=".$parser->byte() . "\n");
}

// packet 0x24a
function PACKET_ZC_MAIL_RECEIVE($parser) {
	$parser->echo_save($parser->packet_desc . "MailID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "Header=".$parser->string(40) . "\n");
	$parser->echo_save($parser->nl . "FromName=".$parser->string(24) . "\n");
}

// packet 0x24b
function PACKET_CZ_AUCTION_CREATE($parser) {
	$parser->echo_save($parser->packet_desc . "Type=".$parser->word() . "\n");
}

// packet 0x24c
function PACKET_CZ_AUCTION_ADD_ITEM($parser) {
	$parser->echo_save($parser->packet_desc . "index=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "count=".$parser->long() . "\n");
}

// packet 0x24d
function PACKET_CZ_AUCTION_ADD($parser) {
	$parser->echo_save($parser->packet_desc . "NowMoney=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "MaxMoney=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "DeleteHour=".$parser->word() . "\n");
}

// packet 0x24e
function PACKET_CZ_AUCTION_ADD_CANCEL($parser) {
	$parser->echo_save($parser->packet_desc . "AuctionID=".$parser->long() . "\n");
}

// packet 0x24f
function PACKET_CZ_AUCTION_BUY($parser) {
	$parser->echo_save($parser->packet_desc . "AuctionID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "Money=".$parser->long() . "\n");
}

// packet 0x250
function PACKET_ZC_AUCTION_RESULT($parser) {
	$parser->echo_save($parser->packet_desc . "Result=".$parser->byte() . "\n");
}

// packet 0x251
function PACKET_CZ_AUCTION_ITEM_SEARCH($parser) {
	$parser->echo_save($parser->packet_desc . "Type=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "AuctionID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "Name=".$parser->string(24) . "\n");
	$parser->echo_save($parser->nl . "Page=".$parser->word() . "\n");
}

// packet 0x252
function PACKET_ZC_AUCTION_ITEM_REQ_SEARCH($parser) {
	$parser->echo_save($parser->packet_desc . "PacketLength=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "MaxPage=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "Number=".$parser->long() . "\n");
	$auctionItemList = ($parser->packet_length - $parser->packet_pointer) / 83;
	for ($i = 0; $i < $auctionItemList; $i++) {
		$parser->echo_save($parser->nl . "AuctionID=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "SellerName=".$parser->string(24) . "\n");
		$parser->echo_save($parser->nl . "ITID=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "Type=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "count=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "IsIdentified=".$parser->byte() . "\n");
		$parser->echo_save($parser->nl . "IsDamaged=".$parser->byte() . "\n");
		$parser->echo_save($parser->nl . "refiningLevel=".$parser->byte() . "\n");
		$parser->echo_save($parser->nl . "card1=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "card2=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "card3=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "card4=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "NowPrice=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "MaxPrice=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "BuyerName=".$parser->string(24) . "\n");
		$parser->echo_save($parser->nl . "DeleteTime=".$parser->long() . "\n");
	}
}

// packet 0x253
function PACKET_ZC_STARPLACE($parser) {
	$parser->echo_save($parser->packet_desc . "which=".$parser->byte() . "\n");
}

// packet 0x254
function PACKET_CZ_AGREE_STARPLACE($parser) {
	$parser->echo_save($parser->packet_desc . "which=".$parser->byte() . "\n");
}

// packet 0x255
function PACKET_ZC_ACK_MAIL_ADD_ITEM($parser) {
	$parser->echo_save($parser->packet_desc . "Index=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "result=".$parser->byte() . "\n");
}

// packet 0x256
function PACKET_ZC_ACK_AUCTION_ADD_ITEM($parser) {
	$parser->echo_save($parser->packet_desc . "Index=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "result=".$parser->byte() . "\n");
}

// packet 0x257
function PACKET_ZC_ACK_MAIL_DELETE($parser) {
	$parser->echo_save($parser->packet_desc . "MailID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "Result=".$parser->word() . "\n");
}

// packet 0x258
function PACKET_CA_REQ_GAME_GUARD_CHECK($parser) {
	$parser->echo_save($parser->packet_desc . "\n");
}

// packet 0x259
function PACKET_AC_ACK_GAME_GUARD($parser) {
	$parser->echo_save($parser->packet_desc . "ucAnswer=".$parser->byte() . "\n");
}

// packet 0x25a
function PACKET_ZC_MAKINGITEM_LIST($parser) {
	$parser->echo_save($parser->packet_desc . "PacketLength=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "idList=".$parser->word() . "\n");
}

// packet 0x25b
function PACKET_CZ_REQ_MAKINGITEM($parser) {
	$parser->echo_save($parser->packet_desc . "mkType=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "id=".$parser->word() . "\n");
}

// packet 0x25c
function PACKET_CZ_AUCTION_REQ_MY_INFO($parser) {
	$parser->echo_save($parser->packet_desc . "Type=".$parser->word() . "\n");
}

// packet 0x25d
function PACKET_CZ_AUCTION_REQ_MY_SELL_STOP($parser) {
	$parser->echo_save($parser->packet_desc . "AuctionID=".$parser->long() . "\n");
}

// packet 0x25e
function PACKET_ZC_AUCTION_ACK_MY_SELL_STOP($parser) {
	$parser->echo_save($parser->packet_desc . "Result=".$parser->word() . "\n");
}

// packet 0x25f
function PACKET_ZC_AUCTION_WINDOWS($parser) {
	$parser->echo_save($parser->packet_desc . "Type=".$parser->long() . "\n");
}

// packet 0x260
function PACKET_ZC_MAIL_WINDOWS($parser) {
	$parser->echo_save($parser->packet_desc . "Type=".$parser->long() . "\n");
}

// packet 0x261
function PACKET_AC_REQ_LOGIN_OLDEKEY($parser) {
	$parser->echo_save($parser->packet_desc . "m_SeedValue=".$parser->string(9) . "\n");
}

// packet 0x262
function PACKET_AC_REQ_LOGIN_NEWEKEY($parser) {
	$parser->echo_save($parser->packet_desc . "m_SeedValue=".$parser->string(9) . "\n");
}

// packet 0x263
function PACKET_AC_REQ_LOGIN_CARDPASS($parser) {
	$parser->echo_save($parser->packet_desc . "m_SeedValue=".$parser->string(9) . "\n");
}

// packet 0x264
function PACKET_CA_ACK_LOGIN_OLDEKEY($parser) {
	$parser->echo_save($parser->packet_desc . "m_SeedValue=".$parser->string(9) . "\n");
	$parser->echo_save($parser->nl . "m_EKey=".$parser->string(9) . "\n");
}

// packet 0x265
function PACKET_CA_ACK_LOGIN_NEWEKEY($parser) {
	$parser->echo_save($parser->packet_desc . "m_SeedValue=".$parser->string(9) . "\n");
	$parser->echo_save($parser->nl . "m_EKey=".$parser->string(9) . "\n");
}

// packet 0x266
function PACKET_CA_ACK_LOGIN_CARDPASS($parser) {
	$parser->echo_save($parser->packet_desc . "m_cardPass=".$parser->string(28) . "\n");
}

// packet 0x267
function PACKET_AC_ACK_EKEY_FAIL_NOTEXIST($parser) {
	$parser->echo_save($parser->packet_desc . "errorCode=".$parser->word() . "\n");
}

// packet 0x268
function PACKET_AC_ACK_EKEY_FAIL_NOTUSESEKEY($parser) {
	$parser->echo_save($parser->packet_desc . "errorCode=".$parser->word() . "\n");
}

// packet 0x269
function PACKET_AC_ACK_EKEY_FAIL_NOTUSEDEKEY($parser) {
	$parser->echo_save($parser->packet_desc . "errorCode=".$parser->word() . "\n");
}

// packet 0x26a
function PACKET_AC_ACK_EKEY_FAIL_AUTHREFUSE($parser) {
	$parser->echo_save($parser->packet_desc . "errorCode=".$parser->word() . "\n");
}

// packet 0x26b
function PACKET_AC_ACK_EKEY_FAIL_INPUTEKEY($parser) {
	$parser->echo_save($parser->packet_desc . "errorCode=".$parser->word() . "\n");
}

// packet 0x26c
function PACKET_AC_ACK_EKEY_FAIL_NOTICE($parser) {
	$parser->echo_save($parser->packet_desc . "errorCode=".$parser->word() . "\n");
}

// packet 0x26d
function PACKET_AC_ACK_EKEY_FAIL_NEEDCARDPASS($parser) {
	$parser->echo_save($parser->packet_desc . "errorCode=".$parser->word() . "\n");
}

// packet 0x26e
function PACKET_AC_ACK_AUTHEKEY_FAIL_NOTMATCHCARDPASS($parser) {
	$parser->echo_save($parser->packet_desc . "errorCode=".$parser->word() . "\n");
}

// packet 0x26f
function PACKET_AC_ACK_FIRST_LOGIN($parser) {
	$parser->echo_save($parser->packet_desc . "\n");
}

// packet 0x270
function PACKET_AC_REQ_LOGIN_ACCOUNT_INFO($parser) {
	$parser->echo_save($parser->packet_desc . "\n");
}

// packet 0x271
function PACKET_CA_ACK_LOGIN_ACCOUNT_INFO($parser) {
	$parser->echo_save($parser->packet_desc . "sex=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "bPoint=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "E_mail=".$parser->string(34) . "\n");
}

// packet 0x272
function PACKET_AC_ACK_PT_ID_INFO($parser) {
	$parser->echo_save($parser->packet_desc . "szPTID=".$parser->string(21) . "\n");
	$parser->echo_save($parser->nl . "szPTNumID=".$parser->string(21) . "\n");
}

// packet 0x273
function PACKET_CZ_REQ_MAIL_RETURN($parser) {
	$parser->echo_save($parser->packet_desc . "MailID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "ReceiveName=".$parser->string(24) . "\n");
}

// packet 0x274
function PACKET_ZC_ACK_MAIL_RETURN($parser) {
	$parser->echo_save($parser->packet_desc . "MailID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "Result=".$parser->word() . "\n");
}

// packet 0x275
function PACKET_CH_ENTER2($parser) {
	$parser->echo_save($parser->packet_desc . "AID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "AuthCode=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "userLevel=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "clientType=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "Sex=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "macData=".$parser->string(16) . "\n");
	$parser->echo_save($parser->nl . "iAccountSID=".$parser->long() . "\n");
}

// packet 0x276
function PACKET_AC_ACCEPT_LOGIN2($parser) {
	$parser->echo_save($parser->packet_desc . "PacketLength=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "AuthCode=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "AID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "userLevel=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "lastLoginIP=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "lastLoginTime=".$parser->string(26) . "\n");
	$parser->echo_save($parser->nl . "Sex=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "iAccountSID=".$parser->long() . "\n");
}

// packet 0x277
function PACKET_CA_LOGIN_PCBANG($parser) {
	$parser->echo_save($parser->packet_desc . "Version=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "ID=".$parser->string(24) . "\n");
	$parser->echo_save($parser->nl . "Passwd=".$parser->string(24) . "\n");
	$parser->echo_save($parser->nl . "clienttype=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "IP=".$parser->string(16) . "\n");
	$parser->echo_save($parser->nl . "MacAdress=".$parser->string(13) . "\n");
}

// packet 0x278
function PACKET_ZC_NOTIFY_PCBANG($parser) {
	$parser->echo_save($parser->packet_desc . "\n");
}

// packet 0x279
function PACKET_CZ_HUNTINGLIST($parser) {
	$parser->echo_save($parser->packet_desc . "\n");
}

// packet 0x27a
function PACKET_ZC_HUNTINGLIST($parser) {
	$parser->echo_save($parser->packet_desc . "PacketLength=".$parser->word() . "\n");
	$HuntingList = ($parser->packet_length - $parser->packet_pointer) / 12;
	for ($i = 0; $i < $HuntingList; $i++) {
		$parser->echo_save($parser->nl . "questID=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "mobGID=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "maxCount=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "count=".$parser->word() . "\n");
	}
}

// packet 0x27b
function PACKET_ZC_PCBANG_EFFECT($parser) {
	$parser->echo_save($parser->packet_desc . "ExpFactor=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "ExpFactor2=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "DropFactor=".$parser->long() . "\n");
}

// packet 0x27c
function PACKET_CA_LOGIN4($parser) {
	$parser->echo_save($parser->packet_desc . "Version=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "ID=".$parser->string(24) . "\n");
	$parser->echo_save($parser->nl . "PasswdMD5=".$parser->string(16) . "\n");
	$parser->echo_save($parser->nl . "clienttype=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "macData=".$parser->string(13) . "\n");
}

// packet 0x27d
function PACKET_ZC_PROPERTY_MERCE($parser) {
	$parser->echo_save($parser->packet_desc . "name=".$parser->string(24) . "\n");
	$parser->echo_save($parser->nl . "level=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "faith=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "summonCount=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "atk=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "Matk=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "hit=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "critical=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "def=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "Mdef=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "flee=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "aspd=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "hp=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "maxHP=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "sp=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "maxSP=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "ATKRange=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "exp=".$parser->long() . "\n");
}

// packet 0x27e
function PACKET_ZC_SHANDA_PROTECT($parser) {
	$parser->echo_save($parser->packet_desc . "PacketLength=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "CodeLen=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "Code=".$parser->string($parser->packet_length - $parser->packet_pointer) . "\n");
}

// packet 0x27f
function PACKET_CA_CLIENT_TYPE($parser) {
	$parser->echo_save($parser->packet_desc . "ClientType=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "nVer=".$parser->long() . "\n");
}

// packet 0x280
function PACKET_ZC_GANGSI_POINT($parser) {
	$parser->echo_save($parser->packet_desc . "Point=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "TotalPoint=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "PacketSwitch=".$parser->word() . "\n");
}

// packet 0x281
function PACKET_CZ_GANGSI_RANK($parser) {
	$parser->echo_save($parser->packet_desc . "PacketSwitch=".$parser->word() . "\n");
}

// packet 0x282
function PACKET_ZC_GANGSI_RANK($parser) {
	$parser->echo_save($parser->packet_desc . "Name=".$parser->string(24) . "\n");
	$parser->echo_save($parser->nl . "Point=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "PacketSwitch=".$parser->word() . "\n");
}

// packet 0x283
function PACKET_ZC_AID($parser) {
	$parser->echo_save($parser->packet_desc . "AID=".$parser->long() . "\n");
}

// packet 0x284
function PACKET_ZC_NOTIFY_EFFECT3($parser) {
	$parser->echo_save($parser->packet_desc . "AID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "effectID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "numdata=".$parser->long() . "\n");
}

// packet 0x285
function PACKET_ZC_DEATH_QUESTION($parser) {
	$parser->echo_save($parser->packet_desc . "Qcategory=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "Qnum=".$parser->word() . "\n");
}

// packet 0x286
function PACKET_CZ_DEATH_QUESTION($parser) {
	$parser->echo_save($parser->packet_desc . "Qanswer=".$parser->word() . "\n");
}

// packet 0x287
function PACKET_ZC_PC_CASH_POINT_ITEMLIST($parser) {
	$parser->echo_save($parser->packet_desc . "PacketLength=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "CashPoint=".$parser->long() . "\n");
	$itemList = ($parser->packet_length - $parser->packet_pointer) / 11;
	for ($i = 0; $i < $itemList; $i++) {
		$parser->echo_save($parser->nl . "price=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "discountprice=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "type=".$parser->byte() . "\n");
		$parser->echo_save($parser->nl . "ITID=".$parser->word() . "\n");
	}
}

// packet 0x288
function PACKET_CZ_PC_BUY_CASH_POINT_ITEM($parser) {
	$parser->echo_save($parser->packet_desc . "ITID=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "count=".$parser->word() . "\n");
}

// packet 0x289
function PACKET_ZC_PC_CASH_POINT_UPDATE($parser) {
	$parser->echo_save($parser->packet_desc . "CashPoint=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "Error=".$parser->word() . "\n");
}

// packet 0x28a
function PACKET_ZC_NPC_SHOWEFST_UPDATE($parser) {
	$parser->echo_save($parser->packet_desc . "AID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "effectState=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "clevel=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "showEFST=".$parser->long() . "\n");
}

// packet 0x28c
function PACKET_CH_SELECT_CHAR_GOINGTOBEUSED($parser) {
	$parser->echo_save($parser->packet_desc . "dwAID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "nCountSelectedChar=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "ardwSelectedGID=".$parser->long() . "\n");
}

// packet 0x28d
function PACKET_CH_REQ_IS_VALID_CHARNAME($parser) {
	$parser->echo_save($parser->packet_desc . "dwAID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "dwGID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "szCharName=".$parser->string(24) . "\n");
}

// packet 0x28e
function PACKET_HC_ACK_IS_VALID_CHARNAME($parser) {
	$parser->echo_save($parser->packet_desc . "sResult=".$parser->word() . "\n");
}

// packet 0x28f
function PACKET_CH_REQ_CHANGE_CHARNAME($parser) {
	$parser->echo_save($parser->packet_desc . "dwGID=".$parser->long() . "\n");
}

// packet 0x290
function PACKET_HC_ACK_CHANGE_CHARNAME($parser) {
	$parser->echo_save($parser->packet_desc . "sResult=".$parser->word() . "\n");
}

// packet 0x291
function PACKET_ZC_MSG($parser) {
	$parser->echo_save($parser->packet_desc . "msg=".$parser->word() . "\n");
}

// packet 0x292
function PACKET_CZ_STANDING_RESURRECTION($parser) {
	$parser->echo_save($parser->packet_desc . "\n");
}

// packet 0x293
function PACKET_ZC_BOSS_INFO($parser) {
	$parser->echo_save($parser->packet_desc . "infoType=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "xPos=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "yPos=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "minHour=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "minMinute=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "maxHour=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "maxMinute=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "name=".$parser->string(51) . "\n");
}

// packet 0x294
function PACKET_ZC_READ_BOOK($parser) {
	$parser->echo_save($parser->packet_desc . "bookID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "page=".$parser->long() . "\n");
}

// packet 0x295
function PACKET_ZC_EQUIPMENT_ITEMLIST2($parser) {
	$parser->echo_save($parser->packet_desc . "PacketLength=".$parser->word() . "\n");
	$ItemInfo = ($parser->packet_length - $parser->packet_pointer) / 24;
	for ($i = 0; $i < $ItemInfo; $i++) {
		$parser->echo_save($parser->nl . "index=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "ITID=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "type=".$parser->byte() . "\n");
		$parser->echo_save($parser->nl . "IsIdentified=".$parser->byte() . "\n");
		$parser->echo_save($parser->nl . "location=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "WearState=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "IsDamaged=".$parser->byte() . "\n");
		$parser->echo_save($parser->nl . "RefiningLevel=".$parser->byte() . "\n");
		$parser->echo_save($parser->nl . "card1=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "card2=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "card3=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "card4=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "HireExpireDate=".$parser->long() . "\n");
	}
}

// packet 0x296
function PACKET_ZC_STORE_EQUIPMENT_ITEMLIST2($parser) {
	$parser->echo_save($parser->packet_desc . "PacketLength=".$parser->word() . "\n");
	$ItemInfo = ($parser->packet_length - $parser->packet_pointer) / 24;
	for ($i = 0; $i < $ItemInfo; $i++) {
		$parser->echo_save($parser->nl . "index=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "ITID=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "type=".$parser->byte() . "\n");
		$parser->echo_save($parser->nl . "IsIdentified=".$parser->byte() . "\n");
		$parser->echo_save($parser->nl . "location=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "WearState=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "IsDamaged=".$parser->byte() . "\n");
		$parser->echo_save($parser->nl . "RefiningLevel=".$parser->byte() . "\n");
		$parser->echo_save($parser->nl . "card1=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "card2=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "card3=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "card4=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "HireExpireDate=".$parser->long() . "\n");
	}
}

// packet 0x297
function PACKET_ZC_CART_EQUIPMENT_ITEMLIST2($parser) {
	$parser->echo_save($parser->packet_desc . "PacketLength=".$parser->word() . "\n");
	$ItemInfo = ($parser->packet_length - $parser->packet_pointer) / 24;
	for ($i = 0; $i < $ItemInfo; $i++) {
		$parser->echo_save($parser->nl . "index=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "ITID=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "type=".$parser->byte() . "\n");
		$parser->echo_save($parser->nl . "IsIdentified=".$parser->byte() . "\n");
		$parser->echo_save($parser->nl . "location=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "WearState=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "IsDamaged=".$parser->byte() . "\n");
		$parser->echo_save($parser->nl . "RefiningLevel=".$parser->byte() . "\n");
		$parser->echo_save($parser->nl . "card1=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "card2=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "card3=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "card4=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "HireExpireDate=".$parser->long() . "\n");
	}
}

// packet 0x298
function PACKET_ZC_CASH_TIME_COUNTER($parser) {
	$parser->echo_save($parser->packet_desc . "ITID=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "RemainSecond=".$parser->long() . "\n");
}

// packet 0x299
function PACKET_ZC_CASH_ITEM_DELETE($parser) {
	$parser->echo_save($parser->packet_desc . "index=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "ITID=".$parser->word() . "\n");
}

// packet 0x29a
function PACKET_ZC_ITEM_PICKUP_ACK2($parser) {
	$parser->echo_save($parser->packet_desc . "Index=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "count=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "ITID=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "IsIdentified=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "IsDamaged=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "refiningLevel=".$parser->byte() . "\n");
		$parser->echo_save($parser->nl . "card1=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "card2=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "card3=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "card4=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "location=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "type=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "result=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "HireExpireDate=".$parser->long() . "\n");
}

// packet 0x29b
function PACKET_ZC_MER_INIT($parser) {
	$parser->echo_save($parser->packet_desc . "AID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "atk=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "Matk=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "hit=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "critical=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "def=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "Mdef=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "flee=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "aspd=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "name=".$parser->string(24) . "\n");
	$parser->echo_save($parser->nl . "level=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "hp=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "maxHP=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "sp=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "maxSP=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "ExpireDate=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "faith=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "toal_call_num=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "approval_monster_kill_counter=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "ATKRange=".$parser->word() . "\n");
}

// packet 0x29c
function PACKET_ZC_MER_PROPERTY($parser) {
	$parser->echo_save($parser->packet_desc . "atk=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "Matk=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "hit=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "critical=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "def=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "Mdef=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "flee=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "aspd=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "name=".$parser->string(24) . "\n");
	$parser->echo_save($parser->nl . "level=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "hp=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "maxHP=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "sp=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "maxSP=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "ExpireDate=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "faith=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "toal_call_num=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "approval_monster_kill_counter=".$parser->long() . "\n");
}

// packet 0x29d
function PACKET_ZC_MER_SKILLINFO_LIST($parser) {
	$parser->echo_save($parser->packet_desc . "PacketLength=".$parser->word() . "\n");
	$skillList = ($parser->packet_length - $parser->packet_pointer) / 37;
	for ($i = 0; $i < $skillList; $i++) {
		$parser->echo_save($parser->nl . "SKID=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "type=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "level=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "spcost=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "attackRange=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "skillName=".$parser->string(24) . "\n");
		$parser->echo_save($parser->nl . "upgradable=".$parser->byte() . "\n");
	}
}

// packet 0x29e
function PACKET_ZC_MER_SKILLINFO_UPDATE($parser) {
	$parser->echo_save($parser->packet_desc . "SKID=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "level=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "spcost=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "attackRange=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "upgradable=".$parser->byte() . "\n");
}

// packet 0x29f
function PACKET_CZ_MER_COMMAND($parser) {
	$parser->echo_save($parser->packet_desc . "command=".$parser->byte() . "\n");
}

// packet 0x2a0
function UNUSED_PACKET_CZ_MER_USE_SKILL($parser) {
	$parser->echo_save($parser->packet_desc . "selectedLevel=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "SKID=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "targetID=".$parser->long() . "\n");
}

// packet 0x2a1
function UNUSED_PACKET_CZ_MER_UPGRADE_SKILLLEVEL($parser) {
	$parser->echo_save($parser->packet_desc . "SKID=".$parser->word() . "\n");
}

// packet 0x2a2
function PACKET_ZC_MER_PAR_CHANGE($parser) {
	$parser->echo_save($parser->packet_desc . "var=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "value=".$parser->long() . "\n");
}

// packet 0x2a3
function PACKET_ZC_GAMEGUARD_LINGO_KEY($parser) {
	$parser->echo_save($parser->packet_desc . "packetType=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "dwAlgNum=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "dwAlgKey1=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "dwAlgKey2=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "dwSeed=".$parser->long() . "\n");
}

// packet 0x2a5
function PACKET_CZ_KSY_EVENT($parser) {
	$parser->echo_save($parser->packet_desc . "index=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "count=".$parser->long() . "\n");
}

// packet 0x2aa
function PACKET_ZC_REQ_CASH_PASSWORD($parser) {
	$parser->echo_save($parser->packet_desc . "Info=".$parser->word() . "\n");
}

// packet 0x2ab
function PACKET_CZ_ACK_CASH_PASSWORD($parser) {
	$parser->echo_save($parser->packet_desc . "Type=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "Password=".$parser->string(16) . "\n");
	$parser->echo_save($parser->nl . "NewPassword=".$parser->string(16) . "\n");
}

// packet 0x2ac
function PACKET_ZC_RESULT_CASH_PASSWORD($parser) {
	$parser->echo_save($parser->packet_desc . "Result=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "ErrorCount=".$parser->word() . "\n");
}

// packet 0x2ad
function PACKET_AC_REQUEST_SECOND_PASSWORD($parser) {
	$parser->echo_save($parser->packet_desc . "Result=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "dwSeed=".$parser->long() . "\n");
}

// packet 0x2b0
function PACKET_CA_LOGIN_HAN($parser) {
	$parser->echo_save($parser->packet_desc . "Version=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "ID=".$parser->string(24) . "\n");
	$parser->echo_save($parser->nl . "Passwd=".$parser->string(24) . "\n");
	$parser->echo_save($parser->nl . "clienttype=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "m_szIP=".$parser->string(16) . "\n");
	$parser->echo_save($parser->nl . "m_szMacAddr=".$parser->string(13) . "\n");
	$parser->echo_save($parser->nl . "isHanGameUser=".$parser->byte() . "\n");
}

// packet 0x2b1
function PACKET_ZC_ALL_QUEST_LIST($parser) {
	$parser->echo_save($parser->packet_desc . "PacketLength=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "questCount=".$parser->long() . "\n");
	$QuestList = ($parser->packet_length - $parser->packet_pointer) / 5;
	for ($i = 0; $i < $QuestList; $i++) {
		$parser->echo_save($parser->nl . "questID=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "active=".$parser->byte() . "\n");
	}
}

// packet 0x2b2
function PACKET_ZC_ALL_QUEST_MISSION($parser) {
	$parser->echo_save($parser->packet_desc . "PacketLength=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "count=".$parser->long() . "\n");
	$QuestMissionList = ($parser->packet_length - $parser->packet_pointer) / 104;
	for ($i = 0; $i < $QuestMissionList; $i++) {
		$parser->echo_save($parser->nl . "questID=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "quest_svrTime=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "quest_endTime=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "count=".$parser->word() . "\n");
	for ($i = 0; $i < 3; $i++) {
		$parser->echo_save($parser->nl . "mobGID=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "huntCount=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "mobName=".$parser->string(24) . "\n");
		}
	}
}

// packet 0x2b3
function PACKET_ZC_ADD_QUEST($parser) {
	$parser->echo_save($parser->packet_desc . "questID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "active=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "quest_svrTime=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "quest_endTime=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "count=".$parser->word() . "\n");
	for ($i = 0; $i < 3; $i++) {
		$parser->echo_save($parser->nl . "mobGID=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "huntCount=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "mobName=".$parser->string(24) . "\n");
	}
}

// packet 0x2b4
function PACKET_ZC_DEL_QUEST($parser) {
	$parser->echo_save($parser->packet_desc . "questID=".$parser->long() . "\n");
}

// packet 0x2b5
function PACKET_ZC_UPDATE_MISSION_HUNT($parser) {
	$parser->echo_save($parser->packet_desc . "PacketLength=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "count=".$parser->word() . "\n");
	$MobHuntList = ($parser->packet_length - $parser->packet_pointer) / 12;
	for ($i = 0; $i < $MobHuntList; $i++) {
		$parser->echo_save($parser->nl . "questID=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "mobGID=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "maxCount=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "count=".$parser->word() . "\n");
	}
}

// packet 0x2b6
function PACKET_CZ_ACTIVE_QUEST($parser) {
	$parser->echo_save($parser->packet_desc . "questID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "active=".$parser->byte() . "\n");
}

// packet 0x2b7
function PACKET_ZC_ACTIVE_QUEST($parser) {
	$parser->echo_save($parser->packet_desc . "questID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "active=".$parser->byte() . "\n");
}

// packet 0x2b8
function PACKET_ZC_ITEM_PICKUP_PARTY($parser) {
	$parser->echo_save($parser->packet_desc . "accountID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "ITID=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "IsIdentified=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "IsDamaged=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "refiningLevel=".$parser->byte() . "\n");
		$parser->echo_save($parser->nl . "card1=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "card2=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "card3=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "card4=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "location=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "type=".$parser->byte() . "\n");
}

// packet 0x2b9
function PACKET_ZC_SHORTCUT_KEY_LIST($parser) {
	$parser->echo_save($parser->packet_desc  . "\n");
	for ($i = 0; $i < 27; $i++) {
		$parser->echo_save($parser->nl . "isSkill=".$parser->byte() . "\n");
		$parser->echo_save($parser->nl . "ID=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "count=".$parser->word() . "\n");
	}
}

// packet 0x2ba
function PACKET_CZ_SHORTCUT_KEY_CHANGE($parser) {
	$parser->echo_save($parser->packet_desc . "Index=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "isSkill=".$parser->byte() . "\n");
		$parser->echo_save($parser->nl . "ID=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "count=".$parser->word() . "\n");
}

// packet 0x2bb
function PACKET_ZC_EQUIPITEM_DAMAGED($parser) {
	$parser->echo_save($parser->packet_desc . "wearLocation=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "accountID=".$parser->long() . "\n");
}

// packet 0x2bc
function PACKET_ZC_NOTIFY_PCBANG_PLAYING_TIME($parser) {
	$parser->echo_save($parser->packet_desc . "TimeMinute=".$parser->long() . "\n");
}

// packet 0x2bf
function PACKET_ZC_SRPACKETR2_INIT($parser) {
	$parser->echo_save($parser->packet_desc . "ProtectFactor=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "DeformSeedFactor=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "DeformAddFactor=".$parser->long() . "\n");
}

// packet 0x2c0
function PACKET_CZ_SRPACKETR2_START($parser) {
	$parser->echo_save($parser->packet_desc . "ProtectFactor=".$parser->word() . "\n");
}

// packet 0x2c1
function PACKET_ZC_NPC_CHAT($parser) {
	$parser->echo_save($parser->packet_desc . "PacketLength=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "accountID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "color=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "msg=".$parser->string($parser->packet_length - $parser->packet_pointer) . "\n");
}

// packet 0x2c2
function PACKET_ZC_FORMATSTRING_MSG($parser) {
	$parser->echo_save($parser->packet_desc . "PacketLength=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "msg=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "value=".$parser->string($parser->packet_length - $parser->packet_pointer) . "\n");
}

// packet 0x2c4
function PACKET_CZ_PARTY_JOIN_REQ($parser) {
	$parser->echo_save($parser->packet_desc . "characterName=".$parser->string(24) . "\n");
}

// packet 0x2c5
function PACKET_ZC_PARTY_JOIN_REQ_ACK($parser) {
	$parser->echo_save($parser->packet_desc . "characterName=".$parser->string(24) . "\n");
	$parser->echo_save($parser->nl . "answer=".$parser->long() . "\n");
}

// packet 0x2c6
function PACKET_ZC_PARTY_JOIN_REQ($parser) {
	$parser->echo_save($parser->packet_desc . "GRID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "groupName=".$parser->string(24) . "\n");
}

// packet 0x2c7
function PACKET_CZ_PARTY_JOIN_REQ_ACK($parser) {
	$parser->echo_save($parser->packet_desc . "GRID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "bAccept=".$parser->byte() . "\n");
}

// packet 0x2c8
function PACKET_CZ_PARTY_CONFIG($parser) {
	$parser->echo_save($parser->packet_desc . "bRefuseJoinMsg=".$parser->byte() . "\n");
}

// packet 0x2c9
function PACKET_ZC_PARTY_CONFIG($parser) {
	$parser->echo_save($parser->packet_desc . "bRefuseJoinMsg=".$parser->byte() . "\n");
}

// packet 0x2ca
function PACKET_HC_REFUSE_SELECTCHAR($parser) {
	$parser->echo_save($parser->packet_desc . "ErrorCode=".$parser->byte() . "\n");
}

// packet 0x2cb
function PACKET_ZC_MEMORIALDUNGEON_SUBSCRIPTION_INFO($parser) {
	$parser->echo_save($parser->packet_desc . "MemorialDungeonName=".$parser->string(61) . "\n");
	$parser->echo_save($parser->nl . "PriorityOrderNum=".$parser->word() . "\n");
}

// packet 0x2cc
function PACKET_ZC_MEMORIALDUNGEON_SUBSCRIPTION_NOTIFY($parser) {
	$parser->echo_save($parser->packet_desc . "PriorityOrderNum=".$parser->word() . "\n");
}

// packet 0x2cd
function PACKET_ZC_MEMORIALDUNGEON_INFO($parser) {
	$parser->echo_save($parser->packet_desc . "MemorialDungeonName=".$parser->string(61) . "\n");
	$parser->echo_save($parser->nl . "DestroyDate=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "EnterTimeOutDate=".$parser->long() . "\n");
}

// packet 0x2ce
function PACKET_ZC_MEMORIALDUNGEON_NOTIFY($parser) {
	$parser->echo_save($parser->packet_desc . "Type=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "EnterLimitDate=".$parser->long() . "\n");
}

// packet 0x2cf
function PACKET_CZ_MEMORIALDUNGEON_COMMAND($parser) {
	$parser->echo_save($parser->packet_desc . "Command=".$parser->long() . "\n");
}

// packet 0x2d0
function PACKET_ZC_EQUIPMENT_ITEMLIST3($parser) {
	$parser->echo_save($parser->packet_desc . "PacketLength=".$parser->word() . "\n");
	$ItemInfo = ($parser->packet_length - $parser->packet_pointer) / 28;
	for ($i = 0; $i < $ItemInfo; $i++) {
		$parser->echo_save($parser->nl . "index=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "ITID=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "type=".$parser->byte() . "\n");
		$parser->echo_save($parser->nl . "IsIdentified=".$parser->byte() . "\n");
		$parser->echo_save($parser->nl . "location=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "WearState=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "IsDamaged=".$parser->byte() . "\n");
		$parser->echo_save($parser->nl . "RefiningLevel=".$parser->byte() . "\n");
		$parser->echo_save($parser->nl . "card1=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "card2=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "card3=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "card4=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "HireExpireDate=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "bindOnEquipType=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "wItemSpriteNumber=".$parser->word() . "\n");
	}
}

// packet 0x2d1
function PACKET_ZC_STORE_EQUIPMENT_ITEMLIST3($parser) {
	$parser->echo_save($parser->packet_desc . "PacketLength=".$parser->word() . "\n");
	$ItemInfo = ($parser->packet_length - $parser->packet_pointer) / 28;
	for ($i = 0; $i < $ItemInfo; $i++) {
		$parser->echo_save($parser->nl . "index=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "ITID=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "type=".$parser->byte() . "\n");
		$parser->echo_save($parser->nl . "IsIdentified=".$parser->byte() . "\n");
		$parser->echo_save($parser->nl . "location=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "WearState=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "IsDamaged=".$parser->byte() . "\n");
		$parser->echo_save($parser->nl . "RefiningLevel=".$parser->byte() . "\n");
		$parser->echo_save($parser->nl . "card1=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "card2=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "card3=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "card4=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "HireExpireDate=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "bindOnEquipType=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "wItemSpriteNumber=".$parser->word() . "\n");
	}
}

// packet 0x2d2
function PACKET_ZC_CART_EQUIPMENT_ITEMLIST3($parser) {
	$parser->echo_save($parser->packet_desc . "PacketLength=".$parser->word() . "\n");
	$ItemInfo = ($parser->packet_length - $parser->packet_pointer) / 28;
	for ($i = 0; $i < $ItemInfo; $i++) {
		$parser->echo_save($parser->nl . "index=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "ITID=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "type=".$parser->byte() . "\n");
		$parser->echo_save($parser->nl . "IsIdentified=".$parser->byte() . "\n");
		$parser->echo_save($parser->nl . "location=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "WearState=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "IsDamaged=".$parser->byte() . "\n");
		$parser->echo_save($parser->nl . "RefiningLevel=".$parser->byte() . "\n");
		$parser->echo_save($parser->nl . "card1=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "card2=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "card3=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "card4=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "HireExpireDate=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "bindOnEquipType=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "wItemSpriteNumber=".$parser->word() . "\n");
	}
}

// packet 0x2d3
function PACKET_ZC_NOTIFY_BIND_ON_EQUIP($parser) {
	$parser->echo_save($parser->packet_desc . "index=".$parser->word() . "\n");
}

// packet 0x2d4
function PACKET_ZC_ITEM_PICKUP_ACK3($parser) {
	$parser->echo_save($parser->packet_desc . "Index=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "count=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "ITID=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "IsIdentified=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "IsDamaged=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "refiningLevel=".$parser->byte() . "\n");
		$parser->echo_save($parser->nl . "card1=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "card2=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "card3=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "card4=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "location=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "type=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "result=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "HireExpireDate=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "bindOnEquipType=".$parser->word() . "\n");
}

// packet 0x2d5
function PACKET_ZC_ISVR_DISCONNECT($parser) {
	$parser->echo_save($parser->packet_desc . "\n");
}

// packet 0x2d6
function PACKET_CZ_EQUIPWIN_MICROSCOPE($parser) {
	$parser->echo_save($parser->packet_desc . "AID=".$parser->long() . "\n");
}

// packet 0x2d7
function PACKET_ZC_EQUIPWIN_MICROSCOPE($parser) {
	$parser->echo_save($parser->packet_desc . "PacketLength=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "characterName=".$parser->string(24) . "\n");
	$parser->echo_save($parser->nl . "job=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "head=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "accessory=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "accessory2=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "accessory3=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "headpalette=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "bodypalette=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "sex=".$parser->byte() . "\n");
	$ItemInfo = ($parser->packet_length - $parser->packet_pointer) / 28;
	for ($i = 0; $i < $ItemInfo; $i++) {
		$parser->echo_save($parser->nl . "index=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "ITID=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "type=".$parser->byte() . "\n");
		$parser->echo_save($parser->nl . "IsIdentified=".$parser->byte() . "\n");
		$parser->echo_save($parser->nl . "location=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "WearState=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "IsDamaged=".$parser->byte() . "\n");
		$parser->echo_save($parser->nl . "RefiningLevel=".$parser->byte() . "\n");
		$parser->echo_save($parser->nl . "card1=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "card2=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "card3=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "card4=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "HireExpireDate=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "bindOnEquipType=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "wItemSpriteNumber=".$parser->word() . "\n");
	}
}

// packet 0x2d8
function PACKET_CZ_CONFIG($parser) {
	$parser->echo_save($parser->packet_desc . "Config=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "Value=".$parser->long() . "\n");
}

// packet 0x2d9
function PACKET_ZC_CONFIG($parser) {
	$parser->echo_save($parser->packet_desc . "Config=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "Value=".$parser->long() . "\n");
}

// packet 0x2da
function PACKET_ZC_CONFIG_NOTIFY($parser) {
	$parser->echo_save($parser->packet_desc . "bOpenEquipmentWin=".$parser->byte() . "\n");
}

// packet 0x2db
function PACKET_CZ_BATTLEFIELD_CHAT($parser) {
	$parser->echo_save($parser->packet_desc . "PacketLength=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "msg=".$parser->string($parser->packet_length - $parser->packet_pointer) . "\n");
}

// packet 0x2dc
function PACKET_ZC_BATTLEFIELD_CHAT($parser) {
	$parser->echo_save($parser->packet_desc . "PacketLength=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "accountID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "name=".$parser->string(24) . "\n");
	$parser->echo_save($parser->nl . "msg=".$parser->string($parser->packet_length - $parser->packet_pointer) . "\n");
}

// packet 0x2dd
function PACKET_ZC_BATTLEFIELD_NOTIFY_CAMPINFO($parser) {
	$parser->echo_save($parser->packet_desc . "accountID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "name=".$parser->string(24) . "\n");
	$parser->echo_save($parser->nl . "camp=".$parser->word() . "\n");
}

// packet 0x2de
function PACKET_ZC_BATTLEFIELD_NOTIFY_POINT($parser) {
	$parser->echo_save($parser->packet_desc . "pointCampA=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "pointCampB=".$parser->word() . "\n");
}

// packet 0x2df
function PACKET_ZC_BATTLEFIELD_NOTIFY_POSITION($parser) {
	$parser->echo_save($parser->packet_desc . "accountID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "name=".$parser->string(24) . "\n");
	$parser->echo_save($parser->nl . "job=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "x=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "y=".$parser->word() . "\n");
}

// packet 0x2e0
function PACKET_ZC_BATTLEFIELD_NOTIFY_HP($parser) {
	$parser->echo_save($parser->packet_desc . "accountID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "name=".$parser->string(24) . "\n");
	$parser->echo_save($parser->nl . "hp=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "maxHp=".$parser->word() . "\n");
}

// packet 0x2e1
function PACKET_ZC_NOTIFY_ACT2($parser) {
	$parser->echo_save($parser->packet_desc . "GID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "targetGID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "startTime=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "attackMT=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "attackedMT=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "damage=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "count=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "action=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "leftDamage=".$parser->long() . "\n");
}

// packet 0x2e6
function PACKET_CZ_BOT_CHECK($parser) {
	$parser->echo_save($parser->packet_desc . "IsBot=".$parser->long() . "\n");
}

// packet 0x2e7
function PACKET_ZC_MAPPROPERTY($parser) {
	$parser->echo_save($parser->packet_desc . "PacketLength=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "type=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "mapInfoTable=".$parser->long() . "\n");
}

// packet 0x2e8
function PACKET_ZC_NORMAL_ITEMLIST3($parser) {
	$parser->echo_save($parser->packet_desc . "PacketLength=".$parser->word() . "\n");
	$ItemInfo = ($parser->packet_length - $parser->packet_pointer) / 22;
	for ($i = 0; $i < $ItemInfo; $i++) {
		$parser->echo_save($parser->nl . "index=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "ITID=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "type=".$parser->byte() . "\n");
		$parser->echo_save($parser->nl . "IsIdentified=".$parser->byte() . "\n");
		$parser->echo_save($parser->nl . "count=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "WearState=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "card1=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "card2=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "card3=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "card4=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "HireExpireDate=".$parser->long() . "\n");
	}
}

// packet 0x2e9
function PACKET_ZC_CART_NORMAL_ITEMLIST3($parser) {
	$parser->echo_save($parser->packet_desc . "PacketLength=".$parser->word() . "\n");
	$ItemInfo = ($parser->packet_length - $parser->packet_pointer) / 22;
	for ($i = 0; $i < $ItemInfo; $i++) {
		$parser->echo_save($parser->nl . "index=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "ITID=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "type=".$parser->byte() . "\n");
		$parser->echo_save($parser->nl . "IsIdentified=".$parser->byte() . "\n");
		$parser->echo_save($parser->nl . "count=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "WearState=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "card1=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "card2=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "card3=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "card4=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "HireExpireDate=".$parser->long() . "\n");
	}
}

// packet 0x2ea
function PACKET_ZC_STORE_NORMAL_ITEMLIST3($parser) {
	$parser->echo_save($parser->packet_desc . "PacketLength=".$parser->word() . "\n");
	$ItemInfo = ($parser->packet_length - $parser->packet_pointer) / 22;
	for ($i = 0; $i < $ItemInfo; $i++) {
		$parser->echo_save($parser->nl . "index=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "ITID=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "type=".$parser->byte() . "\n");
		$parser->echo_save($parser->nl . "IsIdentified=".$parser->byte() . "\n");
		$parser->echo_save($parser->nl . "count=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "WearState=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "card1=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "card2=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "card3=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "card4=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "HireExpireDate=".$parser->long() . "\n");
	}
}

// packet 0x2eb
function PACKET_ZC_ACCEPT_ENTER2($parser) {
	$parser->echo_save($parser->packet_desc . "startTime=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "PosDir=".$parser->string(3) . "\n");
	$parser->echo_save($parser->nl . "xSize=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "ySize=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "font=".$parser->word() . "\n");
}

// packet 0x2ec
function PACKET_ZC_NOTIFY_MOVEENTRY4($parser) {
	$parser->echo_save($parser->packet_desc . "objecttype=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "GID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "speed=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "bodyState=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "healthState=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "effectState=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "job=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "head=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "weapon=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "accessory=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "moveStartTime=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "accessory2=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "accessory3=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "headpalette=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "bodypalette=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "headDir=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "GUID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "GEmblemVer=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "honor=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "virtue=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "isPKModeON=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "sex=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "MoveData=".$parser->string(6) . "\n");
	$parser->echo_save($parser->nl . "xSize=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "ySize=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "clevel=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "font=".$parser->word() . "\n");
}

// packet 0x2ed
function PACKET_ZC_NOTIFY_NEWENTRY4($parser) {
	$parser->echo_save($parser->packet_desc . "GID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "speed=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "bodyState=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "healthState=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "effectState=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "job=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "head=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "weapon=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "accessory=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "accessory2=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "accessory3=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "headpalette=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "bodypalette=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "headDir=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "GUID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "GEmblemVer=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "honor=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "virtue=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "isPKModeON=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "sex=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "PosDir=".$parser->string(3) . "\n");
	$parser->echo_save($parser->nl . "xSize=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "ySize=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "clevel=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "font=".$parser->word() . "\n");
}

// packet 0x2ee
function PACKET_ZC_NOTIFY_STANDENTRY4($parser) {
	$parser->echo_save($parser->packet_desc . "GID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "speed=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "bodyState=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "healthState=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "effectState=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "job=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "head=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "weapon=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "accessory=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "accessory2=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "accessory3=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "headpalette=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "bodypalette=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "headDir=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "GUID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "GEmblemVer=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "honor=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "virtue=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "isPKModeON=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "sex=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "PosDir=".$parser->string(3) . "\n");
	$parser->echo_save($parser->nl . "xSize=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "ySize=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "state=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "clevel=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "font=".$parser->word() . "\n");
}

// packet 0x2ef
function PACKET_ZC_NOTIFY_FONT($parser) {
	$parser->echo_save($parser->packet_desc . "AID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "font=".$parser->word() . "\n");
}

// packet 0x2f0
function PACKET_ZC_PROGRESS($parser) {
	$parser->echo_save($parser->packet_desc . "color=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "time=".$parser->long() . "\n");
}

// packet 0x2f1
function PACKET_CZ_PROGRESS($parser) {
	$parser->echo_save($parser->packet_desc . "\n");
}

// packet 0x2f2
function PACKET_ZC_PROGRESS_CANCEL($parser) {
	$parser->echo_save($parser->packet_desc . "\n");
}

// packet 0x2f3
function PACKET_CZ_IRMAIL_SEND($parser) {
	$parser->echo_save($parser->packet_desc . "PacketLength=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "ReceiveName=".$parser->string(24) . "\n");
	$parser->echo_save($parser->nl . "Title=".$parser->string(40) . "\n");
	$parser->echo_save($parser->nl . "Zeny=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "index=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "id=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "cnt=".$parser->word() . "\n");
}

// packet 0x2f4
function PACKET_ZC_IRMAIL_SEND_RES($parser) {
	$parser->echo_save($parser->packet_desc . "Result=".$parser->byte() . "\n");
}

// packet 0x2f5
function PACKET_ZC_IRMAIL_NOTIFY($parser) {
	$parser->echo_save($parser->packet_desc  . "\n");
		$parser->echo_save($parser->nl . "office=".$parser->byte() . "\n");
		$parser->echo_save($parser->nl . "id=".$parser->long() . "\n");
}

// packet 0x2f6
function PACKET_CZ_IRMAIL_LIST($parser) {
	$parser->echo_save($parser->packet_desc  . "\n");
		$parser->echo_save($parser->nl . "office=".$parser->byte() . "\n");
		$parser->echo_save($parser->nl . "id=".$parser->long() . "\n");
}

// packet 0x35c
function PACKET_CZ_OPEN_SIMPLE_CASHSHOP_ITEMLIST($parser) {
	$parser->echo_save($parser->packet_desc . "\n");
}

// packet 0x35d
function PACKET_ZC_SIMPLE_CASHSHOP_POINT_ITEMLIST($parser) {
	$parser->echo_save($parser->packet_desc . "PacketLength=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "CashPoint=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "md_itemcount=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "md_itemSize=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "best_itemcount=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "best_itemsize=".$parser->word() . "\n");
	$ItemList = ($parser->packet_length - $parser->packet_pointer) / 11;
	for ($i = 0; $i < $ItemList; $i++) {
		$parser->echo_save($parser->nl . "price=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "discountprice=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "type=".$parser->byte() . "\n");
		$parser->echo_save($parser->nl . "ITID=".$parser->word() . "\n");
	}
}

// packet 0x35e
function PACKET_CZ_CLOSE_WINDOW($parser) {
	$parser->echo_save($parser->packet_desc . "\n");
}

// packet 0x35f
function PACKET_CZ_REQUEST_MOVE2($parser) {
	$parser->echo_save($parser->packet_desc . "dest=".$parser->string(3) . "\n");
}

// packet 0x360
function PACKET_CZ_REQUEST_TIME2($parser) {
	$parser->echo_save($parser->packet_desc . "clientTime=".$parser->long() . "\n");
}

// packet 0x361
function PACKET_CZ_CHANGE_DIRECTION2($parser) {
	$parser->echo_save($parser->packet_desc . "headDir=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "dir=".$parser->byte() . "\n");
}

// packet 0x362
function PACKET_CZ_ITEM_PICKUP2($parser) {
	$parser->echo_save($parser->packet_desc . "ITAID=".$parser->long() . "\n");
}

// packet 0x363
function PACKET_CZ_ITEM_THROW2($parser) {
	$parser->echo_save($parser->packet_desc . "Index=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "count=".$parser->word() . "\n");
}

// packet 0x364
function PACKET_CZ_MOVE_ITEM_FROM_BODY_TO_STORE2($parser) {
	$parser->echo_save($parser->packet_desc . "index=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "count=".$parser->long() . "\n");
}

// packet 0x365
function PACKET_CZ_MOVE_ITEM_FROM_STORE_TO_BODY2($parser) {
	$parser->echo_save($parser->packet_desc . "index=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "count=".$parser->long() . "\n");
}

// packet 0x366
function PACKET_CZ_USE_SKILL_TOGROUND2($parser) {
	$parser->echo_save($parser->packet_desc . "selectedLevel=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "SKID=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "xPos=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "yPos=".$parser->word() . "\n");
}

// packet 0x367
function PACKET_CZ_USE_SKILL_TOGROUND_WITHTALKBOX2($parser) {
	$parser->echo_save($parser->packet_desc . "selectedLevel=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "SKID=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "xPos=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "yPos=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "contents=".$parser->string(80) . "\n");
}

// packet 0x368
function PACKET_CZ_REQNAME2($parser) {
	$parser->echo_save($parser->packet_desc . "AID=".$parser->long() . "\n");
}

// packet 0x369
function PACKET_CZ_REQNAME_BYGID2($parser) {
	$parser->echo_save($parser->packet_desc . "GID=".$parser->long() . "\n");
}

// packet 0x3de
function PACKET_CAH_ACK_GAME_GUARD($parser) {
	$parser->echo_save($parser->packet_desc . "AuthData=".$parser->long() . "\n");
}

// packet 0x436
function PACKET_CZ_ENTER2($parser) {
	$parser->echo_save($parser->packet_desc . "AID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "GID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "AuthCode=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "clientTime=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "Sex=".$parser->byte() . "\n");
}

// packet 0x437
function PACKET_CZ_REQUEST_ACT2($parser) {
	$parser->echo_save($parser->packet_desc . "targetGID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "action=".$parser->byte() . "\n");
}

// packet 0x438
function PACKET_CZ_USE_SKILL2($parser) {
	$parser->echo_save($parser->packet_desc . "selectedLevel=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "SKID=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "targetID=".$parser->long() . "\n");
}

// packet 0x439
function PACKET_CZ_USE_ITEM2($parser) {
	$parser->echo_save($parser->packet_desc . "index=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "AID=".$parser->long() . "\n");
}

// packet 0x43d
function PACKET_ZC_SKILL_POSTDELAY($parser) {
	$parser->echo_save($parser->packet_desc . "SKID=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "DelayTM=".$parser->long() . "\n");
}

// packet 0x43e
function PACKET_ZC_SKILL_POSTDELAY_LIST($parser) {
	$parser->echo_save($parser->packet_desc . "PacketLength=".$parser->word() . "\n");
	$delayList = ($parser->packet_length - $parser->packet_pointer) / 6;
	for ($i = 0; $i < $delayList; $i++) {
		$parser->echo_save($parser->nl . "SKID=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "DelayTM=".$parser->long() . "\n");
	}
}

// packet 0x43f
function PACKET_ZC_MSG_STATE_CHANGE2($parser) {
	$parser->echo_save($parser->packet_desc . "index=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "AID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "state=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "RemainMS=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "val=".$parser->long() . "\n");
}

// packet 0x440
function PACKET_ZC_MILLENNIUMSHIELD($parser) {
	$parser->echo_save($parser->packet_desc . "AID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "num=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "state=".$parser->word() . "\n");
}

// packet 0x441
function PACKET_ZC_SKILLINFO_DELETE($parser) {
	$parser->echo_save($parser->packet_desc . "SKID=".$parser->word() . "\n");
}

// packet 0x442
function PACKET_ZC_SKILL_SELECT_REQUEST($parser) {
	$parser->echo_save($parser->packet_desc . "PacketLength=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "why=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "SKIDList=".$parser->word() . "\n");
}

// packet 0x443
function PACKET_CZ_SKILL_SELECT_RESPONSE($parser) {
	$parser->echo_save($parser->packet_desc . "why=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "SKID=".$parser->word() . "\n");
}

// packet 0x444
function PACKET_ZC_SIMPLE_CASH_POINT_ITEMLIST($parser) {
	$parser->echo_save($parser->packet_desc . "PacketLength=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "CashPoint=".$parser->long() . "\n");
	$ItemList = ($parser->packet_length - $parser->packet_pointer) / 11;
	for ($i = 0; $i < $ItemList; $i++) {
		$parser->echo_save($parser->nl . "price=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "discountprice=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "type=".$parser->byte() . "\n");
		$parser->echo_save($parser->nl . "ITID=".$parser->word() . "\n");
	}
}

// packet 0x445
function PACKET_CZ_SIMPLE_BUY_CASH_POINT_ITEM($parser) {
	$parser->echo_save($parser->packet_desc . "ITID=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "count=".$parser->word() . "\n");
}

// packet 0x446
function PACKET_ZC_QUEST_NOTIFY_EFFECT($parser) {
	$parser->echo_save($parser->packet_desc . "npcID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "xPos=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "yPos=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "effect=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "type=".$parser->word() . "\n");
}

// packet 0x447
function PACKET_CZ_BLOCKING_PLAY_CANCEL($parser) {
	$parser->echo_save($parser->packet_desc . "\n");
}

// packet 0x448
function PACKET_HC_CHARACTER_LIST($parser) {
	$parser->echo_save($parser->packet_desc . "PacketLength=".$parser->word() . "\n");
	$CharacterList = ($parser->packet_length - $parser->packet_pointer) / 5;
	for ($i = 0; $i < $CharacterList; $i++) {
		$parser->echo_save($parser->nl . "dwGID=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "SlotIdx=".$parser->byte() . "\n");
	}
}

// packet 0x449
function PACKET_ZC_HACKSH_ERROR_MSG($parser) {
	$parser->echo_save($parser->packet_desc . "ErrorID=".$parser->word() . "\n");
}

// packet 0x44a
function PACKET_CZ_CLIENT_VERSION($parser) {
	$parser->echo_save($parser->packet_desc . "clientVer=".$parser->long() . "\n");
}

// packet 0x44b
function PACKET_CZ_CLOSE_SIMPLECASH_SHOP($parser) {
	$parser->echo_save($parser->packet_desc . "\n");
}

// packet 0x7d0
function PACKET_ZC_ES_RESULT($parser) {
	$parser->echo_save($parser->packet_desc . "esNo=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "esMsg=".$parser->word() . "\n");
}

// packet 0x7d1
function PACKET_CZ_ES_GET_LIST($parser) {
	$parser->echo_save($parser->packet_desc . "\n");
}

// packet 0x7d2
function PACKET_ZC_ES_LIST($parser) {
	$parser->echo_save($parser->packet_desc . "PacketLength=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "Count=".$parser->word() . "\n");
}

// packet 0x7d3
function PACKET_CZ_ES_CHOOSE($parser) {
	$parser->echo_save($parser->packet_desc . "esNo=".$parser->word() . "\n");
}

// packet 0x7d4
function PACKET_CZ_ES_CANCEL($parser) {
	$parser->echo_save($parser->packet_desc . "esNo=".$parser->word() . "\n");
}

// packet 0x7d5
function PACKET_ZC_ES_READY($parser) {
	$parser->echo_save($parser->packet_desc . "esNo=".$parser->word() . "\n");
}

// packet 0x7d6
function PACKET_ZC_ES_GOTO($parser) {
	$parser->echo_save($parser->packet_desc . "esNo=".$parser->word() . "\n");
}

// packet 0x7d7
function PACKET_CZ_GROUPINFO_CHANGE_V2($parser) {
	$parser->echo_save($parser->packet_desc . "expOption=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "ItemPickupRule=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "ItemDivisionRule=".$parser->byte() . "\n");
}

// packet 0x7d8
function PACKET_ZC_REQ_GROUPINFO_CHANGE_V2($parser) {
	$parser->echo_save($parser->packet_desc . "expOption=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "ItemPickupRule=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "ItemDivisionRule=".$parser->byte() . "\n");
}

// packet 0x7d9
function PACKET_ZC_SHORTCUT_KEY_LIST_V2($parser) {
	$parser->echo_save($parser->packet_desc  . "\n");
	for ($i = 0; $i < 38; $i++) {
		$parser->echo_save($parser->nl . "isSkill=".$parser->byte() . "\n");
		$parser->echo_save($parser->nl . "ID=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "count=".$parser->word() . "\n");
	}
}

// packet 0x7da
function PACKET_CZ_CHANGE_GROUP_MASTER($parser) {
	$parser->echo_save($parser->packet_desc . "AID=".$parser->long() . "\n");
}

// packet 0x7db
function PACKET_ZC_HO_PAR_CHANGE($parser) {
	$parser->echo_save($parser->packet_desc . "var=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "value=".$parser->long() . "\n");
}

// packet 0x7dc
function PACKET_CZ_SEEK_PARTY($parser) {
	$parser->echo_save($parser->packet_desc . "Option=".$parser->long() . "\n");
}

// packet 0x7dd
function PACKET_ZC_SEEK_PARTY($parser) {
	$parser->echo_save($parser->packet_desc . "Name=".$parser->string(24) . "\n");
	$parser->echo_save($parser->nl . "Job=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "Level=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "mapName=".$parser->string(16) . "\n");
	$parser->echo_save($parser->nl . "Option=".$parser->long() . "\n");
}

// packet 0x7de
function PACKET_CZ_SEEK_PARTY_MEMBER($parser) {
	$parser->echo_save($parser->packet_desc . "Job=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "Level=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "mapName=".$parser->string(16) . "\n");
	$parser->echo_save($parser->nl . "Option=".$parser->long() . "\n");
}

// packet 0x7df
function PACKET_ZC_SEEK_PARTY_MEMBER($parser) {
	$parser->echo_save($parser->packet_desc . "Name=".$parser->string(24) . "\n");
	$parser->echo_save($parser->nl . "Job=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "Level=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "mapName=".$parser->string(16) . "\n");
	$parser->echo_save($parser->nl . "Option=".$parser->long() . "\n");
}

// packet 0x7e0
function PACKET_ZC_ES_NOTI_MYINFO($parser) {
	$parser->echo_save($parser->packet_desc . "esNo=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "esname=".$parser->string(54) . "\n");
}

// packet 0x7e1
function PACKET_ZC_SKILLINFO_UPDATE2($parser) {
	$parser->echo_save($parser->packet_desc . "SKID=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "type=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "level=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "spcost=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "attackRange=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "upgradable=".$parser->byte() . "\n");
}

// packet 0x7e2
function PACKET_ZC_MSG_VALUE($parser) {
	$parser->echo_save($parser->packet_desc . "msg=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "value=".$parser->long() . "\n");
}

// packet 0x7e3
function PACKET_ZC_ITEMLISTWIN_OPEN($parser) {
	$parser->echo_save($parser->packet_desc . "Type=".$parser->long() . "\n");
}

// packet 0x7e4
function PACKET_CZ_ITEMLISTWIN_RES($parser) {
	$parser->echo_save($parser->packet_desc . "PacketLength=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "Type=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "Action=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "MaterialList=".$parser->word() . "\n");
}

// packet 0x7e5
function PACKET_CH_ENTER_CHECKBOT($parser) {
	$parser->echo_save($parser->packet_desc . "PacketLength=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "dwAID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "szStringInfo=".$parser->string($parser->packet_length - $parser->packet_pointer) . "\n");
}

// packet 0x7e6
function PACKET_ZC_MSG_SKILL($parser) {
	$parser->echo_save($parser->packet_desc . "SKID=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "MSGID=".$parser->long() . "\n");
}

// packet 0x7e7
function PACKET_CH_CHECKBOT($parser) {
	$parser->echo_save($parser->packet_desc . "PacketLength=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "dwAID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "szStringInfo=".$parser->string(24) . "\n");
}

// packet 0x7e8
function PACKET_HC_CHECKBOT($parser) {
	$parser->echo_save($parser->packet_desc . "PacketLength=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "img=".$parser->string($parser->packet_length - $parser->packet_pointer) . "\n");
}

// packet 0x7e9
function PACKET_HC_CHECKBOT_RESULT($parser) {
	$parser->echo_save($parser->packet_desc . "PacketLength=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "Result=".$parser->byte() . "\n");
}

// packet 0x7ea
function PACKET_CZ_BATTLE_FIELD_LIST($parser) {
	$parser->echo_save($parser->packet_desc . "\n");
}

// packet 0x7eb
function PACKET_ZC_BATTLE_FIELD_LIST($parser) {
	$parser->echo_save($parser->packet_desc . "PacketLength=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "Count=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "ack_type=".$parser->word() . "\n");
	$InfoList = ($parser->packet_length - $parser->packet_pointer) / 62;
	for ($i = 0; $i < $InfoList; $i++) {
		$parser->echo_save($parser->nl . "BFNO=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "BattleFieldName=".$parser->string(56) . "\n");
		$parser->echo_save($parser->nl . "JoinTeam=".$parser->word() . "\n");
	}
}

// packet 0x7ec
function PACKET_CZ_JOIN_BATTLE_FIELD($parser) {
	$parser->echo_save($parser->packet_desc . "BFNO=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "JoinTeam=".$parser->word() . "\n");
}

// packet 0x7ed
function PACKET_ZC_JOIN_BATTLE_FIELD($parser) {
	$parser->echo_save($parser->packet_desc . "BFNO=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "JoinTeam=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "Result=".$parser->word() . "\n");
}

// packet 0x7ee
function PACKET_CZ_CANCEL_BATTLE_FIELD($parser) {
	$parser->echo_save($parser->packet_desc . "BFNO=".$parser->long() . "\n");
}

// packet 0x7ef
function PACKET_ZC_CANCEL_BATTLE_FIELD($parser) {
	$parser->echo_save($parser->packet_desc . "BFNO=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "Result=".$parser->word() . "\n");
}

// packet 0x7f0
function PACKET_CZ_REQ_BATTLE_STATE_MONITOR($parser) {
	$parser->echo_save($parser->packet_desc . "BFNO=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "PowerSwitch=".$parser->word() . "\n");
}

// packet 0x7f1
function PACKET_ZC_ACK_BATTLE_STATE_MONITOR($parser) {
	$parser->echo_save($parser->packet_desc . "BFNO=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "PlayCount=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "BattleState=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "TeamCount_A=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "TeamCount_B=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "MyCount=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "JoinTeam=".$parser->word() . "\n");
}

// packet 0x7f2
function PACKET_ZC_BATTLE_NOTI_START_STEP($parser) {
	$parser->echo_save($parser->packet_desc . "BFNO=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "Result=".$parser->word() . "\n");
}

// packet 0x7f3
function PACKET_ZC_BATTLE_JOIN_NOTI_DEFER($parser) {
	$parser->echo_save($parser->packet_desc . "BFNO=".$parser->long() . "\n");
}

// packet 0x7f4
function PACKET_ZC_BATTLE_JOIN_DISABLE_STATE($parser) {
	$parser->echo_save($parser->packet_desc . "Enable=".$parser->byte() . "\n");
}

// packet 0x7f5
function PACKET_CZ_GM_FULLSTRIP($parser) {
	$parser->echo_save($parser->packet_desc . "TargetAID=".$parser->long() . "\n");
}

// packet 0x7f6
function PACKET_ZC_NOTIFY_EXP($parser) {
	$parser->echo_save($parser->packet_desc . "AID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "amount=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "varID=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "expType=".$parser->word() . "\n");
}

// packet 0x7f7
function PACKET_ZC_NOTIFY_MOVEENTRY7($parser) {
	$parser->echo_save($parser->packet_desc . "PacketLength=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "objecttype=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "GID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "speed=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "bodyState=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "healthState=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "effectState=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "job=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "head=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "weapon=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "accessory=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "moveStartTime=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "accessory2=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "accessory3=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "headpalette=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "bodypalette=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "headDir=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "GUID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "GEmblemVer=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "honor=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "virtue=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "isPKModeON=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "sex=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "MoveData=".$parser->string(6) . "\n");
	$parser->echo_save($parser->nl . "xSize=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "ySize=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "clevel=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "font=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "name=".$parser->string(24) . "\n");
}

// packet 0x7f8
function PACKET_ZC_NOTIFY_NEWENTRY5($parser) {
	$parser->echo_save($parser->packet_desc . "PacketLength=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "objecttype=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "GID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "speed=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "bodyState=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "healthState=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "effectState=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "job=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "head=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "weapon=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "accessory=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "accessory2=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "accessory3=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "headpalette=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "bodypalette=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "headDir=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "GUID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "GEmblemVer=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "honor=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "virtue=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "isPKModeON=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "sex=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "PosDir=".$parser->string(3) . "\n");
	$parser->echo_save($parser->nl . "xSize=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "ySize=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "clevel=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "font=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "name=".$parser->string(24) . "\n");
}

// packet 0x7f9
function PACKET_ZC_NOTIFY_STANDENTRY5($parser) {
	$parser->echo_save($parser->packet_desc . "PacketLength=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "objecttype=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "GID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "speed=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "bodyState=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "healthState=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "effectState=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "job=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "head=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "weapon=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "accessory=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "accessory2=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "accessory3=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "headpalette=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "bodypalette=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "headDir=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "GUID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "GEmblemVer=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "honor=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "virtue=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "isPKModeON=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "sex=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "PosDir=".$parser->string(3) . "\n");
	$parser->echo_save($parser->nl . "xSize=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "ySize=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "state=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "clevel=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "font=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "name=".$parser->string(24) . "\n");
}

// packet 0x7fa
function PACKET_ZC_DELETE_ITEM_FROM_BODY($parser) {
	$parser->echo_save($parser->packet_desc . "DeleteType=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "Index=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "Count=".$parser->word() . "\n");
}

// packet 0x7fb
function PACKET_ZC_USESKILL_ACK2($parser) {
	$parser->echo_save($parser->packet_desc . "AID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "targetID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "xPos=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "yPos=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "SKID=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "property=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "delayTime=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "isDisposable=".$parser->byte() . "\n");
}

// packet 0x7fc
function PACKET_ZC_CHANGE_GROUP_MASTER($parser) {
	$parser->echo_save($parser->packet_desc . "OldMasterAID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "NewMasterAID=".$parser->long() . "\n");
}

// packet 0x7fe
function PACKET_ZC_PLAY_NPC_BGM($parser) {
	$parser->echo_save($parser->packet_desc . "Bgm=".$parser->string(24) . "\n");
}

// packet 0x7ff
function PACKET_ZC_DEFINE_CHECK($parser) {
	$parser->echo_save($parser->packet_desc . "PacketLength=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "Result=".$parser->long() . "\n");
}

// packet 0x800
function PACKET_ZC_PC_PURCHASE_ITEMLIST_FROMMC2($parser) {
	$parser->echo_save($parser->packet_desc . "PacketLength=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "AID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "UniqueID=".$parser->long() . "\n");
	$itemList = ($parser->packet_length - $parser->packet_pointer) / 22;
	for ($i = 0; $i < $itemList; $i++) {
		$parser->echo_save($parser->nl . "price=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "count=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "index=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "type=".$parser->byte() . "\n");
		$parser->echo_save($parser->nl . "ITID=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "IsIdentified=".$parser->byte() . "\n");
		$parser->echo_save($parser->nl . "IsDamaged=".$parser->byte() . "\n");
		$parser->echo_save($parser->nl . "refiningLevel=".$parser->byte() . "\n");
		$parser->echo_save($parser->nl . "card1=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "card2=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "card3=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "card4=".$parser->word() . "\n");
	}
}

// packet 0x801
function PACKET_CZ_PC_PURCHASE_ITEMLIST_FROMMC2($parser) {
	$parser->echo_save($parser->packet_desc . "PacketLength=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "AID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "UniqueID=".$parser->long() . "\n");
	$itemList = ($parser->packet_length - $parser->packet_pointer) / 4;
	for ($i = 0; $i < $itemList; $i++) {
		$parser->echo_save($parser->nl . "count=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "index=".$parser->word() . "\n");
	}
}

// packet 0x802
function PACKET_CZ_PARTY_BOOKING_REQ_REGISTER($parser) {
	$parser->echo_save($parser->packet_desc  . "\n");
		$parser->echo_save($parser->nl . "Level=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "MapID=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "Job=".$parser->word() . "\n");
}

// packet 0x803
function PACKET_ZC_PARTY_BOOKING_ACK_REGISTER($parser) {
	$parser->echo_save($parser->packet_desc . "Result=".$parser->word() . "\n");
}

// packet 0x804
function PACKET_CZ_PARTY_BOOKING_REQ_SEARCH($parser) {
	$parser->echo_save($parser->packet_desc . "Level=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "MapID=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "Job=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "LastIndex=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "ResultCount=".$parser->word() . "\n");
}

// packet 0x805
function PACKET_ZC_PARTY_BOOKING_ACK_SEARCH($parser) {
	$parser->echo_save($parser->packet_desc . "PacketLength=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "IsExistMoreResult=".$parser->byte() . "\n");
	$Info = ($parser->packet_length - $parser->packet_pointer) / 48;
	for ($i = 0; $i < $Info; $i++) {
		$parser->echo_save($parser->nl . "Index=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "CharName=".$parser->string(24) . "\n");
		$parser->echo_save($parser->nl . "ExpireTime=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "Level=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "MapID=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "Job=".$parser->word() . "\n");
	}
}

// packet 0x806
function PACKET_CZ_PARTY_BOOKING_REQ_DELETE($parser) {
	$parser->echo_save($parser->packet_desc . "\n");
}

// packet 0x807
function PACKET_ZC_PARTY_BOOKING_ACK_DELETE($parser) {
	$parser->echo_save($parser->packet_desc . "Result=".$parser->word() . "\n");
}

// packet 0x808
function PACKET_CZ_PARTY_BOOKING_REQ_UPDATE($parser) {
	$parser->echo_save($parser->packet_desc . "Job=".$parser->word() . "\n");
}

// packet 0x809
function PACKET_ZC_PARTY_BOOKING_NOTIFY_INSERT($parser) {
	$parser->echo_save($parser->packet_desc  . "\n");
		$parser->echo_save($parser->nl . "Index=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "CharName=".$parser->string(24) . "\n");
		$parser->echo_save($parser->nl . "ExpireTime=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "Level=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "MapID=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "Job1=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "Job2=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "Job3=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "Job4=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "Job5=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "Job6=".$parser->word() . "\n");
}

// packet 0x80a
function PACKET_ZC_PARTY_BOOKING_NOTIFY_UPDATE($parser) {
	$parser->echo_save($parser->packet_desc . "Index=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "Job1=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "Job2=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "Job3=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "Job4=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "Job5=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "Job6=".$parser->word() . "\n");
}

// packet 0x80b
function PACKET_ZC_PARTY_BOOKING_NOTIFY_DELETE($parser) {
	$parser->echo_save($parser->packet_desc . "Index=".$parser->long() . "\n");
}

// packet 0x80c
function PACKET_CZ_SIMPLE_CASH_BTNSHOW($parser) {
	$parser->echo_save($parser->packet_desc . "\n");
}

// packet 0x80d
function PACKET_ZC_SIMPLE_CASH_BTNSHOW($parser) {
	$parser->echo_save($parser->packet_desc . "show=".$parser->byte() . "\n");
}

// packet 0x80e
function PACKET_ZC_NOTIFY_HP_TO_GROUPM_R2($parser) {
	$parser->echo_save($parser->packet_desc . "AID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "hp=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "maxhp=".$parser->long() . "\n");
}

// packet 0x80f
function PACKET_ZC_ADD_EXCHANGE_ITEM2($parser) {
	$parser->echo_save($parser->packet_desc . "ITID=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "type=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "count=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "IsIdentified=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "IsDamaged=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "refiningLevel=".$parser->byte() . "\n");
		$parser->echo_save($parser->nl . "card1=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "card2=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "card3=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "card4=".$parser->word() . "\n");
}

// packet 0x810
function PACKET_ZC_OPEN_BUYING_STORE($parser) {
	$parser->echo_save($parser->packet_desc . "count=".$parser->byte() . "\n");
}

// packet 0x811
function PACKET_CZ_REQ_OPEN_BUYING_STORE($parser) {
	$parser->echo_save($parser->packet_desc . "PacketLength=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "LimitZeny=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "result=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "storeName=".$parser->string(80) . "\n");
	$ItemList = ($parser->packet_length - $parser->packet_pointer) / 8;
	for ($i = 0; $i < $ItemList; $i++) {
		$parser->echo_save($parser->nl . "ITID=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "count=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "price=".$parser->long() . "\n");
	}
}

// packet 0x812
function PACKET_ZC_FAILED_OPEN_BUYING_STORE_TO_BUYER($parser) {
	$parser->echo_save($parser->packet_desc . "Result=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "total_weight=".$parser->long() . "\n");
}

// packet 0x813
function PACKET_ZC_MYITEMLIST_BUYING_STORE($parser) {
	$parser->echo_save($parser->packet_desc . "PacketLength=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "AID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "limitZeny=".$parser->long() . "\n");
	$ItemList = ($parser->packet_length - $parser->packet_pointer) / 9;
	for ($i = 0; $i < $ItemList; $i++) {
		$parser->echo_save($parser->nl . "price=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "count=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "type=".$parser->byte() . "\n");
		$parser->echo_save($parser->nl . "ITID=".$parser->word() . "\n");
	}
}

// packet 0x814
function PACKET_ZC_BUYING_STORE_ENTRY($parser) {
	$parser->echo_save($parser->packet_desc . "makerAID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "storeName=".$parser->string(80) . "\n");
}

// packet 0x815
function PACKET_CZ_REQ_CLOSE_BUYING_STORE($parser) {
	$parser->echo_save($parser->packet_desc . "\n");
}

// packet 0x816
function PACKET_ZC_DISAPPEAR_BUYING_STORE_ENTRY($parser) {
	$parser->echo_save($parser->packet_desc . "makerAID=".$parser->long() . "\n");
}

// packet 0x817
function PACKET_CZ_REQ_CLICK_TO_BUYING_STORE($parser) {
	$parser->echo_save($parser->packet_desc . "makerAID=".$parser->long() . "\n");
}

// packet 0x818
function PACKET_ZC_ACK_ITEMLIST_BUYING_STORE($parser) {
	$parser->echo_save($parser->packet_desc . "PacketLength=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "makerAID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "StoreID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "limitZeny=".$parser->long() . "\n");
	$ItemList = ($parser->packet_length - $parser->packet_pointer) / 9;
	for ($i = 0; $i < $ItemList; $i++) {
		$parser->echo_save($parser->nl . "price=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "count=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "type=".$parser->byte() . "\n");
		$parser->echo_save($parser->nl . "ITID=".$parser->word() . "\n");
	}
}

// packet 0x819
function PACKET_CZ_REQ_TRADE_BUYING_STORE($parser) {
	$parser->echo_save($parser->packet_desc . "PacketLength=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "makerAID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "StoreID=".$parser->long() . "\n");
	$ItemList = ($parser->packet_length - $parser->packet_pointer) / 6;
	for ($i = 0; $i < $ItemList; $i++) {
		$parser->echo_save($parser->nl . "index=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "ITID=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "count=".$parser->word() . "\n");
	}
}

// packet 0x81a
function PACKET_ZC_FAILED_TRADE_BUYING_STORE_TO_BUYER($parser) {
	$parser->echo_save($parser->packet_desc . "Result=".$parser->word() . "\n");
}

// packet 0x81b
function PACKET_ZC_UPDATE_ITEM_FROM_BUYING_STORE($parser) {
	$parser->echo_save($parser->packet_desc . "ITID=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "count=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "limitZeny=".$parser->long() . "\n");
}

// packet 0x81c
function PACKET_ZC_ITEM_DELETE_BUYING_STORE($parser) {
	$parser->echo_save($parser->packet_desc . "index=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "count=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "zeny=".$parser->long() . "\n");
}

// packet 0x81d
function PACKET_ZC_EL_INIT($parser) {
	$parser->echo_save($parser->packet_desc . "AID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "hp=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "maxHP=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "sp=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "maxSP=".$parser->long() . "\n");
}

// packet 0x81e
function PACKET_ZC_EL_PAR_CHANGE($parser) {
	$parser->echo_save($parser->packet_desc . "var=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "value=".$parser->long() . "\n");
}

// packet 0x81f
function PACKET_ZC_BROADCAST4($parser) {
	$parser->echo_save($parser->packet_desc . "PakcetType=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "PacketLength=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "Msgtype=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "ColorRGB=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "msg=".$parser->string($parser->packet_length - $parser->packet_pointer) . "\n");
}

// packet 0x820
function PACKET_ZC_COSTUME_SPRITE_CHANGE($parser) {
	$parser->echo_save($parser->packet_desc . "GID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "type=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "value=".$parser->long() . "\n");
}

// packet 0x821
function PACKET_AC_OTP_USER($parser) {
	$parser->echo_save($parser->packet_desc . "\n");
}

// packet 0x822
function PACKET_CA_OTP_AUTH_REQ($parser) {
	$parser->echo_save($parser->packet_desc . "OTPCode=".$parser->string(7) . "\n");
}

// packet 0x823
function PACKET_AC_OTP_AUTH_ACK($parser) {
	$parser->echo_save($parser->packet_desc . "PacketLength=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "LoginResult=".$parser->word() . "\n");
}

// packet 0x824
function PACKET_ZC_FAILED_TRADE_BUYING_STORE_TO_SELLER($parser) {
	$parser->echo_save($parser->packet_desc . "Result=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "ITID=".$parser->word() . "\n");
}

// packet 0x825a
function PACKET_CA_SSO_LOGIN_REQa($parser) {
	$parser->echo_save($parser->packet_desc . "PacketLength=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "Version=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "clienttype=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "ID=".$parser->string(24) . "\n");
	$parser->echo_save($parser->nl . "MacAddr=".$parser->string(17) . "\n");
	$parser->echo_save($parser->nl . "IpAddr=".$parser->string(15) . "\n");
	$parser->echo_save($parser->nl . "t1=".$parser->string($parser->packet_length - $parser->packet_pointer) . "\n");
}

// packet 0x825
function PACKET_CA_SSO_LOGIN_REQ($parser) {
	$parser->echo_save($parser->packet_desc . "PacketLength=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "Version=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "clienttype=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "ID=".$parser->string(24) . "\n");
	$parser->echo_save($parser->nl . "Passwd=".$parser->string(27) . "\n");
	$parser->echo_save($parser->nl . "MacAdress=".$parser->string(17) . "\n");
	$parser->echo_save($parser->nl . "IP=".$parser->string(15) . "\n");
	$parser->echo_save($parser->nl . "t1=".$parser->string($parser->packet_length - $parser->packet_pointer) . "\n");
}

// packet 0x826
function PACKET_AC_SSO_LOGIN_ACK($parser) {
	$parser->echo_save($parser->packet_desc . "Result=".$parser->word() . "\n");
}

// packet 0x827
function PACKET_CH_DELETE_CHAR3_RESERVED($parser) {
	$parser->echo_save($parser->packet_desc . "GID=".$parser->long() . "\n");
}

// packet 0x828
function PACKET_HC_DELETE_CHAR3_RESERVED($parser) {
	$parser->echo_save($parser->packet_desc . "GID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "Result=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "DeleteReservedDate=".$parser->long() . "\n");
}

// packet 0x829
function PACKET_CH_DELETE_CHAR3($parser) {
	$parser->echo_save($parser->packet_desc . "GID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "Birth=".$parser->string(6) . "\n");
}

// packet 0x82a
function PACKET_HC_DELETE_CHAR3($parser) {
	$parser->echo_save($parser->packet_desc . "GID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "Result=".$parser->long() . "\n");
}

// packet 0x82b
function PACKET_CH_DELETE_CHAR3_CANCEL($parser) {
	$parser->echo_save($parser->packet_desc . "GID=".$parser->long() . "\n");
}

// packet 0x82c
function PACKET_HC_DELETE_CHAR3_CANCEL($parser) {
	$parser->echo_save($parser->packet_desc . "GID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "Result=".$parser->long() . "\n");
}

// packet 0x82d
function PACKET_HC_ACCEPT2($parser) {
	$parser->echo_save($parser->packet_desc . "PacketLength=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "NormalSlotNum=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "PremiumSlotNum=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "BillingSlotNum=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "ProducibleSlotNum=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "ValidSlotNum=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "m_extension=".$parser->string(20) . "\n");
	$charInfo = ($parser->packet_length - $parser->packet_pointer) / 116;
	for ($i = 0; $i < $charInfo; $i++) {
		$parser->echo_save($parser->nl . "GID=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "exp=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "money=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "jobexp=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "joblevel=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "bodystate=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "healthstate=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "effectstate=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "virtue=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "honor=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "jobpoint=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "hp=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "maxhp=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "sp=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "maxsp=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "speed=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "job=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "head=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "weapon=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "level=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "sppoint=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "accessory=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "shield=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "accessory2=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "accessory3=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "headpalette=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "bodypalette=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "name=".$parser->string(24) . "\n");
		$parser->echo_save($parser->nl . "Str=".$parser->byte() . "\n");
		$parser->echo_save($parser->nl . "Agi=".$parser->byte() . "\n");
		$parser->echo_save($parser->nl . "Vit=".$parser->byte() . "\n");
		$parser->echo_save($parser->nl . "Int=".$parser->byte() . "\n");
		$parser->echo_save($parser->nl . "Dex=".$parser->byte() . "\n");
		$parser->echo_save($parser->nl . "Luk=".$parser->byte() . "\n");
		$parser->echo_save($parser->nl . "CharNum=".$parser->byte() . "\n");
		$parser->echo_save($parser->nl . "haircolor=".$parser->byte() . "\n");
		$parser->echo_save($parser->nl . "bIsChangedCharName=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "Robe=".$parser->long() . "\n");
	}
}

// packet 0x835
function PACKET_CZ_SEARCH_STORE_INFO($parser) {
	$parser->echo_save($parser->packet_desc . "PacketLength=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "StoreType=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "maxPrice=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "minPrice=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "ItemIDListSize=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "CardIDListSize=".$parser->byte() . "\n");
}

// packet 0x836
function PACKET_ZC_SEARCH_STORE_INFO_ACK($parser) {
	$parser->echo_save($parser->packet_desc . "PacketLength=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "IsFirstPage=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "IsNexPage=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "RemainedSearchCnt=".$parser->byte() . "\n");
	$SSI_List = ($parser->packet_length - $parser->packet_pointer) / 106;
	for ($i = 0; $i < $SSI_List; $i++) {
		$parser->echo_save($parser->nl . "SSI_ID=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "AID=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "StoreName=".$parser->string(80) . "\n");
		$parser->echo_save($parser->nl . "ITID=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "ItemType=".$parser->byte() . "\n");
		$parser->echo_save($parser->nl . "price=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "count=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "refiningLevel=".$parser->byte() . "\n");
		$parser->echo_save($parser->nl . "card1=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "card2=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "card3=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "card4=".$parser->word() . "\n");
	}
}

// packet 0x837
function PACKET_ZC_SEARCH_STORE_INFO_FAILED($parser) {
	$parser->echo_save($parser->packet_desc . "Reason=".$parser->byte() . "\n");
}

// packet 0x838
function PACKET_CZ_SEARCH_STORE_INFO_NEXT_PAGE($parser) {
	$parser->echo_save($parser->packet_desc . "\n");
}

// packet 0x839
function PACKET_ZC_ACK_BAN_GUILD_SSO($parser) {
	$parser->echo_save($parser->packet_desc . "charName=".$parser->string(24) . "\n");
	$parser->echo_save($parser->nl . "reasonDesc=".$parser->string(40) . "\n");
}

// packet 0x83a
function PACKET_ZC_OPEN_SEARCH_STORE_INFO($parser) {
	$parser->echo_save($parser->packet_desc . "OpenType=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "SearchCntMax=".$parser->byte() . "\n");
}

// packet 0x83b
function PACKET_CZ_CLOSE_SEARCH_STORE_INFO($parser) {
	$parser->echo_save($parser->packet_desc . "\n");
}

// packet 0x83c
function PACKET_CZ_SSILIST_ITEM_CLICK($parser) {
	$parser->echo_save($parser->packet_desc . "AID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "SSI_ID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "ITID=".$parser->word() . "\n");
}

// packet 0x83d
function PACKET_ZC_SSILIST_ITEM_CLICK_ACK($parser) {
	$parser->echo_save($parser->packet_desc . "x=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "y=".$parser->word() . "\n");
}

// packet 0x83e
function PACKET_AC_REFUSE_LOGIN_R2($parser) {
	$parser->echo_save($parser->packet_desc . "ErrorCode=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "blockDate=".$parser->string(20) . "\n");
}

// packet 0x83f
function PACKET_ZC_SEARCH_STORE_OPEN_INFO($parser) {
	$parser->echo_save($parser->packet_desc . "\n");
}

// packet 0x841
function PACKET_CH_SELECT_ACCESSIBLE_MAPNAME($parser) {
	$parser->echo_save($parser->packet_desc . "CharNum=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "mapListNum=".$parser->byte() . "\n");
}

// packet 0x842
function PACKET_CZ_RECALL_SSO($parser) {
	$parser->echo_save($parser->packet_desc . "aid=".$parser->long() . "\n");
}

// packet 0x843
function PACKET_CZ_REMOVE_AID_SSO($parser) {
	$parser->echo_save($parser->packet_desc . "aid=".$parser->long() . "\n");
}

// packet 0x844
function PACKET_CZ_SE_CASHSHOP_OPEN($parser) {
	$parser->echo_save($parser->packet_desc . "\n");
}

// packet 0x845
function PACKET_ZC_SE_CASHSHOP_OPEN($parser) {
	$parser->echo_save($parser->packet_desc . "cash_point=".$parser->long() . "\n");
}

// packet 0x846
function PACKET_CZ_REQ_SE_CASH_TAB_CODE($parser) {
	$parser->echo_save($parser->packet_desc . "tab_code=".$parser->word() . "\n");
}

// packet 0x847
function PACKET_ZC_ACK_SE_CASH_ITEM_LIST($parser) {
	$parser->echo_save($parser->packet_desc . "PacketLength=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "item_count=".$parser->word() . "\n");
	$items = ($parser->packet_length - $parser->packet_pointer) / 8;
	for ($i = 0; $i < $items; $i++) {
		$parser->echo_save($parser->nl . "item_id=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "price=".$parser->long() . "\n");
	}
}

// packet 0x848
function PACKET_CZ_SE_PC_BUY_CASHITEM_LIST($parser) {
	$parser->echo_save($parser->packet_desc . "PacketLength=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "item_count=".$parser->word() . "\n");
	$items = ($parser->packet_length - $parser->packet_pointer) / 10;
	for ($i = 0; $i < $items; $i++) {
		$parser->echo_save($parser->nl . "item_id=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "count=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "tab_code=".$parser->word() . "\n");
	}
}

// packet 0x849
function PACKET_ZC_SE_PC_BUY_CASHITEM_RESULT($parser) {
	$parser->echo_save($parser->packet_desc . "item_id=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "result=".$parser->word() . "\n");
}

// packet 0x84a
function PACKET_CZ_SE_CASHSHOP_CLOSE($parser) {
	$parser->echo_save($parser->packet_desc . "\n");
}

// packet 0x84b
function PACKET_ZC_ITEM_FALL_ENTRY4($parser) {
	$parser->echo_save($parser->packet_desc . "ITAID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "ITID=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "type=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "IsIdentified=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "xPos=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "yPos=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "subX=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "subY=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "count=".$parser->word() . "\n");
}

// packet 0x84c
function PACKET_CZ_MACRO_USE_SKILL($parser) {
	$parser->echo_save($parser->packet_desc . "SKID=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "selectedLevel=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "targetID=".$parser->long() . "\n");
}

// packet 0x84d
function PACKET_CZ_MACRO_USE_SKILL_TOGROUND($parser) {
	$parser->echo_save($parser->packet_desc . "SKID=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "selectedLevel=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "xPos=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "yPos=".$parser->word() . "\n");
}

// packet 0x84e
function PACKET_CZ_MACRO_REQUEST_MOVE($parser) {
	$parser->echo_save($parser->packet_desc . "dest=".$parser->string(3) . "\n");
}

// packet 0x84f
function PACKET_CZ_MACRO_ITEM_PICKUP($parser) {
	$parser->echo_save($parser->packet_desc . "ITAID=".$parser->long() . "\n");
}

// packet 0x850
function PACKET_CZ_MACRO_REQUEST_ACT($parser) {
	$parser->echo_save($parser->packet_desc . "action=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "targetGID=".$parser->long() . "\n");
}

// packet 0x851
function PACKET_ZC_GPK_DYNCODE($parser) {
	$parser->echo_save($parser->packet_desc . "PacketLength=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "code=".$parser->string($parser->packet_length - $parser->packet_pointer) . "\n");
}

// packet 0x852
function PACKET_CZ_GPK_DYNCODE_RELOAD($parser) {
	$parser->echo_save($parser->packet_desc . "\n");
}

// packet 0x855
function PACKET_ZC_MACRO_ITEMPICKUP_FAIL($parser) {
	$parser->echo_save($parser->packet_desc . "ITAID=".$parser->long() . "\n");
}

// packet 0x856
function PACKET_ZC_NOTIFY_MOVEENTRY8($parser) {
	$parser->echo_save($parser->packet_desc . "PacketLength=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "objecttype=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "GID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "speed=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "bodyState=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "healthState=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "effectState=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "job=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "head=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "weapon=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "accessory=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "moveStartTime=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "accessory2=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "accessory3=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "headpalette=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "bodypalette=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "headDir=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "robe=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "GUID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "GEmblemVer=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "honor=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "virtue=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "isPKModeON=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "sex=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "MoveData=".$parser->string(6) . "\n");
	$parser->echo_save($parser->nl . "xSize=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "ySize=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "clevel=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "font=".$parser->word() . "\n");
}

// packet 0x857
function PACKET_ZC_NOTIFY_STANDENTRY7($parser) {
	$parser->echo_save($parser->packet_desc . "PacketLength=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "objecttype=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "GID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "speed=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "bodyState=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "healthState=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "effectState=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "job=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "head=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "weapon=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "accessory=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "accessory2=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "accessory3=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "headpalette=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "bodypalette=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "headDir=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "robe=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "GUID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "GEmblemVer=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "honor=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "virtue=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "isPKModeON=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "sex=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "PosDir=".$parser->string(3) . "\n");
	$parser->echo_save($parser->nl . "xSize=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "ySize=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "state=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "clevel=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "font=".$parser->word() . "\n");
}

// packet 0x858
function PACKET_ZC_NOTIFY_NEWENTRY6($parser) {
	$parser->echo_save($parser->packet_desc . "PacketLength=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "objecttype=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "GID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "speed=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "bodyState=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "healthState=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "effectState=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "job=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "head=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "weapon=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "accessory=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "accessory2=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "accessory3=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "headpalette=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "bodypalette=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "headDir=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "robe=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "GUID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "GEmblemVer=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "honor=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "virtue=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "isPKModeON=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "sex=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "PosDir=".$parser->string(3) . "\n");
	$parser->echo_save($parser->nl . "xSize=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "ySize=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "clevel=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "font=".$parser->word() . "\n");
}

// packet 0x859
function PACKET_ZC_EQUIPWIN_MICROSCOPE2($parser) {
	$parser->echo_save($parser->packet_desc . "PacketLength=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "characterName=".$parser->string(24) . "\n");
	$parser->echo_save($parser->nl . "job=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "head=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "accessory=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "accessory2=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "accessory3=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "robe=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "headpalette=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "bodypalette=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "sex=".$parser->byte() . "\n");
}

// packet 0x8af
function PACKET_HC_WAITING_LOGIN($parser) {
	$parser->echo_save($parser->packet_desc . "AID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "CurWaitingNum=".$parser->long() . "\n");
}

// packet 0x8b0
function PACKET_CH_WAITING_LOGIN($parser) {
	$parser->echo_save($parser->packet_desc . "AID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "AuthCode=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "userLevel=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "clientType=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "Sex=".$parser->byte() . "\n");
}

// packet 0x8b4
function PACKET_ZC_START_COLLECTION($parser) {
	$parser->echo_save($parser->packet_desc . "\n");
}

// packet 0x8b5
function PACKET_CZ_TRYCOLLECTION($parser) {
	$parser->echo_save($parser->packet_desc . "targetAID=".$parser->long() . "\n");
}

// packet 0x8b6
function PACKET_ZC_TRYCOLLECTION($parser) {
	$parser->echo_save($parser->packet_desc . "result=".$parser->byte() . "\n");
}

// packet 0x8b7
function PACKET_HC_SECOND_PASSWD_REQ($parser) {
	$parser->echo_save($parser->packet_desc . "AID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "Seed=".$parser->long() . "\n");
}

// packet 0x8b8
function PACKET_CH_SECOND_PASSWD_ACK($parser) {
	$parser->echo_save($parser->packet_desc . "AID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "SecondPWIdx=".$parser->string(6) . "\n");
}

// packet 0x8b9
function PACKET_HC_SECOND_PASSWD_LOGIN($parser) {
	$parser->echo_save($parser->packet_desc . "Seed=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "AID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "Result=".$parser->word() . "\n");
}

// packet 0x8ba
function PACKET_CH_MAKE_SECOND_PASSWD($parser) {
	$parser->echo_save($parser->packet_desc . "AID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "Seed=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "SecondPWIdx=".$parser->string(6) . "\n");
}

// packet 0x8bb
function PACKET_HC_MAKE_SECOND_PASSWD($parser) {
	$parser->echo_save($parser->packet_desc . "Result=".$parser->word() . "\n");
}

// packet 0x8bc
function PACKET_CH_DELETE_SECOND_PASSWD($parser) {
	$parser->echo_save($parser->packet_desc . "AID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "Seed=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "SecondPWIdx=".$parser->string(6) . "\n");
}

// packet 0x8bd
function PACKET_HC_DELETE_SECOND_PASSWD($parser) {
	$parser->echo_save($parser->packet_desc . "Result=".$parser->word() . "\n");
}

// packet 0x8be
function PACKET_CH_EDIT_SECOND_PASSWD($parser) {
	$parser->echo_save($parser->packet_desc . "AID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "Seed=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "SecondPWIdx=".$parser->string(6) . "\n");
}

// packet 0x8bf
function PACKET_HC_EDIT_SECOND_PASSWD($parser) {
	$parser->echo_save($parser->packet_desc . "Result=".$parser->word() . "\n");
}

// packet 0x8c0
function PACKET_ZC_ACK_SE_CASH_ITEM_LIST2($parser) {
	$parser->echo_save($parser->packet_desc . "PacketLength=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "OpenIdentity=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "item_count=".$parser->word() . "\n");
	$ItemList = ($parser->packet_length - $parser->packet_pointer) / 6;
	for ($i = 0; $i < $ItemList; $i++) {
		$parser->echo_save($parser->nl . "item_id=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "price=".$parser->long() . "\n");
	}
}

// packet 0x8c1
function PACKET_CZ_MACRO_START($parser) {
	$parser->echo_save($parser->packet_desc . "\n");
}

// packet 0x8c2
function PACKET_CZ_MACRO_STOP($parser) {
	$parser->echo_save($parser->packet_desc . "\n");
}

// packet 0x8c3
function PACKET_CH_NOT_AVAILABLE_SECOND_PASSWD($parser) {
	$parser->echo_save($parser->packet_desc . "AID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "SecondPWIdx=".$parser->string(4) . "\n");
}

// packet 0x8c4
function PACKET_HC_NOT_AVAILABLE_SECOND_PASSWD($parser) {
	$parser->echo_save($parser->packet_desc . "Result=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "Seed=".$parser->long() . "\n");
}

// packet 0x8c5
function PACKET_CH_AVAILABLE_SECOND_PASSWD($parser) {
	$parser->echo_save($parser->packet_desc . "AID=".$parser->long() . "\n");
}

// packet 0x8c6
function PACKET_HC_AVAILABLE_SECOND_PASSWD($parser) {
	$parser->echo_save($parser->packet_desc . "Result=".$parser->word() . "\n");
}

// packet 0x8c7
function PACKET_ZC_SKILL_ENTRY3($parser) {
	$parser->echo_save($parser->packet_desc . "PacketLength=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "AID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "creatorAID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "xPos=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "yPos=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "job=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "RadiusRange=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "isVisible=".$parser->byte() . "\n");
}

// packet 0x8c8
function PACKET_ZC_NOTIFY_ACT3($parser) {
	$parser->echo_save($parser->packet_desc . "GID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "targetGID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "startTime=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "attackMT=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "attackedMT=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "damage=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "IsSPDamage=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "count=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "action=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "leftDamage=".$parser->long() . "\n");
}

// packet 0x8c9
function PACKET_CZ_REQ_SCHEDULER_CASHITEM($parser) {
	$parser->echo_save($parser->packet_desc . "\n");
}

// packet 0x8cb
function PACKET_ZC_PERSONAL_INFOMATION($parser) {
	$parser->echo_save($parser->packet_desc . "PacketLength=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "Exp=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "Death=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "Drop=".$parser->word() . "\n");
	$DetailInfo = ($parser->packet_length - $parser->packet_pointer) / 6;
	for ($i = 0; $i < $DetailInfo; $i++) {
		$parser->echo_save($parser->nl . "InfoType=".$parser->byte() . "\n");
		$parser->echo_save($parser->nl . "Exp=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "Death=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "Drop=".$parser->word() . "\n");
	}
}

// packet 0x8cc
function PACKET_CA_LOGIN5($parser) {
	$parser->echo_save($parser->packet_desc . "Version=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "ID=".$parser->string(51) . "\n");
	$parser->echo_save($parser->nl . "Passwd=".$parser->string(51) . "\n");
	$parser->echo_save($parser->nl . "clienttype=".$parser->byte() . "\n");
}

// packet 0x8cd
function PACKET_ZC_STOPMOVE_FORCE($parser) {
	$parser->echo_save($parser->packet_desc . "AID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "xPos=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "yPos=".$parser->word() . "\n");
}

// packet 0x8ce
function PACKET_ZC_FAILED_GET_ITEM_FROM_ZONEDA($parser) {
	$parser->echo_save($parser->packet_desc . "\n");
}

// packet 0x8cf
function PACKET_ZC_SPIRITS_ATTRIBUTE($parser) {
	$parser->echo_save($parser->packet_desc . "AID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "SpritsType=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "Num=".$parser->word() . "\n");
}

// packet 0x8d0
function PACKET_ZC_REQ_WEAR_EQUIP_ACK2($parser) {
	$parser->echo_save($parser->packet_desc . "index=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "wearLocation=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "wItemSpriteNumber=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "result=".$parser->byte() . "\n");
}

// packet 0x8d1
function PACKET_ZC_REQ_TAKEOFF_EQUIP_ACK2($parser) {
	$parser->echo_save($parser->packet_desc . "index=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "wearLocation=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "result=".$parser->byte() . "\n");
}

// packet 0x8d2
function PACKET_ZC_FASTMOVE($parser) {
	$parser->echo_save($parser->packet_desc . "AID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "targetXpos=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "targetYpos=".$parser->word() . "\n");
}

// packet 0x8d3
function PACKET_ZC_SE_CASHSHOP_UPDATE($parser) {
	$parser->echo_save($parser->packet_desc . "cash_point=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "free_point=".$parser->long() . "\n");
}

// packet 0x8d4
function PACKET_CH_REQ_CHANGE_CHARACTER_SLOT($parser) {
	$parser->echo_save($parser->packet_desc . "beforeCharNum=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "AfterCharNum=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "CurChrSlotCnt=".$parser->word() . "\n");
}

// packet 0x8d5
function PACKET_HC_ACK_CHANGE_CHARACTER_SLOT($parser) {
	$parser->echo_save($parser->packet_desc . "PacketLength=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "Reason=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "AfterChrSlotCnt=".$parser->word() . "\n");
}

// packet 0x8d6
function PACKET_ZC_CLEAR_DIALOG($parser) {
	$parser->echo_save($parser->packet_desc . "NAID=".$parser->long() . "\n");
}

// packet 0x8d7
function PACKET_CZ_REQ_ENTRY_QUEUE_APPLY($parser) {
	$parser->echo_save($parser->packet_desc . "ApplyType=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "EntryQueueName=".$parser->string(24) . "\n");
}

// packet 0x8d8
function PACKET_ZC_ACK_ENTRY_QUEUE_APPLY($parser) {
	$parser->echo_save($parser->packet_desc . "Result=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "EntryQueueName=".$parser->string(24) . "\n");
}

// packet 0x8d9
function PACKET_ZC_NOTIFY_ENTRY_QUEUE_APPLY($parser) {
	$parser->echo_save($parser->packet_desc . "EntryQueueName=".$parser->string(24) . "\n");
	$parser->echo_save($parser->nl . "Ranking=".$parser->long() . "\n");
}

// packet 0x8da
function PACKET_CZ_REQ_ENTRY_QUEUE_CANCEL($parser) {
	$parser->echo_save($parser->packet_desc . "EntryQueueName=".$parser->string(24) . "\n");
}

// packet 0x8db
function PACKET_ZC_ACK_ENTRY_QUEUE_CANCEL($parser) {
	$parser->echo_save($parser->packet_desc . "Result=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "EntryQueueName=".$parser->string(24) . "\n");
}

// packet 0x8dc
function PACKET_ZC_NOTIFY_ENTRY_QUEUE_ADMISSION($parser) {
	$parser->echo_save($parser->packet_desc . "EntryQueueName=".$parser->string(24) . "\n");
}

// packet 0x8dd
function PACKET_CZ_REPLY_ENTRY_QUEUE_ADMISSION($parser) {
	$parser->echo_save($parser->packet_desc . "Result=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "EntryQueueName=".$parser->string(24) . "\n");
}

// packet 0x8de
function PACKET_ZC_REPLY_ACK_ENTRY_QUEUE_ADMISSION($parser) {
	$parser->echo_save($parser->packet_desc . "Result=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "EntryQueueName=".$parser->string(24) . "\n");
}

// packet 0x8df
function PACKET_ZC_NOTIFY_LOBBY_ADMISSION($parser) {
	$parser->echo_save($parser->packet_desc . "EntryQueueName=".$parser->string(24) . "\n");
	$parser->echo_save($parser->nl . "LobbyName=".$parser->string(24) . "\n");
}

// packet 0x8e0
function PACKET_CZ_REPLY_LOBBY_ADMISSION($parser) {
	$parser->echo_save($parser->packet_desc . "Result=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "EntryQueueName=".$parser->string(24) . "\n");
	$parser->echo_save($parser->nl . "LobbyName=".$parser->string(24) . "\n");
}

// packet 0x8e1
function PACKET_ZC_REPLY_ACK_LOBBY_ADMISSION($parser) {
	$parser->echo_save($parser->packet_desc . "Result=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "EntryQueueName=".$parser->string(24) . "\n");
	$parser->echo_save($parser->nl . "LobbyName=".$parser->string(24) . "\n");
}

// packet 0x8e2
function PACKET_ZC_NAVIGATION_ACTIVE($parser) {
	$parser->echo_save($parser->packet_desc . "Type=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "SetType=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "Hide=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "MapName=".$parser->string(16) . "\n");
	$parser->echo_save($parser->nl . "xPos=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "yPos=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "sprIndex=".$parser->word() . "\n");
}

// packet 0x8e3
function PACKET_HC_UPDATE_CHARINFO($parser) {
	$parser->echo_save($parser->packet_desc  . "\n");
	$charInfo = ($parser->packet_length - $parser->packet_pointer) / 144;
	for ($i = 0; $i < $charInfo; $i++) {
		$parser->echo_save($parser->nl . "GID=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "exp=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "money=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "jobexp=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "joblevel=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "bodystate=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "healthstate=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "effectstate=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "virtue=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "honor=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "jobpoint=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "hp=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "maxhp=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "sp=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "maxsp=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "speed=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "job=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "head=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "weapon=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "level=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "sppoint=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "accessory=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "shield=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "accessory2=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "accessory3=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "headpalette=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "bodypalette=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "name=".$parser->string(24) . "\n");
		$parser->echo_save($parser->nl . "Str=".$parser->byte() . "\n");
		$parser->echo_save($parser->nl . "Agi=".$parser->byte() . "\n");
		$parser->echo_save($parser->nl . "Vit=".$parser->byte() . "\n");
		$parser->echo_save($parser->nl . "Int=".$parser->byte() . "\n");
		$parser->echo_save($parser->nl . "Dex=".$parser->byte() . "\n");
		$parser->echo_save($parser->nl . "Luk=".$parser->byte() . "\n");
		$parser->echo_save($parser->nl . "CharNum=".$parser->byte() . "\n");
		$parser->echo_save($parser->nl . "haircolor=".$parser->byte() . "\n");
		$parser->echo_save($parser->nl . "bIsChangedCharName=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "lastMap=".$parser->string(16) . "\n");
		$parser->echo_save($parser->nl . "DeleteDate=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "Robe=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "SlotAddon=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "RenameAddon=".$parser->long() . "\n");
	}
}

// packet 0x8e4
function PACKET_AC_SHUTDOWN_INFO($parser) {
	$parser->echo_save($parser->packet_desc . "Time=".$parser->long() . "\n");
}

// packet 0x8e5
function PACKET_CZ_PARTY_RECRUIT_REQ_REGISTER($parser) {
	$parser->echo_save($parser->packet_desc  . "\n");
	$regsiterInfo = ($parser->packet_length - $parser->packet_pointer) / 39;
	for ($i = 0; $i < $regsiterInfo; $i++) {
		$parser->echo_save($parser->nl . "Level=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "Notice=".$parser->string(37) . "\n");
	}
}

// packet 0x8e6
function PACKET_ZC_PARTY_RECRUIT_ACK_REGISTER($parser) {
	$parser->echo_save($parser->packet_desc . "Result=".$parser->word() . "\n");
}

// packet 0x8e7
function PACKET_CZ_PARTY_RECRUIT_REQ_SEARCH($parser) {
	$parser->echo_save($parser->packet_desc . "Level=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "LastIndex=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "ResultCount=".$parser->word() . "\n");
}

// packet 0x8e9
function PACKET_CZ_PARTY_RECRUIT_REQ_DELETE($parser) {
	$parser->echo_save($parser->packet_desc . "\n");
}

// packet 0x8ea
function PACKET_ZC_PARTY_RECRUIT_ACK_DELETE($parser) {
	$parser->echo_save($parser->packet_desc . "Result=".$parser->word() . "\n");
}

// packet 0x8eb
function PACKET_CZ_PARTY_RECRUIT_REQ_UPDATE($parser) {
	$parser->echo_save($parser->packet_desc . "Notice=".$parser->string(37) . "\n");
}

// packet 0x8ec
function PACKET_ZC_PARTY_RECRUIT_NOTIFY_INSERT($parser) {
	$parser->echo_save($parser->packet_desc  . "\n");
		$parser->echo_save($parser->nl . "Index=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "ExpireTime=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "CharName=".$parser->string(24) . "\n");
		$parser->echo_save($parser->nl . "Level=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "Notice=".$parser->string(37) . "\n");
}

// packet 0x8ed
function PACKET_ZC_PARTY_RECRUIT_NOTIFY_UPDATE($parser) {
	$parser->echo_save($parser->packet_desc . "Index=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "Notice=".$parser->string(37) . "\n");
}

// packet 0x8ee
function PACKET_ZC_PARTY_RECRUIT_NOTIFY_DELETE($parser) {
	$parser->echo_save($parser->packet_desc . "Index=".$parser->long() . "\n");
}

// packet 0x8ef
function PACKET_CZ_PARTY_RECRUIT_ADD_FILTERLINGLIST($parser) {
	$parser->echo_save($parser->packet_desc . "Index=".$parser->long() . "\n");
}

// packet 0x8f0
function PACKET_CZ_PARTY_RECRUIT_SUB_FILTERLINGLIST($parser) {
	$parser->echo_save($parser->packet_desc . "GID=".$parser->long() . "\n");
}

// packet 0x8f1
function PACKET_CZ_PARTY_RECRUIT_REQ_VOLUNTEER($parser) {
	$parser->echo_save($parser->packet_desc . "Index=".$parser->long() . "\n");
}

// packet 0x8f2
function PACKET_ZC_PARTY_RECRUIT_VOLUNTEER_INFO($parser) {
	$parser->echo_save($parser->packet_desc . "AID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "Job=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "Level=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "CharName=".$parser->string(24) . "\n");
}

// packet 0x8f4
function PACKET_CZ_PARTY_RECRUIT_SHOW_EQUIPMENT($parser) {
	$parser->echo_save($parser->packet_desc . "TargetGID=".$parser->long() . "\n");
}

// packet 0x8f6
function PACKET_ZC_PARTY_RECRUIT_RECALL_COST($parser) {
	$parser->echo_save($parser->packet_desc . "Money=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "mapName=".$parser->string(16) . "\n");
}

// packet 0x8f7
function PACKET_CZ_PARTY_RECRUIT_ACK_RECALL($parser) {
	$parser->echo_save($parser->packet_desc . "Result=".$parser->byte() . "\n");
}

// packet 0x8f8
function PACKET_ZC_PARTY_RECRUIT_FAILED_RECALL($parser) {
	$parser->echo_save($parser->packet_desc . "CallerAID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "Reason=".$parser->byte() . "\n");
}

// packet 0x8f9
function PACKET_CZ_PARTY_RECRUIT_REFUSE_VOLUNTEER($parser) {
	$parser->echo_save($parser->packet_desc . "REFUSE_AID=".$parser->long() . "\n");
}

// packet 0x8fa
function PACKET_ZC_PARTY_RECRUIT_REFUSE_VOLUNTEER($parser) {
	$parser->echo_save($parser->packet_desc . "Index=".$parser->long() . "\n");
}

// packet 0x8fb
function PACKET_CZ_PARTY_RECRUIT_CANCEL_VOLUNTEER($parser) {
	$parser->echo_save($parser->packet_desc . "Index=".$parser->long() . "\n");
}

// packet 0x8fc
function PACKET_CH_REQ_CHANGE_CHARACTERNAME($parser) {
	$parser->echo_save($parser->packet_desc . "dwGID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "szCharName=".$parser->string(24) . "\n");
}

// packet 0x8fd
function PACKET_HC_ACK_CHANGE_CHARACTERNAME($parser) {
	$parser->echo_save($parser->packet_desc . "dwResult=".$parser->long() . "\n");
}

// packet 0x8ff
function PACKET_ZC_EFST_SET_ENTER($parser) {
	$parser->echo_save($parser->packet_desc . "AID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "hEFST=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "Time=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "Val1=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "Val2=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "Val3=".$parser->long() . "\n");
}

// packet 0x900
function PACKET_ZC_INVENTORY_ITEMLIST_NORMAL($parser) {
	$parser->echo_save($parser->packet_desc . "PacketLength=".$parser->word() . "\n");
	$Items = ($parser->packet_length - $parser->packet_pointer) / 22;
	for ($i = 0; $i < $Items; $i++) {
		$parser->echo_save($parser->nl . "index=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "ITID=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "type=".$parser->byte() . "\n");
		$parser->echo_save($parser->nl . "count=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "WearState=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "card1=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "card2=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "card3=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "card4=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "HireExpireDate=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "Flag=".$parser->byte() . "\n");
	}
}

// packet 0x901
function PACKET_ZC_INVENTORY_ITEMLIST_EQUIP($parser) {
	$parser->echo_save($parser->packet_desc . "PacketLength=".$parser->word() . "\n");
	$Items = ($parser->packet_length - $parser->packet_pointer) / 27;
	for ($i = 0; $i < $Items; $i++) {
		$parser->echo_save($parser->nl . "index=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "ITID=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "type=".$parser->byte() . "\n");
		$parser->echo_save($parser->nl . "location=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "WearState=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "RefiningLevel=".$parser->byte() . "\n");
		$parser->echo_save($parser->nl . "card1=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "card2=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "card3=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "card4=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "HireExpireDate=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "bindOnEquipType=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "wItemSpriteNumber=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "Flag=".$parser->byte() . "\n");
	}
}

// packet 0x907
function PACKET_CZ_INVENTORY_TAB($parser) {
	$parser->echo_save($parser->packet_desc . "Index=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "NORMALorPRIVATE=".$parser->byte() . "\n");
}

// packet 0x908
function PACKET_ZC_INVENTORY_TAB($parser) {
	$parser->echo_save($parser->packet_desc . "Index=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "NORMALorPRIVATE=".$parser->byte() . "\n");
}

// packet 0x909
function PACKET_ZC_PARTY_RECRUIT_CANCEL_VOLUNTEER($parser) {
	$parser->echo_save($parser->packet_desc . "index=".$parser->long() . "\n");
}

// packet 0x90a
function PACKET_CZ_REQ_ENTRY_QUEUE_RANKING($parser) {
	$parser->echo_save($parser->packet_desc . "EntryQueueName=".$parser->string(24) . "\n");
}

// packet 0x90b
function PACKET_ZC_PARTY_RECRUIT_ADD_FILTERLINGLIST($parser) {
	$parser->echo_save($parser->packet_desc . "GID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "CharName=".$parser->string(24) . "\n");
}

// packet 0x90c
function PACKET_ZC_PARTY_RECRUIT_SUB_FILTERLINGLIST($parser) {
	$parser->echo_save($parser->packet_desc . "GID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "CharName=".$parser->string(24) . "\n");
}

// packet 0x90d
function PACKET_ZC_PREMIUM_CAMPAIGN_INFO($parser) {
	$parser->echo_save($parser->packet_desc . "PacketLength=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "Count=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "PremiumValue=".$parser->long() . "\n");
	$CampainInfo = ($parser->packet_length - $parser->packet_pointer) / 14;
	for ($i = 0; $i < $CampainInfo; $i++) {
		$parser->echo_save($parser->nl . "Grade=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "Exp=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "Death=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "Drp=".$parser->long() . "\n");
	}
}

// packet 0x90e
function PACKET_ZC_ENTRY_QUEUE_INIT($parser) {
	$parser->echo_save($parser->packet_desc . "\n");
}

// packet 0x90f
function PACKET_ZC_NOTIFY_NEWENTRY7($parser) {
	$parser->echo_save($parser->packet_desc . "PacketLength=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "objecttype=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "GID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "speed=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "bodyState=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "healthState=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "effectState=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "job=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "head=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "weapon=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "accessory=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "accessory2=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "accessory3=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "headpalette=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "bodypalette=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "headDir=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "robe=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "GUID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "GEmblemVer=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "honor=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "virtue=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "isPKModeON=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "sex=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "PosDir=".$parser->string(3) . "\n");
	$parser->echo_save($parser->nl . "xSize=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "ySize=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "clevel=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "font=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "maxHP=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "HP=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "isBoss=".$parser->byte() . "\n");
}

// packet 0x910
function PACKET_CZ_REQ_PARTY_NAME($parser) {
	$parser->echo_save($parser->packet_desc . "AID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "PartyID=".$parser->long() . "\n");
}

// packet 0x911
function PACKET_ZC_ACK_PARTY_NAME($parser) {
	$parser->echo_save($parser->packet_desc . "PartyID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "szPartyName=".$parser->string(24) . "\n");
}

// packet 0x912
function PACKET_CZ_REQ_GUILD_NAME($parser) {
	$parser->echo_save($parser->packet_desc . "AID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "GuildID=".$parser->long() . "\n");
}

// packet 0x914
function PACKET_ZC_NOTIFY_MOVEENTRY9($parser) {
	$parser->echo_save($parser->packet_desc . "PacketLength=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "objecttype=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "GID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "speed=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "bodyState=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "healthState=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "effectState=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "job=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "head=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "weapon=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "accessory=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "moveStartTime=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "accessory2=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "accessory3=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "headpalette=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "bodypalette=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "headDir=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "robe=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "GUID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "GEmblemVer=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "honor=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "virtue=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "isPKModeON=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "sex=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "MoveData=".$parser->string(6) . "\n");
	$parser->echo_save($parser->nl . "xSize=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "ySize=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "clevel=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "font=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "maxHP=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "HP=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "isBoss=".$parser->byte() . "\n");
}

// packet 0x915
function PACKET_ZC_NOTIFY_STANDENTRY8($parser) {
	$parser->echo_save($parser->packet_desc . "PacketLength=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "objecttype=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "GID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "speed=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "bodyState=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "healthState=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "effectState=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "job=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "head=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "weapon=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "accessory=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "accessory2=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "accessory3=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "headpalette=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "bodypalette=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "headDir=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "robe=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "GUID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "GEmblemVer=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "honor=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "virtue=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "isPKModeON=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "sex=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "PosDir=".$parser->string(3) . "\n");
	$parser->echo_save($parser->nl . "xSize=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "ySize=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "state=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "clevel=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "font=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "maxHP=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "HP=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "isBoss=".$parser->byte() . "\n");
}

// packet 0x916
function PACKET_CZ_REQ_JOIN_GUILD2($parser) {
	$parser->echo_save($parser->packet_desc . "characterName=".$parser->string(24) . "\n");
}

// packet 0x91b
function PACKET_ZC_PRNPC_STATE($parser) {
	$parser->echo_save($parser->packet_desc . "Winner=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "Point=".$parser->byte() . "\n");
}

// packet 0x91c
function PACKET_ZC_PARTY_RECRUIT_CANCEL_VOLUNTEER_TO_PM($parser) {
	$parser->echo_save($parser->packet_desc . "AID=".$parser->long() . "\n");
}

// packet 0x96f
function PACKET_ZC_ACK_MERGE_ITEM($parser) {
	$parser->echo_save($parser->packet_desc . "item_index=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "item_count=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "Result=".$parser->byte() . "\n");
}

// packet 0x970
function PACKET_CH_MAKE_CHAR_NOT_STATS($parser) {
	$parser->echo_save($parser->packet_desc . "name=".$parser->string(24) . "\n");
	$parser->echo_save($parser->nl . "CharNum=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "headPal=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "head=".$parser->word() . "\n");
}

// packet 0x971
function PACKET_ZC_PARTY_RECRUIT_REFUSE_VOLUNTEER_TO_PM($parser) {
	$parser->echo_save($parser->packet_desc . "PM_AID=".$parser->long() . "\n");
}

// packet 0x973
function PACKET_ZC_WAIT_DIALOG2($parser) {
	$parser->echo_save($parser->packet_desc . "NAID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "type=".$parser->byte() . "\n");
}

// packet 0x974
function PACKET_CZ_CANCEL_MERGE_ITEM($parser) {
	$parser->echo_save($parser->packet_desc . "\n");
}

// packet 0x977
function PACKET_ZC_HP_INFO($parser) {
	$parser->echo_save($parser->packet_desc . "AID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "HP=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "MaxHP=".$parser->long() . "\n");
}

// packet 0x978
function PACKET_CZ_REQ_BEFORE_WORLD_INFO($parser) {
	$parser->echo_save($parser->packet_desc . "AID=".$parser->long() . "\n");
}

// packet 0x979
function PACKET_ZC_ACK_BEFORE_WORLD_INFO($parser) {
	$parser->echo_save($parser->packet_desc . "WorldName=".$parser->string(24) . "\n");
	$parser->echo_save($parser->nl . "CharName=".$parser->string(24) . "\n");
}

// packet 0x97a
function PACKET_ZC_ALL_QUEST_LIST2($parser) {
	$parser->echo_save($parser->packet_desc . "PacketLength=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "QuestCount=".$parser->long() . "\n");
	$QuestInfo = ($parser->packet_length - $parser->packet_pointer) / 15;
	for ($i = 0; $i < $QuestInfo; $i++) {
		$parser->echo_save($parser->nl . "questID=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "active=".$parser->byte() . "\n");
		$parser->echo_save($parser->nl . "quest_svrTime=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "quest_endTime=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "hunting_count=".$parser->word() . "\n");
	}
}

// packet 0x97b
function PACKET_ZC_PERSONAL_INFOMATION2($parser) {
	$parser->echo_save($parser->packet_desc . "PacketLength=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "Exp=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "Death=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "Drop=".$parser->long() . "\n");
	$DatailInfo = ($parser->packet_length - $parser->packet_pointer) / 13;
	for ($i = 0; $i < $DatailInfo; $i++) {
		$parser->echo_save($parser->nl . "InfoType=".$parser->byte() . "\n");
		$parser->echo_save($parser->nl . "Exp=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "Death=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "Drop=".$parser->long() . "\n");
	}
}

// packet 0x97c
function PACKET_CZ_REQ_RANKING($parser) {
	$parser->echo_save($parser->packet_desc . "RankingType=".$parser->word() . "\n");
}

// packet 0x97d
function PACKET_ZC_ACK_RANKING($parser) {
	$parser->echo_save($parser->packet_desc . "RankingType=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "CharName=".$parser->string(24) . "\n");
	$parser->echo_save($parser->nl . "Point=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "myPoint=".$parser->long() . "\n");
}

// packet 0x97e
function PACKET_ZC_UPDATE_RANKING_POINT($parser) {
	$parser->echo_save($parser->packet_desc . "RankingType=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "Point=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "TotalPoint=".$parser->long() . "\n");
}

// packet 0x980
function PACKET_CZ_SELECTCART($parser) {
	$parser->echo_save($parser->packet_desc . "Identity=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "type=".$parser->byte() . "\n");
}

// packet 0x981
function PACKET_ZC_PERSONAL_INFOMATION_CHN($parser) {
	$parser->echo_save($parser->packet_desc . "PacketLength=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "Exp=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "Death=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "Drop=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "ActivityRate=".$parser->word() . "\n");
	$DatailInfo = ($parser->packet_length - $parser->packet_pointer) / 13;
	for ($i = 0; $i < $DatailInfo; $i++) {
		$parser->echo_save($parser->nl . "InfoType=".$parser->byte() . "\n");
		$parser->echo_save($parser->nl . "Exp=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "Death=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "Drop=".$parser->long() . "\n");
	}
}

// packet 0x982
function PACKET_ZC_FATIGUE_CHN($parser) {
	$parser->echo_save($parser->packet_desc . "Level=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "TotalPlayTime=".$parser->long() . "\n");
}

// packet 0x983
function PACKET_ZC_MSG_STATE_CHANGE3($parser) {
	$parser->echo_save($parser->packet_desc . "index=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "AID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "state=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "MaxMS=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "RemainMS=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "val=".$parser->long() . "\n");
}

// packet 0x984
function PACKET_ZC_EFST_SET_ENTER2($parser) {
	$parser->echo_save($parser->packet_desc . "AID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "hEFST=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "MaxMS=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "Time=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "Val1=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "Val2=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "Val3=".$parser->long() . "\n");
}

// packet 0x985
function PACKET_ZC_SKILL_POSTDELAY_LIST2($parser) {
	$parser->echo_save($parser->packet_desc . "PacketLength=".$parser->word() . "\n");
	$PostDelay = ($parser->packet_length - $parser->packet_pointer) / 10;
	for ($i = 0; $i < $PostDelay; $i++) {
		$parser->echo_save($parser->nl . "SKID=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "MaxDelayTM=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "DelayTM=".$parser->long() . "\n");
	}
}

// packet 0x986
function PACKET_AC_SHUTDOWN_NOTIFY($parser) {
	$parser->echo_save($parser->packet_desc . "Time=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "ServerTime=".$parser->long() . "\n");
}

// packet 0x987
function PACKET_CA_LOGIN6($parser) {
	$parser->echo_save($parser->packet_desc . "Version=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "ID=".$parser->string(24) . "\n");
	$parser->echo_save($parser->nl . "PasswdMD5=".$parser->string(32) . "\n");
	$parser->echo_save($parser->nl . "clienttype=".$parser->byte() . "\n");
}

// packet 0x988
function PACKET_ZC_NOTIFY_CLAN_CONNECTINFO($parser) {
	$parser->echo_save($parser->packet_desc . "NumConnect=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "NumTotal=".$parser->word() . "\n");
}

// packet 0x989
function PACKET_ZC_ACK_CLAN_LEAVE($parser) {
	$parser->echo_save($parser->packet_desc . "\n");
}

// packet 0x98a
function PACKET_ZC_CLANINFO($parser) {
	$parser->echo_save($parser->packet_desc . "PacketLength=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "EmblemNum=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "ClanName=".$parser->string(24) . "\n");
	$parser->echo_save($parser->nl . "Mastername=".$parser->string(24) . "\n");
	$parser->echo_save($parser->nl . "ManageMap=".$parser->string(16) . "\n");
	$parser->echo_save($parser->nl . "Num_AllyClan=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "Num_HostileClan=".$parser->byte() . "\n");
}

// packet 0x98b
function PACKET_AC_REQ_NEW_USER($parser) {
	$parser->echo_save($parser->packet_desc . "\n");
}

// packet 0x98c
function PACKET_CA_ACK_NEW_USER($parser) {
	$parser->echo_save($parser->packet_desc . "Sex=".$parser->word() . "\n");
}

// packet 0x98d
function PACKET_CZ_CLAN_CHAT($parser) {
	$parser->echo_save($parser->packet_desc . "PacketLength=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "chat=".$parser->string($parser->packet_length - $parser->packet_pointer) . "\n");
}

// packet 0x98e
function PACKET_ZC_NOTIFY_CLAN_CHAT($parser) {
	$parser->echo_save($parser->packet_desc . "PacketLength=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "charName=".$parser->string(24) . "\n");
	$parser->echo_save($parser->nl . "chat=".$parser->string($parser->packet_length - $parser->packet_pointer) . "\n");
}

// packet 0x990
function PACKET_ZC_ITEM_PICKUP_ACK_V5($parser) {
	$parser->echo_save($parser->packet_desc . "Index=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "count=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "ITID=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "IsIdentified=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "IsDamaged=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "refiningLevel=".$parser->byte() . "\n");
		$parser->echo_save($parser->nl . "card1=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "card2=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "card3=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "card4=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "location=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "type=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "result=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "HireExpireDate=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "bindOnEquipType=".$parser->word() . "\n");
}

// packet 0x991
function PACKET_ZC_INVENTORY_ITEMLIST_NORMAL_V5($parser) {
	$parser->echo_save($parser->packet_desc . "PacketLength=".$parser->word() . "\n");
	$Items = ($parser->packet_length - $parser->packet_pointer) / 24;
	for ($i = 0; $i < $Items; $i++) {
		$parser->echo_save($parser->nl . "index=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "ITID=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "type=".$parser->byte() . "\n");
		$parser->echo_save($parser->nl . "count=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "WearState=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "card1=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "card2=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "card3=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "card4=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "HireExpireDate=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "Flag=".$parser->byte() . "\n");
	}
}

// packet 0x992
function PACKET_ZC_INVENTORY_ITEMLIST_EQUIP_V5($parser) {
	$parser->echo_save($parser->packet_desc . "PacketLength=".$parser->word() . "\n");
	$Items = ($parser->packet_length - $parser->packet_pointer) / 31;
	for ($i = 0; $i < $Items; $i++) {
		$parser->echo_save($parser->nl . "index=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "ITID=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "type=".$parser->byte() . "\n");
		$parser->echo_save($parser->nl . "location=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "WearState=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "RefiningLevel=".$parser->byte() . "\n");
		$parser->echo_save($parser->nl . "card1=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "card2=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "card3=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "card4=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "HireExpireDate=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "bindOnEquipType=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "wItemSpriteNumber=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "Flag=".$parser->byte() . "\n");
	}
}

// packet 0x993
function PACKET_ZC_CART_ITEMLIST_NORMAL_V5($parser) {
	$parser->echo_save($parser->packet_desc . "PacketLength=".$parser->word() . "\n");
	$Items = ($parser->packet_length - $parser->packet_pointer) / 24;
	for ($i = 0; $i < $Items; $i++) {
		$parser->echo_save($parser->nl . "index=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "ITID=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "type=".$parser->byte() . "\n");
		$parser->echo_save($parser->nl . "count=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "WearState=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "card1=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "card2=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "card3=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "card4=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "HireExpireDate=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "Flag=".$parser->byte() . "\n");
	}
}

// packet 0x994
function PACKET_ZC_CART_ITEMLIST_EQUIP_V5($parser) {
	$parser->echo_save($parser->packet_desc . "PacketLength=".$parser->word() . "\n");
	$Items = ($parser->packet_length - $parser->packet_pointer) / 31;
	for ($i = 0; $i < $Items; $i++) {
		$parser->echo_save($parser->nl . "index=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "ITID=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "type=".$parser->byte() . "\n");
		$parser->echo_save($parser->nl . "location=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "WearState=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "RefiningLevel=".$parser->byte() . "\n");
		$parser->echo_save($parser->nl . "card1=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "card2=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "card3=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "card4=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "HireExpireDate=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "bindOnEquipType=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "wItemSpriteNumber=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "Flag=".$parser->byte() . "\n");
	}
}

// packet 0x995
function PACKET_ZC_STORE_ITEMLIST_NORMAL_V5($parser) {
	$parser->echo_save($parser->packet_desc . "PacketLength=".$parser->word() . "\n");
	$Items = ($parser->packet_length - $parser->packet_pointer) / 24;
	for ($i = 0; $i < $Items; $i++) {
		$parser->echo_save($parser->nl . "index=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "ITID=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "type=".$parser->byte() . "\n");
		$parser->echo_save($parser->nl . "count=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "WearState=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "card1=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "card2=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "card3=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "card4=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "HireExpireDate=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "Flag=".$parser->byte() . "\n");
	}
}

// packet 0x996
function PACKET_ZC_STORE_ITEMLIST_EQUIP_V5($parser) {
	$parser->echo_save($parser->packet_desc . "PacketLength=".$parser->word() . "\n");
	$Items = ($parser->packet_length - $parser->packet_pointer) / 27;
	for ($i = 0; $i < $Items; $i++) {
		$parser->echo_save($parser->nl . "index=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "ITID=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "type=".$parser->byte() . "\n");
		$parser->echo_save($parser->nl . "location=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "WearState=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "RefiningLevel=".$parser->byte() . "\n");
		$parser->echo_save($parser->nl . "card1=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "card2=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "card3=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "card4=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "HireExpireDate=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "bindOnEquipType=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "wItemSpriteNumber=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "Flag=".$parser->byte() . "\n");
	}
}

// packet 0x997
function PACKET_ZC_EQUIPWIN_MICROSCOPE_V5($parser) {
	$parser->echo_save($parser->packet_desc . "Length=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "characterName=".$parser->string(24) . "\n");
	$parser->echo_save($parser->nl . "job=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "head=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "accessory=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "accessory2=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "accessory3=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "robe=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "headpalette=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "bodypalette=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "sex=".$parser->byte() . "\n");
}

// packet 0x998
function PACKET_CZ_REQ_WEAR_EQUIP_V5($parser) {
	$parser->echo_save($parser->packet_desc . "index=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "wearLocation=".$parser->long() . "\n");
}

// packet 0x999
function PACKET_ZC_ACK_WEAR_EQUIP_V5($parser) {
	$parser->echo_save($parser->packet_desc . "index=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "wearLocation=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "wItemSpriteNumber=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "result=".$parser->byte() . "\n");
}

// packet 0x99a
function PACKET_ZC_ACK_TAKEOFF_EQUIP_V5($parser) {
	$parser->echo_save($parser->packet_desc . "index=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "wearLocation=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "result=".$parser->byte() . "\n");
}

// packet 0x99b
function PACKET_ZC_MAPPROPERTY_R2($parser) {
	$parser->echo_save($parser->packet_desc . "type=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "NotifyPropertyBits=".$parser->long() . "\n");
}

// packet 0x99c
function PACKET_CH_REQ_CHARINFO_PER_PAGE($parser) {
	$parser->echo_save($parser->packet_desc . "SeqNum=".$parser->long() . "\n");
}

// packet 0x99d
function PACKET_HC_ACK_CHARINFO_PER_PAGE($parser) {
	$parser->echo_save($parser->packet_desc . "PacketLength=".$parser->word() . "\n");
	$charInfo = ($parser->packet_length - $parser->packet_pointer) / 144;
	for ($i = 0; $i < $charInfo; $i++) {
		$parser->echo_save($parser->nl . "GID=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "exp=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "money=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "jobexp=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "joblevel=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "bodystate=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "healthstate=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "effectstate=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "virtue=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "honor=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "jobpoint=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "hp=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "maxhp=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "sp=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "maxsp=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "speed=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "job=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "head=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "weapon=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "level=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "sppoint=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "accessory=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "shield=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "accessory2=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "accessory3=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "headpalette=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "bodypalette=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "name=".$parser->string(24) . "\n");
		$parser->echo_save($parser->nl . "Str=".$parser->byte() . "\n");
		$parser->echo_save($parser->nl . "Agi=".$parser->byte() . "\n");
		$parser->echo_save($parser->nl . "Vit=".$parser->byte() . "\n");
		$parser->echo_save($parser->nl . "Int=".$parser->byte() . "\n");
		$parser->echo_save($parser->nl . "Dex=".$parser->byte() . "\n");
		$parser->echo_save($parser->nl . "Luk=".$parser->byte() . "\n");
		$parser->echo_save($parser->nl . "CharNum=".$parser->byte() . "\n");
		$parser->echo_save($parser->nl . "haircolor=".$parser->byte() . "\n");
		$parser->echo_save($parser->nl . "bIsChangedCharName=".$parser->word() . "\n");
		$parser->echo_save($parser->nl . "lastMap=".$parser->string(16) . "\n");
		$parser->echo_save($parser->nl . "DeleteDate=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "Robe=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "SlotAddon=".$parser->long() . "\n");
		$parser->echo_save($parser->nl . "RenameAddon=".$parser->long() . "\n");
	}
}

// packet 0x99e
function PACKET_HC_QUEUE_ORDER($parser) {
	$parser->echo_save($parser->packet_desc . "PacketLength=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "m_AID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "m_QueueOrder=".$parser->long() . "\n");
}

// packet 0x99f
function PACKET_ZC_SKILL_ENTRY4($parser) {
	$parser->echo_save($parser->packet_desc . "PacketLength=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "AID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "creatorAID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "xPos=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "yPos=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "job=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "RadiusRange=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "isVisible=".$parser->byte() . "\n");
}

// packet 0x9a0
function PACKET_HC_CHARLIST_NOTIFY($parser) {
	$parser->echo_save($parser->packet_desc . "TotalCnt=".$parser->long() . "\n");
}

// packet 0x9a1
function PACKET_CH_CHARLIST_REQ($parser) {
	$parser->echo_save($parser->packet_desc . "\n");
}

// packet 0x9a2
function PACKET_AC_REQ_MOBILE_OTP($parser) {
	$parser->echo_save($parser->packet_desc . "AID=".$parser->long() . "\n");
}

// packet 0x9a4
function PACKET_ZC_DISPATCH_TIMING_INFO_CHN($parser) {
	$parser->echo_save($parser->packet_desc . "AID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "Balance=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "Effective_dTime=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "Reason=".$parser->long() . "\n");
}

// packet 0x9a5
function PACKET_AC_REFUSE_LOGIN3($parser) {
	$parser->echo_save($parser->packet_desc . "ErrorCode=".$parser->byte() . "\n");
	$parser->echo_save($parser->nl . "BlockedReaminSEC=".$parser->long() . "\n");
}

// packet 0x9a6
function PACKET_ZC_BANKING_CHECK($parser) {
	$parser->echo_save($parser->packet_desc . "Money=".$parser->int64() . "\n");
	$parser->echo_save($parser->nl . "Reason=".$parser->word() . "\n");
}

// packet 0x9a7
function PACKET_CZ_REQ_BANKING_DEPOSIT($parser) {
	$parser->echo_save($parser->packet_desc . "AID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "Money=".$parser->long() . "\n");
}

// packet 0x9a8
function PACKET_ZC_ACK_BANKING_DEPOSIT($parser) {
	$parser->echo_save($parser->packet_desc . "Reason=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "Money=".$parser->int64() . "\n");
}

// packet 0x9a9
function PACKET_CZ_REQ_BANKING_WITHDRAW($parser) {
	$parser->echo_save($parser->packet_desc . "AID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "Money=".$parser->long() . "\n");
}

// packet 0x9aa
function PACKET_ZC_ACK_BANKING_WITHDRAW($parser) {
	$parser->echo_save($parser->packet_desc . "Reason=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "Money=".$parser->int64() . "\n");
}

// packet 0x9ab
function PACKET_CZ_REQ_BANKING_CHECK($parser) {
	$parser->echo_save($parser->packet_desc . "AID=".$parser->long() . "\n");
}

// packet 0x9ac
function PACKET_CZ_REQ_CASH_BARGAIN_SALE_ITEM_INFO($parser) {
	$parser->echo_save($parser->packet_desc . "PacketLength=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "AID=".$parser->long() . "\n");
}

// packet 0x9ad
function PACKET_ZC_ACK_CASH_BARGAIN_SALE_ITEM_INFO($parser) {
	$parser->echo_save($parser->packet_desc . "Result=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "ItemID=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "Price=".$parser->long() . "\n");
}

// packet 0x9ae
function PACKET_CZ_REQ_APPLY_BARGAIN_SALE_ITEM($parser) {
	$parser->echo_save($parser->packet_desc . "AID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "ItemID=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "Count=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "StartDate=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "SellingTime=".$parser->byte() . "\n");
}

// packet 0x9af
function PACKET_ZC_ACK_APPLY_BARGAIN_SALE_ITEM($parser) {
	$parser->echo_save($parser->packet_desc . "Result=".$parser->word() . "\n");
}

// packet 0x9b0
function PACKET_CZ_REQ_REMOVE_BARGAIN_SALE_ITEM($parser) {
	$parser->echo_save($parser->packet_desc . "AID=".$parser->long() . "\n");
	$parser->echo_save($parser->nl . "ItemID=".$parser->word() . "\n");
}

// packet 0x9b1
function PACKET_ZC_ACK_REMOVE_BARGAIN_SALE_ITEM($parser) {
	$parser->echo_save($parser->packet_desc . "Result=".$parser->word() . "\n");
}

// packet 0x9b2
function PACKET_ZC_NOTIFY_BARGAIN_SALE_SELLING($parser) {
	$parser->echo_save($parser->packet_desc . "ItemID=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "TabCode=".$parser->word() . "\n");
}

// packet 0x9b3
function PACKET_ZC_NOTIFY_BARGAIN_SALE_CLOSE($parser) {
	$parser->echo_save($parser->packet_desc . "ItemID=".$parser->word() . "\n");
	$parser->echo_save($parser->nl . "TabCode=".$parser->word() . "\n");
}

// packet 0x9b4
function PACKET_CZ_OPEN_BARGAIN_SALE_TOOL($parser) {
	$parser->echo_save($parser->packet_desc . "AID=".$parser->long() . "\n");
}

// packet 0x9b5
function PACKET_ZC_OPEN_BARGAIN_SALE_TOOL($parser) {
	$parser->echo_save($parser->packet_desc . "\n");
}
?>
