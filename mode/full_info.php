<?php

// packet_parser functions
function PP_MODE_INIT($parser) {
	$parser->mode["mode_name"] = "full_info";	//
	$parser->mode["extra_bytes"] = true;		// warning about extra packet data
	$parser->mode["debug"] = true;				// write packets to file
	$parser->nl = "|     |     |      |                                                    |";
	$parser->br = "|.....|.....|......|....................................................|...............................\n";
	if($parser->mode["debug"]) {
		$debugfilename = "debug/".date("Ymd-gis").".txt";
		$parser->debug = fopen($debugfilename, "w");
	}
}

function PP_FUNC_NOT_DEFINED($parser) {
	echo $parser->packet_desc . "\n";
}

function PP_AEGIS_GID($parser) {
	echo "| $parser->packet_num |  $parser->packet_dir  |     | Account_ID\n";
}

function PP_PACKET_SPLIT($parser) {
	echo "| $parser->packet_num |  $parser->packet_dir  | $parser->packet_id | Packet Not Complete                                |\n";
}

function PP_LINE_BREAK($parser) {
	echo $parser->br;
}

function PP_ENTRY_TEXT($parser) {
	echo "T-----T-----T------T----------------------------------------------------T----------------------------------------------T\n";
	echo "| Num | Way |  ID  | Packet description                                 | Extra information                            \n";
	echo "I-----I-----I------I----------------------------------------------------I----------------------------------------------I\n";
}

// packet 0x64
function PACKET_CA_LOGIN($parser) {
	echo "$parser->packet_desc Version=".$parser->long()."\n";
	echo "$parser->nl ID=".$parser->string(24)."\n";
	echo "$parser->nl Passwd=".$parser->string(24)."\n";
	echo "$parser->nl clienttype=".$parser->byte()."\n";
}

// packet 0x65
function PACKET_CH_ENTER($parser) {
	echo "$parser->packet_desc AID=".$parser->long()."\n";
	echo "$parser->nl AuthCode=".$parser->long()."\n";
	echo "$parser->nl userLevel=".$parser->long()."\n";
	echo "$parser->nl clientType=".$parser->word()."\n";
	echo "$parser->nl Sex=".$parser->byte()."\n";
}

// packet 0x66
function PACKET_CH_SELECT_CHAR($parser) {
	echo "$parser->packet_desc CharNum=".$parser->byte()."\n";
}

// packet 0x67
function PACKET_CH_MAKE_CHAR($parser) {
	echo "$parser->packet_desc name=".$parser->string(24)."\n";
	echo "$parser->nl Str=".$parser->byte()."\n";
	echo "$parser->nl Agi=".$parser->byte()."\n";
	echo "$parser->nl Vit=".$parser->byte()."\n";
	echo "$parser->nl Int=".$parser->byte()."\n";
	echo "$parser->nl Dex=".$parser->byte()."\n";
	echo "$parser->nl Luk=".$parser->byte()."\n";
	echo "$parser->nl CharNum=".$parser->byte()."\n";
	echo "$parser->nl headPal=".$parser->word()."\n";
	echo "$parser->nl head=".$parser->word()."\n";
}

// packet 0x68
function PACKET_CH_DELETE_CHAR($parser) {
	echo "$parser->packet_desc GID=".$parser->long()."\n";
	echo "$parser->nl key=".$parser->string(40)."\n";
}

// packet 0x69
function PACKET_AC_ACCEPT_LOGIN($parser) {
	echo "$parser->packet_desc PacketLength=".$parser->word()."\n";
	echo "$parser->nl AuthCode=".$parser->long()."\n";
	echo "$parser->nl AID=".$parser->long()."\n";
	echo "$parser->nl userLevel=".$parser->long()."\n";
	echo "$parser->nl lastLoginIP=".$parser->ip()."\n";
	echo "$parser->nl lastLoginTime=".$parser->string(26)."\n";
	echo "$parser->nl Sex=".$parser->byte()."\n";
	$ServerList = ($parser->packet_length - $parser->packet_pointer) / 32;
	for ($i = 0; $i < $ServerList; $i++) {
		echo "$parser->nl ip=".$parser->ip()."\n";
		echo "$parser->nl port=".$parser->word()."\n";
		echo "$parser->nl name=".$parser->string(20)."\n";
		echo "$parser->nl usercount=".$parser->word()."\n";
		echo "$parser->nl state=".$parser->word()."\n";
		echo "$parser->nl property=".$parser->word()."\n";
	}
}

// packet 0x6a
function PACKET_AC_REFUSE_LOGIN($parser) {
	echo "$parser->packet_desc ErrorCode=".$parser->byte()."\n";
	echo "$parser->nl blockDate=".$parser->string(20)."\n";
}

// packet 0x6b
function PACKET_HC_ACCEPT_ENTER_NEO_UNION($parser) {
	echo "$parser->packet_desc PacketLength=".$parser->word()."\n";
	echo "$parser->nl TotalSlotNum=".$parser->byte()."\n";
	echo "$parser->nl PremiumStartSlot=".$parser->byte()."\n";
	echo "$parser->nl PremiumEndSlot=".$parser->byte()."\n";
	echo "$parser->nl dummy1_beginbilling=".$parser->byte()."\n";
	echo "$parser->nl code=".$parser->long()."\n";
	echo "$parser->nl time1=".$parser->long()."\n";
	echo "$parser->nl time2=".$parser->long()."\n";
	echo "$parser->nl dummy2_endbilling=".$parser->string(7)."\n";
	$charInfo = ($parser->packet_length - $parser->packet_pointer) / 144;
	for ($i = 0; $i < $charInfo; $i++) {
		echo "$parser->nl GID=".$parser->long()."\n";
		echo "$parser->nl exp=".$parser->long()."\n";
		echo "$parser->nl money=".$parser->long()."\n";
		echo "$parser->nl jobexp=".$parser->long()."\n";
		echo "$parser->nl joblevel=".$parser->long()."\n";
		echo "$parser->nl bodystate=".$parser->long()."\n";
		echo "$parser->nl healthstate=".$parser->long()."\n";
		echo "$parser->nl effectstate=".$parser->long()."\n";
		echo "$parser->nl virtue=".$parser->long()."\n";
		echo "$parser->nl honor=".$parser->long()."\n";
		echo "$parser->nl jobpoint=".$parser->word()."\n";
		echo "$parser->nl hp=".$parser->long()."\n";
		echo "$parser->nl maxhp=".$parser->long()."\n";
		echo "$parser->nl sp=".$parser->word()."\n";
		echo "$parser->nl maxsp=".$parser->word()."\n";
		echo "$parser->nl speed=".$parser->word()."\n";
		echo "$parser->nl job=".$parser->word()."\n";
		echo "$parser->nl head=".$parser->word()."\n";
		echo "$parser->nl weapon=".$parser->word()."\n";
		echo "$parser->nl level=".$parser->word()."\n";
		echo "$parser->nl sppoint=".$parser->word()."\n";
		echo "$parser->nl accessory=".$parser->word()."\n";
		echo "$parser->nl shield=".$parser->word()."\n";
		echo "$parser->nl accessory2=".$parser->word()."\n";
		echo "$parser->nl accessory3=".$parser->word()."\n";
		echo "$parser->nl headpalette=".$parser->word()."\n";
		echo "$parser->nl bodypalette=".$parser->word()."\n";
		echo "$parser->nl name=".$parser->string(24)."\n";
		echo "$parser->nl Str=".$parser->byte()."\n";
		echo "$parser->nl Agi=".$parser->byte()."\n";
		echo "$parser->nl Vit=".$parser->byte()."\n";
		echo "$parser->nl Int=".$parser->byte()."\n";
		echo "$parser->nl Dex=".$parser->byte()."\n";
		echo "$parser->nl Luk=".$parser->byte()."\n";
		echo "$parser->nl CharNum=".$parser->byte()."\n";
		echo "$parser->nl haircolor=".$parser->byte()."\n";
		echo "$parser->nl bIsChangedCharName=".$parser->word()."\n";
		echo "$parser->nl lastMap=".$parser->string(16)."\n";
		echo "$parser->nl DeleteDate=".$parser->long()."\n";
		echo "$parser->nl Robe=".$parser->long()."\n";
		echo "$parser->nl SlotAddon=".$parser->long()."\n";
		echo "$parser->nl RenameAddon=".$parser->long()."\n";
	}
}

// packet 0x6c
function PACKET_HC_REFUSE_ENTER($parser) {
	echo "$parser->packet_desc ErrorCode=".$parser->byte()."\n";
}

// packet 0x6d
function PACKET_HC_ACCEPT_MAKECHAR_NEO_UNION($parser) {
	echo "$parser->packet_desc ";
		echo "$parser->nl GID=".$parser->long()."\n";
		echo "$parser->nl exp=".$parser->long()."\n";
		echo "$parser->nl money=".$parser->long()."\n";
		echo "$parser->nl jobexp=".$parser->long()."\n";
		echo "$parser->nl joblevel=".$parser->long()."\n";
		echo "$parser->nl bodystate=".$parser->long()."\n";
		echo "$parser->nl healthstate=".$parser->long()."\n";
		echo "$parser->nl effectstate=".$parser->long()."\n";
		echo "$parser->nl virtue=".$parser->long()."\n";
		echo "$parser->nl honor=".$parser->long()."\n";
		echo "$parser->nl jobpoint=".$parser->word()."\n";
		echo "$parser->nl hp=".$parser->long()."\n";
		echo "$parser->nl maxhp=".$parser->long()."\n";
		echo "$parser->nl sp=".$parser->word()."\n";
		echo "$parser->nl maxsp=".$parser->word()."\n";
		echo "$parser->nl speed=".$parser->word()."\n";
		echo "$parser->nl job=".$parser->word()."\n";
		echo "$parser->nl head=".$parser->word()."\n";
		echo "$parser->nl weapon=".$parser->word()."\n";
		echo "$parser->nl level=".$parser->word()."\n";
		echo "$parser->nl sppoint=".$parser->word()."\n";
		echo "$parser->nl accessory=".$parser->word()."\n";
		echo "$parser->nl shield=".$parser->word()."\n";
		echo "$parser->nl accessory2=".$parser->word()."\n";
		echo "$parser->nl accessory3=".$parser->word()."\n";
		echo "$parser->nl headpalette=".$parser->word()."\n";
		echo "$parser->nl bodypalette=".$parser->word()."\n";
		echo "$parser->nl name=".$parser->string(24)."\n";
		echo "$parser->nl Str=".$parser->byte()."\n";
		echo "$parser->nl Agi=".$parser->byte()."\n";
		echo "$parser->nl Vit=".$parser->byte()."\n";
		echo "$parser->nl Int=".$parser->byte()."\n";
		echo "$parser->nl Dex=".$parser->byte()."\n";
		echo "$parser->nl Luk=".$parser->byte()."\n";
		echo "$parser->nl CharNum=".$parser->byte()."\n";
		echo "$parser->nl haircolor=".$parser->byte()."\n";
		echo "$parser->nl bIsChangedCharName=".$parser->word()."\n";
}

// packet 0x6e
function PACKET_HC_REFUSE_MAKECHAR($parser) {
	echo "$parser->packet_desc ErrorCode=".$parser->byte()."\n";
}

// packet 0x6f
function PACKET_HC_ACCEPT_DELETECHAR($parser) {
	echo "$parser->packet_desc \n";
}

// packet 0x70
function PACKET_HC_REFUSE_DELETECHAR($parser) {
	echo "$parser->packet_desc ErrorCode=".$parser->byte()."\n";
}

// packet 0x71
function PACKET_HC_NOTIFY_ZONESVR($parser) {
	echo "$parser->packet_desc GID=".$parser->long()."\n";
	echo "$parser->nl mapName=".$parser->string(16)."\n";
		echo "$parser->nl ip=".$parser->ip()."\n";
		echo "$parser->nl port=".$parser->word()."\n";
}

// packet 0x72
function PACKET_CZ_ENTER($parser) {
	echo "$parser->packet_desc AID=".$parser->long()."\n";
	echo "$parser->nl GID=".$parser->long()."\n";
	echo "$parser->nl AuthCode=".$parser->long()."\n";
	echo "$parser->nl clientTime=".$parser->long()."\n";
	echo "$parser->nl Sex=".$parser->byte()."\n";
}

// packet 0x73
function PACKET_ZC_ACCEPT_ENTER($parser) {
	echo "$parser->packet_desc startTime=".$parser->long()."\n";
	echo "$parser->nl PosDir=".$parser->xy()."\n";
	echo "$parser->nl xSize=".$parser->byte()."\n";
	echo "$parser->nl ySize=".$parser->byte()."\n";
}

// packet 0x74
function PACKET_ZC_REFUSE_ENTER($parser) {
	echo "$parser->packet_desc ErrorCode=".$parser->byte()."\n";
}

// packet 0x75
function PACKET_ZC_NOTIFY_INITCHAR($parser) {
	echo "$parser->packet_desc PacketLength=".$parser->word()."\n";
	echo "$parser->nl GID=".$parser->long()."\n";
	echo "$parser->nl Style=".$parser->word()."\n";
	echo "$parser->nl Item=".$parser->byte()."\n";
}

// packet 0x76
function PACKET_ZC_NOTIFY_UPDATECHAR($parser) {
	echo "$parser->packet_desc GID=".$parser->long()."\n";
	echo "$parser->nl Style=".$parser->word()."\n";
	echo "$parser->nl Item=".$parser->byte()."\n";
}

// packet 0x77
function PACKET_ZC_NOTIFY_UPDATEPLAYER($parser) {
	echo "$parser->packet_desc Style=".$parser->word()."\n";
	echo "$parser->nl Item=".$parser->byte()."\n";
}

// packet 0x78
function PACKET_ZC_NOTIFY_STANDENTRY($parser) {
	echo "$parser->packet_desc objecttype=".$parser->byte()."\n";
	echo "$parser->nl GID=".$parser->long()."\n";
	echo "$parser->nl speed=".$parser->word()."\n";
	echo "$parser->nl bodyState=".$parser->word()."\n";
	echo "$parser->nl healthState=".$parser->word()."\n";
	echo "$parser->nl effectState=".$parser->word()."\n";
	echo "$parser->nl job=".$parser->word()."\n";
	echo "$parser->nl head=".$parser->word()."\n";
	echo "$parser->nl weapon=".$parser->word()."\n";
	echo "$parser->nl accessory=".$parser->word()."\n";
	echo "$parser->nl shield=".$parser->word()."\n";
	echo "$parser->nl accessory2=".$parser->word()."\n";
	echo "$parser->nl accessory3=".$parser->word()."\n";
	echo "$parser->nl headpalette=".$parser->word()."\n";
	echo "$parser->nl bodypalette=".$parser->word()."\n";
	echo "$parser->nl headDir=".$parser->word()."\n";
	echo "$parser->nl GUID=".$parser->long()."\n";
	echo "$parser->nl GEmblemVer=".$parser->word()."\n";
	echo "$parser->nl honor=".$parser->word()."\n";
	echo "$parser->nl virtue=".$parser->word()."\n";
	echo "$parser->nl isPKModeON=".$parser->byte()."\n";
	echo "$parser->nl sex=".$parser->byte()."\n";
	echo "$parser->nl PosDir=".$parser->xy()."\n";
	echo "$parser->nl xSize=".$parser->byte()."\n";
	echo "$parser->nl ySize=".$parser->byte()."\n";
	echo "$parser->nl state=".$parser->byte()."\n";
	echo "$parser->nl clevel=".$parser->word()."\n";
}

// packet 0x79
function PACKET_ZC_NOTIFY_NEWENTRY($parser) {
	echo "$parser->packet_desc GID=".$parser->long()."\n";
	echo "$parser->nl speed=".$parser->word()."\n";
	echo "$parser->nl bodyState=".$parser->word()."\n";
	echo "$parser->nl healthState=".$parser->word()."\n";
	echo "$parser->nl effectState=".$parser->word()."\n";
	echo "$parser->nl job=".$parser->word()."\n";
	echo "$parser->nl head=".$parser->word()."\n";
	echo "$parser->nl weapon=".$parser->word()."\n";
	echo "$parser->nl accessory=".$parser->word()."\n";
	echo "$parser->nl shield=".$parser->word()."\n";
	echo "$parser->nl accessory2=".$parser->word()."\n";
	echo "$parser->nl accessory3=".$parser->word()."\n";
	echo "$parser->nl headpalette=".$parser->word()."\n";
	echo "$parser->nl bodypalette=".$parser->word()."\n";
	echo "$parser->nl headDir=".$parser->word()."\n";
	echo "$parser->nl GUID=".$parser->long()."\n";
	echo "$parser->nl GEmblemVer=".$parser->word()."\n";
	echo "$parser->nl honor=".$parser->word()."\n";
	echo "$parser->nl virtue=".$parser->word()."\n";
	echo "$parser->nl isPKModeON=".$parser->byte()."\n";
	echo "$parser->nl sex=".$parser->byte()."\n";
	echo "$parser->nl PosDir=".$parser->xy()."\n";
	echo "$parser->nl xSize=".$parser->byte()."\n";
	echo "$parser->nl ySize=".$parser->byte()."\n";
	echo "$parser->nl clevel=".$parser->word()."\n";
}

// packet 0x7a
function PACKET_ZC_NOTIFY_ACTENTRY($parser) {
	echo "$parser->packet_desc GID=".$parser->long()."\n";
	echo "$parser->nl speed=".$parser->word()."\n";
	echo "$parser->nl bodyState=".$parser->word()."\n";
	echo "$parser->nl healthState=".$parser->word()."\n";
	echo "$parser->nl effectState=".$parser->word()."\n";
	echo "$parser->nl job=".$parser->word()."\n";
	echo "$parser->nl head=".$parser->word()."\n";
	echo "$parser->nl weapon=".$parser->word()."\n";
	echo "$parser->nl accessory=".$parser->word()."\n";
	echo "$parser->nl shield=".$parser->word()."\n";
	echo "$parser->nl accessory2=".$parser->word()."\n";
	echo "$parser->nl accessory3=".$parser->word()."\n";
	echo "$parser->nl headpalette=".$parser->word()."\n";
	echo "$parser->nl bodypalette=".$parser->word()."\n";
	echo "$parser->nl headDir=".$parser->word()."\n";
	echo "$parser->nl GUID=".$parser->long()."\n";
	echo "$parser->nl GEmblemVer=".$parser->word()."\n";
	echo "$parser->nl honor=".$parser->word()."\n";
	echo "$parser->nl virtue=".$parser->word()."\n";
	echo "$parser->nl isPKModeON=".$parser->byte()."\n";
	echo "$parser->nl sex=".$parser->byte()."\n";
	echo "$parser->nl PosDir=".$parser->xy()."\n";
	echo "$parser->nl xSize=".$parser->byte()."\n";
	echo "$parser->nl ySize=".$parser->byte()."\n";
	echo "$parser->nl action=".$parser->byte()."\n";
	echo "$parser->nl actStartTime=".$parser->long()."\n";
	echo "$parser->nl clevel=".$parser->word()."\n";
}

// packet 0x7b
function PACKET_ZC_NOTIFY_MOVEENTRY($parser) {
	echo "$parser->packet_desc GID=".$parser->long()."\n";
	echo "$parser->nl speed=".$parser->word()."\n";
	echo "$parser->nl bodyState=".$parser->word()."\n";
	echo "$parser->nl healthState=".$parser->word()."\n";
	echo "$parser->nl effectState=".$parser->word()."\n";
	echo "$parser->nl job=".$parser->word()."\n";
	echo "$parser->nl head=".$parser->word()."\n";
	echo "$parser->nl weapon=".$parser->word()."\n";
	echo "$parser->nl accessory=".$parser->word()."\n";
	echo "$parser->nl moveStartTime=".$parser->long()."\n";
	echo "$parser->nl shield=".$parser->word()."\n";
	echo "$parser->nl accessory2=".$parser->word()."\n";
	echo "$parser->nl accessory3=".$parser->word()."\n";
	echo "$parser->nl headpalette=".$parser->word()."\n";
	echo "$parser->nl bodypalette=".$parser->word()."\n";
	echo "$parser->nl headDir=".$parser->word()."\n";
	echo "$parser->nl GUID=".$parser->long()."\n";
	echo "$parser->nl GEmblemVer=".$parser->word()."\n";
	echo "$parser->nl honor=".$parser->word()."\n";
	echo "$parser->nl virtue=".$parser->word()."\n";
	echo "$parser->nl isPKModeON=".$parser->byte()."\n";
	echo "$parser->nl sex=".$parser->byte()."\n";
	echo "$parser->nl MoveData=".$parser->xyxy()."\n";
	echo "$parser->nl xSize=".$parser->byte()."\n";
	echo "$parser->nl ySize=".$parser->byte()."\n";
	echo "$parser->nl clevel=".$parser->word()."\n";
}

// packet 0x7c
function PACKET_ZC_NOTIFY_STANDENTRY_NPC($parser) {
	echo "$parser->packet_desc objecttype=".$parser->byte()."\n";
	echo "$parser->nl GID=".$parser->long()."\n";
	echo "$parser->nl speed=".$parser->word()."\n";
	echo "$parser->nl bodyState=".$parser->word()."\n";
	echo "$parser->nl healthState=".$parser->word()."\n";
	echo "$parser->nl effectState=".$parser->word()."\n";
	echo "$parser->nl head=".$parser->word()."\n";
	echo "$parser->nl weapon=".$parser->word()."\n";
	echo "$parser->nl accessory=".$parser->word()."\n";
	echo "$parser->nl job=".$parser->word()."\n";
	echo "$parser->nl shield=".$parser->word()."\n";
	echo "$parser->nl accessory2=".$parser->word()."\n";
	echo "$parser->nl accessory3=".$parser->word()."\n";
	echo "$parser->nl headpalette=".$parser->word()."\n";
	echo "$parser->nl bodypalette=".$parser->word()."\n";
	echo "$parser->nl headDir=".$parser->word()."\n";
	echo "$parser->nl isPKModeON=".$parser->byte()."\n";
	echo "$parser->nl sex=".$parser->byte()."\n";
	echo "$parser->nl PosDir=".$parser->xy()."\n";
	echo "$parser->nl xSize=".$parser->byte()."\n";
	echo "$parser->nl ySize=".$parser->byte()."\n";
}

// packet 0x7d
function PACKET_CZ_NOTIFY_ACTORINIT($parser) {
	echo "$parser->packet_desc \n";
}

// packet 0x7e
function PACKET_CZ_REQUEST_TIME($parser) {
	echo "$parser->packet_desc clientTime=".$parser->long()."\n";
}

// packet 0x7f
function PACKET_ZC_NOTIFY_TIME($parser) {
	echo "$parser->packet_desc time=".$parser->long()."\n";
}

// packet 0x80
function PACKET_ZC_NOTIFY_VANISH($parser) {
	echo "$parser->packet_desc GID=".$parser->long()."\n";
	echo "$parser->nl type=".$parser->byte()."\n";
}

// packet 0x81
function PACKET_SC_NOTIFY_BAN($parser) {
	echo "$parser->packet_desc ErrorCode=".$parser->byte()."\n";
}

// packet 0x82
function PACKET_CZ_REQUEST_QUIT($parser) {
	echo "$parser->packet_desc \n";
}

// packet 0x83
function PACKET_ZC_ACCEPT_QUIT($parser) {
	echo "$parser->packet_desc \n";
}

// packet 0x84
function PACKET_ZC_REFUSE_QUIT($parser) {
	echo "$parser->packet_desc \n";
}

// packet 0x85
function PACKET_CZ_REQUEST_MOVE($parser) {
	echo "$parser->packet_desc dest=".$parser->xy()."\n";
}

// packet 0x86
function PACKET_ZC_NOTIFY_MOVE($parser) {
	echo "$parser->packet_desc GID=".$parser->long()."\n";
	echo "$parser->nl MoveData=".$parser->xyxy()."\n";
	echo "$parser->nl moveStartTime=".$parser->long()."\n";
}

// packet 0x87
function PACKET_ZC_NOTIFY_PLAYERMOVE($parser) {
	echo "$parser->packet_desc moveStartTime=".$parser->long()."\n";
	echo "$parser->nl MoveData=".$parser->xyxy()."\n";
}

// packet 0x88
function PACKET_ZC_STOPMOVE($parser) {
	echo "$parser->packet_desc AID=".$parser->long()."\n";
	echo "$parser->nl xPos=".$parser->word()."\n";
	echo "$parser->nl yPos=".$parser->word()."\n";
}

// packet 0x89
function PACKET_CZ_REQUEST_ACT($parser) {
	echo "$parser->packet_desc targetGID=".$parser->long()."\n";
	echo "$parser->nl action=".$parser->byte()."\n";
}

// packet 0x8a
function PACKET_ZC_NOTIFY_ACT($parser) {
	echo "$parser->packet_desc GID=".$parser->long()."\n";
	echo "$parser->nl targetGID=".$parser->long()."\n";
	echo "$parser->nl startTime=".$parser->long()."\n";
	echo "$parser->nl attackMT=".$parser->long()."\n";
	echo "$parser->nl attackedMT=".$parser->long()."\n";
	echo "$parser->nl damage=".$parser->word()."\n";
	echo "$parser->nl count=".$parser->word()."\n";
	echo "$parser->nl action=".$parser->byte()."\n";
	echo "$parser->nl leftDamage=".$parser->word()."\n";
}

// packet 0x8b
function PACKET_ZC_NOTIFY_ACT_POSITION($parser) {
	echo "$parser->packet_desc GID=".$parser->long()."\n";
	echo "$parser->nl targetGID=".$parser->long()."\n";
	echo "$parser->nl startTime=".$parser->long()."\n";
	echo "$parser->nl xPos=".$parser->word()."\n";
	echo "$parser->nl yPos=".$parser->word()."\n";
	echo "$parser->nl damage=".$parser->word()."\n";
	echo "$parser->nl count=".$parser->word()."\n";
	echo "$parser->nl action=".$parser->byte()."\n";
}

// packet 0x8c
function PACKET_CZ_REQUEST_CHAT($parser) {
	echo "$parser->packet_desc PacketLength=".$parser->word()."\n";
	echo "$parser->nl msg=".$parser->string($parser->packet_length - $parser->packet_pointer)."\n";
}

// packet 0x8d
function PACKET_ZC_NOTIFY_CHAT($parser) {
	echo "$parser->packet_desc PacketLength=".$parser->word()."\n";
	echo "$parser->nl GID=".$parser->long()."\n";
	echo "$parser->nl msg=".$parser->string($parser->packet_length - $parser->packet_pointer)."\n";
}

// packet 0x8e
function PACKET_ZC_NOTIFY_PLAYERCHAT($parser) {
	echo "$parser->packet_desc PacketLength=".$parser->word()."\n";
	echo "$parser->nl msg=".$parser->string($parser->packet_length - $parser->packet_pointer)."\n";
}

// packet 0x8f
function PACKET_SERVER_ENTRY_ACK($parser) {
	echo "$parser->packet_desc Header=".$parser->word()."\n";
	echo "$parser->nl AID=".$parser->long()."\n";
}

// packet 0x90
function PACKET_CZ_CONTACTNPC($parser) {
	echo "$parser->packet_desc NAID=".$parser->long()."\n";
	echo "$parser->nl type=".$parser->byte()."\n";
}

// packet 0x91
function PACKET_ZC_NPCACK_MAPMOVE($parser) {
	echo "$parser->packet_desc mapName=".$parser->string(16)."\n";
	echo "$parser->nl xPos=".$parser->word()."\n";
	echo "$parser->nl yPos=".$parser->word()."\n";
}

// packet 0x92
function PACKET_ZC_NPCACK_SERVERMOVE($parser) {
	echo "$parser->packet_desc mapName=".$parser->string(16)."\n";
	echo "$parser->nl xPos=".$parser->word()."\n";
	echo "$parser->nl yPos=".$parser->word()."\n";
		echo "$parser->nl ip=".$parser->ip()."\n";
		echo "$parser->nl port=".$parser->word()."\n";
}

// packet 0x93
function PACKET_ZC_NPCACK_ENABLE($parser) {
	echo "$parser->packet_desc \n";
}

// packet 0x94
function PACKET_CZ_REQNAME($parser) {
	echo "$parser->packet_desc AID=".$parser->long()."\n";
}

// packet 0x95
function PACKET_ZC_ACK_REQNAME($parser) {
	echo "$parser->packet_desc AID=".$parser->long()."\n";
	echo "$parser->nl CName=".$parser->string(24)."\n";
}

// packet 0x96
function PACKET_CZ_WHISPER($parser) {
	echo "$parser->packet_desc PacketLength=".$parser->word()."\n";
	echo "$parser->nl receiver=".$parser->string(24)."\n";
	echo "$parser->nl msg=".$parser->string($parser->packet_length - $parser->packet_pointer)."\n";
}

// packet 0x97
function PACKET_ZC_WHISPER($parser) {
	echo "$parser->packet_desc PacketLength=".$parser->word()."\n";
	echo "$parser->nl sender=".$parser->string(24)."\n";
	echo "$parser->nl msg=".$parser->string($parser->packet_length - $parser->packet_pointer)."\n";
}

// packet 0x98
function PACKET_ZC_ACK_WHISPER($parser) {
	echo "$parser->packet_desc result=".$parser->byte()."\n";
}

// packet 0x99
function PACKET_CZ_BROADCAST($parser) {
	echo "$parser->packet_desc PacketLength=".$parser->word()."\n";
	echo "$parser->nl msg=".$parser->string($parser->packet_length - $parser->packet_pointer)."\n";
}

// packet 0x9a
function PACKET_ZC_BROADCAST($parser) {
	echo "$parser->packet_desc PacketLength=".$parser->word()."\n";
	echo "$parser->nl msg=".$parser->string($parser->packet_length - $parser->packet_pointer)."\n";
}

// packet 0x9b
function PACKET_CZ_CHANGE_DIRECTION($parser) {
	echo "$parser->packet_desc headDir=".$parser->word()."\n";
	echo "$parser->nl dir=".$parser->byte()."\n";
}

// packet 0x9c
function PACKET_ZC_CHANGE_DIRECTION($parser) {
	echo "$parser->packet_desc AID=".$parser->long()."\n";
	echo "$parser->nl headDir=".$parser->word()."\n";
	echo "$parser->nl dir=".$parser->byte()."\n";
}

// packet 0x9d
function PACKET_ZC_ITEM_ENTRY($parser) {
	echo "$parser->packet_desc ITAID=".$parser->long()."\n";
	echo "$parser->nl ITID=".$parser->word()."\n";
	echo "$parser->nl IsIdentified=".$parser->byte()."\n";
	echo "$parser->nl xPos=".$parser->word()."\n";
	echo "$parser->nl yPos=".$parser->word()."\n";
	echo "$parser->nl count=".$parser->word()."\n";
	echo "$parser->nl subX=".$parser->byte()."\n";
	echo "$parser->nl subY=".$parser->byte()."\n";
}

// packet 0x9e
function PACKET_ZC_ITEM_FALL_ENTRY($parser) {
	echo "$parser->packet_desc ITAID=".$parser->long()."\n";
	echo "$parser->nl ITID=".$parser->word()."\n";
	echo "$parser->nl IsIdentified=".$parser->byte()."\n";
	echo "$parser->nl xPos=".$parser->word()."\n";
	echo "$parser->nl yPos=".$parser->word()."\n";
	echo "$parser->nl subX=".$parser->byte()."\n";
	echo "$parser->nl subY=".$parser->byte()."\n";
	echo "$parser->nl count=".$parser->word()."\n";
}

// packet 0x9f
function PACKET_CZ_ITEM_PICKUP($parser) {
	echo "$parser->packet_desc ITAID=".$parser->long()."\n";
}

// packet 0xa0
function PACKET_ZC_ITEM_PICKUP_ACK($parser) {
	echo "$parser->packet_desc Index=".$parser->word()."\n";
	echo "$parser->nl count=".$parser->word()."\n";
	echo "$parser->nl ITID=".$parser->word()."\n";
	echo "$parser->nl IsIdentified=".$parser->byte()."\n";
	echo "$parser->nl IsDamaged=".$parser->byte()."\n";
	echo "$parser->nl refiningLevel=".$parser->byte()."\n";
		echo "$parser->nl card1=".$parser->word()."\n";
		echo "$parser->nl card2=".$parser->word()."\n";
		echo "$parser->nl card3=".$parser->word()."\n";
		echo "$parser->nl card4=".$parser->word()."\n";
	echo "$parser->nl location=".$parser->word()."\n";
	echo "$parser->nl type=".$parser->byte()."\n";
	echo "$parser->nl result=".$parser->byte()."\n";
}

// packet 0xa1
function PACKET_ZC_ITEM_DISAPPEAR($parser) {
	echo "$parser->packet_desc ITAID=".$parser->long()."\n";
}

// packet 0xa2
function PACKET_CZ_ITEM_THROW($parser) {
	echo "$parser->packet_desc Index=".$parser->word()."\n";
	echo "$parser->nl count=".$parser->word()."\n";
}

// packet 0xa3
function PACKET_ZC_NORMAL_ITEMLIST($parser) {
	echo "$parser->packet_desc PacketLength=".$parser->word()."\n";
	$itemInfo = ($parser->packet_length - $parser->packet_pointer) / 10;
	for ($i = 0; $i < $itemInfo; $i++) {
		echo "$parser->nl index=".$parser->word()."\n";
		echo "$parser->nl ITID=".$parser->word()."\n";
		echo "$parser->nl type=".$parser->byte()."\n";
		echo "$parser->nl IsIdentified=".$parser->byte()."\n";
		echo "$parser->nl count=".$parser->word()."\n";
		echo "$parser->nl WearState=".$parser->word()."\n";
	}
}

// packet 0xa4
function PACKET_ZC_EQUIPMENT_ITEMLIST($parser) {
	echo "$parser->packet_desc PacketLength=".$parser->word()."\n";
	$itemInfo = ($parser->packet_length - $parser->packet_pointer) / 20;
	for ($i = 0; $i < $itemInfo; $i++) {
		echo "$parser->nl index=".$parser->word()."\n";
		echo "$parser->nl ITID=".$parser->word()."\n";
		echo "$parser->nl type=".$parser->byte()."\n";
		echo "$parser->nl IsIdentified=".$parser->byte()."\n";
		echo "$parser->nl location=".$parser->word()."\n";
		echo "$parser->nl WearState=".$parser->word()."\n";
		echo "$parser->nl IsDamaged=".$parser->byte()."\n";
		echo "$parser->nl RefiningLevel=".$parser->byte()."\n";
		echo "$parser->nl card1=".$parser->word()."\n";
		echo "$parser->nl card2=".$parser->word()."\n";
		echo "$parser->nl card3=".$parser->word()."\n";
		echo "$parser->nl card4=".$parser->word()."\n";
	}
}

// packet 0xa5
function PACKET_ZC_STORE_NORMAL_ITEMLIST($parser) {
	echo "$parser->packet_desc PacketLength=".$parser->word()."\n";
	$itemInfo = ($parser->packet_length - $parser->packet_pointer) / 10;
	for ($i = 0; $i < $itemInfo; $i++) {
		echo "$parser->nl index=".$parser->word()."\n";
		echo "$parser->nl ITID=".$parser->word()."\n";
		echo "$parser->nl type=".$parser->byte()."\n";
		echo "$parser->nl IsIdentified=".$parser->byte()."\n";
		echo "$parser->nl count=".$parser->word()."\n";
		echo "$parser->nl WearState=".$parser->word()."\n";
	}
}

// packet 0xa6
function PACKET_ZC_STORE_EQUIPMENT_ITEMLIST($parser) {
	echo "$parser->packet_desc PacketLength=".$parser->word()."\n";
	$itemInfo = ($parser->packet_length - $parser->packet_pointer) / 20;
	for ($i = 0; $i < $itemInfo; $i++) {
		echo "$parser->nl index=".$parser->word()."\n";
		echo "$parser->nl ITID=".$parser->word()."\n";
		echo "$parser->nl type=".$parser->byte()."\n";
		echo "$parser->nl IsIdentified=".$parser->byte()."\n";
		echo "$parser->nl location=".$parser->word()."\n";
		echo "$parser->nl WearState=".$parser->word()."\n";
		echo "$parser->nl IsDamaged=".$parser->byte()."\n";
		echo "$parser->nl RefiningLevel=".$parser->byte()."\n";
		echo "$parser->nl card1=".$parser->word()."\n";
		echo "$parser->nl card2=".$parser->word()."\n";
		echo "$parser->nl card3=".$parser->word()."\n";
		echo "$parser->nl card4=".$parser->word()."\n";
	}
}

// packet 0xa7
function PACKET_CZ_USE_ITEM($parser) {
	echo "$parser->packet_desc index=".$parser->word()."\n";
	echo "$parser->nl AID=".$parser->long()."\n";
}

// packet 0xa8
function PACKET_ZC_USE_ITEM_ACK($parser) {
	echo "$parser->packet_desc index=".$parser->word()."\n";
	echo "$parser->nl count=".$parser->word()."\n";
	echo "$parser->nl result=".$parser->byte()."\n";
}

// packet 0xa9
function PACKET_CZ_REQ_WEAR_EQUIP($parser) {
	echo "$parser->packet_desc index=".$parser->word()."\n";
	echo "$parser->nl wearLocation=".$parser->word()."\n";
}

// packet 0xaa
function PACKET_ZC_REQ_WEAR_EQUIP_ACK($parser) {
	echo "$parser->packet_desc index=".$parser->word()."\n";
	echo "$parser->nl wearLocation=".$parser->word()."\n";
	echo "$parser->nl wItemSpriteNumber=".$parser->word()."\n";
	echo "$parser->nl result=".$parser->byte()."\n";
}

// packet 0xab
function PACKET_CZ_REQ_TAKEOFF_EQUIP($parser) {
	echo "$parser->packet_desc index=".$parser->word()."\n";
}

// packet 0xac
function PACKET_ZC_REQ_TAKEOFF_EQUIP_ACK($parser) {
	echo "$parser->packet_desc index=".$parser->word()."\n";
	echo "$parser->nl wearLocation=".$parser->word()."\n";
	echo "$parser->nl result=".$parser->byte()."\n";
}

// packet 0xaf
function PACKET_ZC_ITEM_THROW_ACK($parser) {
	echo "$parser->packet_desc Index=".$parser->word()."\n";
	echo "$parser->nl count=".$parser->word()."\n";
}

// packet 0xb0
function PACKET_ZC_PAR_CHANGE($parser) {
	echo "$parser->packet_desc varID=".$parser->word()."\n";
	echo "$parser->nl count=".$parser->long()."\n";
}

// packet 0xb1
function PACKET_ZC_LONGPAR_CHANGE($parser) {
	echo "$parser->packet_desc varID=".$parser->word()."\n";
	echo "$parser->nl amount=".$parser->long()."\n";
}

// packet 0xb2
function PACKET_CZ_RESTART($parser) {
	echo "$parser->packet_desc type=".$parser->byte()."\n";
}

// packet 0xb3
function PACKET_ZC_RESTART_ACK($parser) {
	echo "$parser->packet_desc type=".$parser->byte()."\n";
}

// packet 0xb4
function PACKET_ZC_SAY_DIALOG($parser) {
	echo "$parser->packet_desc PacketLength=".$parser->word()."\n";
	echo "$parser->nl NAID=".$parser->long()."\n";
	echo "$parser->nl msg=".$parser->string($parser->packet_length - $parser->packet_pointer)."\n";
}

// packet 0xb5
function PACKET_ZC_WAIT_DIALOG($parser) {
	echo "$parser->packet_desc NAID=".$parser->long()."\n";
}

// packet 0xb6
function PACKET_ZC_CLOSE_DIALOG($parser) {
	echo "$parser->packet_desc NAID=".$parser->long()."\n";
}

// packet 0xb7
function PACKET_ZC_MENU_LIST($parser) {
	echo "$parser->packet_desc PacketLength=".$parser->word()."\n";
	echo "$parser->nl NAID=".$parser->long()."\n";
	echo "$parser->nl msg=".$parser->string($parser->packet_length - $parser->packet_pointer)."\n";
}

// packet 0xb8
function PACKET_CZ_CHOOSE_MENU($parser) {
	echo "$parser->packet_desc NAID=".$parser->long()."\n";
	echo "$parser->nl num=".$parser->byte()."\n";
}

// packet 0xb9
function PACKET_CZ_REQ_NEXT_SCRIPT($parser) {
	echo "$parser->packet_desc NAID=".$parser->long()."\n";
}

// packet 0xba
function PACKET_CZ_REQ_STATUS($parser) {
	echo "$parser->packet_desc \n";
}

// packet 0xbb
function PACKET_CZ_STATUS_CHANGE($parser) {
	echo "$parser->packet_desc statusID=".$parser->word()."\n";
	echo "$parser->nl changeAmount=".$parser->byte()."\n";
}

// packet 0xbc
function PACKET_ZC_STATUS_CHANGE_ACK($parser) {
	echo "$parser->packet_desc statusID=".$parser->word()."\n";
	echo "$parser->nl result=".$parser->byte()."\n";
	echo "$parser->nl value=".$parser->byte()."\n";
}

// packet 0xbd
function PACKET_ZC_STATUS($parser) {
	echo "$parser->packet_desc point=".$parser->word()."\n";
	echo "$parser->nl str=".$parser->byte()."\n";
	echo "$parser->nl standardStr=".$parser->byte()."\n";
	echo "$parser->nl agi=".$parser->byte()."\n";
	echo "$parser->nl standardAgi=".$parser->byte()."\n";
	echo "$parser->nl vit=".$parser->byte()."\n";
	echo "$parser->nl standardVit=".$parser->byte()."\n";
	echo "$parser->nl Int=".$parser->byte()."\n";
	echo "$parser->nl standardInt=".$parser->byte()."\n";
	echo "$parser->nl dex=".$parser->byte()."\n";
	echo "$parser->nl standardDex=".$parser->byte()."\n";
	echo "$parser->nl luk=".$parser->byte()."\n";
	echo "$parser->nl standardLuk=".$parser->byte()."\n";
	echo "$parser->nl attPower=".$parser->word()."\n";
	echo "$parser->nl refiningPower=".$parser->word()."\n";
	echo "$parser->nl max_mattPower=".$parser->word()."\n";
	echo "$parser->nl min_mattPower=".$parser->word()."\n";
	echo "$parser->nl itemdefPower=".$parser->word()."\n";
	echo "$parser->nl plusdefPower=".$parser->word()."\n";
	echo "$parser->nl mdefPower=".$parser->word()."\n";
	echo "$parser->nl plusmdefPower=".$parser->word()."\n";
	echo "$parser->nl hitSuccessValue=".$parser->word()."\n";
	echo "$parser->nl avoidSuccessValue=".$parser->word()."\n";
	echo "$parser->nl plusAvoidSuccessValue=".$parser->word()."\n";
	echo "$parser->nl criticalSuccessValue=".$parser->word()."\n";
	echo "$parser->nl ASPD=".$parser->word()."\n";
	echo "$parser->nl plusASPD=".$parser->word()."\n";
}

// packet 0xbe
function PACKET_ZC_STATUS_CHANGE($parser) {
	echo "$parser->packet_desc statusID=".$parser->word()."\n";
	echo "$parser->nl value=".$parser->byte()."\n";
}

// packet 0xbf
function PACKET_CZ_REQ_EMOTION($parser) {
	echo "$parser->packet_desc type=".$parser->byte()."\n";
}

// packet 0xc0
function PACKET_ZC_EMOTION($parser) {
	echo "$parser->packet_desc GID=".$parser->long()."\n";
	echo "$parser->nl type=".$parser->byte()."\n";
}

// packet 0xc1
function PACKET_CZ_REQ_USER_COUNT($parser) {
	echo "$parser->packet_desc \n";
}

// packet 0xc2
function PACKET_ZC_USER_COUNT($parser) {
	echo "$parser->packet_desc count=".$parser->long()."\n";
}

// packet 0xc3
function PACKET_ZC_SPRITE_CHANGE($parser) {
	echo "$parser->packet_desc GID=".$parser->long()."\n";
	echo "$parser->nl type=".$parser->byte()."\n";
	echo "$parser->nl value=".$parser->byte()."\n";
}

// packet 0xc4
function PACKET_ZC_SELECT_DEALTYPE($parser) {
	echo "$parser->packet_desc NAID=".$parser->long()."\n";
}

// packet 0xc5
function PACKET_CZ_ACK_SELECT_DEALTYPE($parser) {
	echo "$parser->packet_desc NAID=".$parser->long()."\n";
	echo "$parser->nl type=".$parser->byte()."\n";
}

// packet 0xc6
function PACKET_ZC_PC_PURCHASE_ITEMLIST($parser) {
	echo "$parser->packet_desc PacketLength=".$parser->word()."\n";
	$itemList = ($parser->packet_length - $parser->packet_pointer) / 11;
	for ($i = 0; $i < $itemList; $i++) {
		echo "$parser->nl price=".$parser->long()."\n";
		echo "$parser->nl discountprice=".$parser->long()."\n";
		echo "$parser->nl type=".$parser->byte()."\n";
		echo "$parser->nl ITID=".$parser->word()."\n";
	}
}

// packet 0xc7
function PACKET_ZC_PC_SELL_ITEMLIST($parser) {
	echo "$parser->packet_desc PacketLength=".$parser->word()."\n";
	$itemList = ($parser->packet_length - $parser->packet_pointer) / 10;
	for ($i = 0; $i < $itemList; $i++) {
		echo "$parser->nl index=".$parser->word()."\n";
		echo "$parser->nl price=".$parser->long()."\n";
		echo "$parser->nl overchargeprice=".$parser->long()."\n";
	}
}

// packet 0xc8
function PACKET_CZ_PC_PURCHASE_ITEMLIST($parser) {
	echo "$parser->packet_desc PacketLength=".$parser->word()."\n";
	$itemList = ($parser->packet_length - $parser->packet_pointer) / 4;
	for ($i = 0; $i < $itemList; $i++) {
		echo "$parser->nl count=".$parser->word()."\n";
		echo "$parser->nl ITID=".$parser->word()."\n";
	}
}

// packet 0xc9
function PACKET_CZ_PC_SELL_ITEMLIST($parser) {
	echo "$parser->packet_desc PacketLength=".$parser->word()."\n";
	$itemList = ($parser->packet_length - $parser->packet_pointer) / 4;
	for ($i = 0; $i < $itemList; $i++) {
		echo "$parser->nl index=".$parser->word()."\n";
		echo "$parser->nl count=".$parser->word()."\n";
	}
}

// packet 0xca
function PACKET_ZC_PC_PURCHASE_RESULT($parser) {
	echo "$parser->packet_desc result=".$parser->byte()."\n";
}

// packet 0xcb
function PACKET_ZC_PC_SELL_RESULT($parser) {
	echo "$parser->packet_desc result=".$parser->byte()."\n";
}

// packet 0xcc
function PACKET_CZ_DISCONNECT_CHARACTER($parser) {
	echo "$parser->packet_desc AID=".$parser->long()."\n";
}

// packet 0xcd
function PACKET_ZC_ACK_DISCONNECT_CHARACTER($parser) {
	echo "$parser->packet_desc result=".$parser->byte()."\n";
}

// packet 0xce
function PACKET_CZ_DISCONNECT_ALL_CHARACTER($parser) {
	echo "$parser->packet_desc \n";
}

// packet 0xcf
function PACKET_CZ_SETTING_WHISPER_PC($parser) {
	echo "$parser->packet_desc name=".$parser->string(24)."\n";
	echo "$parser->nl type=".$parser->byte()."\n";
}

// packet 0xd0
function PACKET_CZ_SETTING_WHISPER_STATE($parser) {
	echo "$parser->packet_desc type=".$parser->byte()."\n";
}

// packet 0xd1
function PACKET_ZC_SETTING_WHISPER_PC($parser) {
	echo "$parser->packet_desc type=".$parser->byte()."\n";
	echo "$parser->nl result=".$parser->byte()."\n";
}

// packet 0xd2
function PACKET_ZC_SETTING_WHISPER_STATE($parser) {
	echo "$parser->packet_desc type=".$parser->byte()."\n";
	echo "$parser->nl result=".$parser->byte()."\n";
}

// packet 0xd3
function PACKET_CZ_REQ_WHISPER_LIST($parser) {
	echo "$parser->packet_desc \n";
}

// packet 0xd4
function PACKET_ZC_WHISPER_LIST($parser) {
	echo "$parser->packet_desc PacketLength=".$parser->word()."\n";
	$wisperList = ($parser->packet_length - $parser->packet_pointer) / 24;
	for ($i = 0; $i < $wisperList; $i++) {
		echo "$parser->nl name=".$parser->string(24)."\n";
	}
}

// packet 0xd5
function PACKET_CZ_CREATE_CHATROOM($parser) {
	echo "$parser->packet_desc PacketLength=".$parser->word()."\n";
	echo "$parser->nl size=".$parser->word()."\n";
	echo "$parser->nl type=".$parser->byte()."\n";
	echo "$parser->nl passwd=".$parser->string(8)."\n";
	echo "$parser->nl title=".$parser->string($parser->packet_length - $parser->packet_pointer)."\n";
}

// packet 0xd6
function PACKET_ZC_ACK_CREATE_CHATROOM($parser) {
	echo "$parser->packet_desc result=".$parser->byte()."\n";
}

// packet 0xd7
function PACKET_ZC_ROOM_NEWENTRY($parser) {
	echo "$parser->packet_desc PacketLength=".$parser->word()."\n";
	echo "$parser->nl AID=".$parser->long()."\n";
	echo "$parser->nl roomID=".$parser->long()."\n";
	echo "$parser->nl maxcount=".$parser->word()."\n";
	echo "$parser->nl curcount=".$parser->word()."\n";
	echo "$parser->nl type=".$parser->byte()."\n";
	echo "$parser->nl title=".$parser->string($parser->packet_length - $parser->packet_pointer)."\n";
}

// packet 0xd8
function PACKET_ZC_DESTROY_ROOM($parser) {
	echo "$parser->packet_desc roomID=".$parser->long()."\n";
}

// packet 0xd9
function PACKET_CZ_REQ_ENTER_ROOM($parser) {
	echo "$parser->packet_desc roomID=".$parser->long()."\n";
	echo "$parser->nl passwd=".$parser->string(8)."\n";
}

// packet 0xda
function PACKET_ZC_REFUSE_ENTER_ROOM($parser) {
	echo "$parser->packet_desc result=".$parser->byte()."\n";
}

// packet 0xdb
function PACKET_ZC_ENTER_ROOM($parser) {
	echo "$parser->packet_desc PacketLength=".$parser->word()."\n";
	echo "$parser->nl roomID=".$parser->long()."\n";
	$memberList = ($parser->packet_length - $parser->packet_pointer) / 28;
	for ($i = 0; $i < $memberList; $i++) {
		echo "$parser->nl role=".$parser->long()."\n";
		echo "$parser->nl name=".$parser->string(24)."\n";
	}
}

// packet 0xdc
function PACKET_ZC_MEMBER_NEWENTRY($parser) {
	echo "$parser->packet_desc curcount=".$parser->word()."\n";
	echo "$parser->nl name=".$parser->string(24)."\n";
}

// packet 0xdd
function PACKET_ZC_MEMBER_EXIT($parser) {
	echo "$parser->packet_desc curcount=".$parser->word()."\n";
	echo "$parser->nl name=".$parser->string(24)."\n";
	echo "$parser->nl type=".$parser->byte()."\n";
}

// packet 0xde
function PACKET_CZ_CHANGE_CHATROOM($parser) {
	echo "$parser->packet_desc PacketLength=".$parser->word()."\n";
	echo "$parser->nl size=".$parser->word()."\n";
	echo "$parser->nl type=".$parser->byte()."\n";
	echo "$parser->nl passwd=".$parser->string(8)."\n";
	echo "$parser->nl title=".$parser->string($parser->packet_length - $parser->packet_pointer)."\n";
}

// packet 0xdf
function PACKET_ZC_CHANGE_CHATROOM($parser) {
	echo "$parser->packet_desc PacketLength=".$parser->word()."\n";
	echo "$parser->nl AID=".$parser->long()."\n";
	echo "$parser->nl roomID=".$parser->long()."\n";
	echo "$parser->nl maxcount=".$parser->word()."\n";
	echo "$parser->nl curcount=".$parser->word()."\n";
	echo "$parser->nl type=".$parser->byte()."\n";
	echo "$parser->nl title=".$parser->string($parser->packet_length - $parser->packet_pointer)."\n";
}

// packet 0xe0
function PACKET_CZ_REQ_ROLE_CHANGE($parser) {
	echo "$parser->packet_desc role=".$parser->long()."\n";
	echo "$parser->nl name=".$parser->string(24)."\n";
}

// packet 0xe1
function PACKET_ZC_ROLE_CHANGE($parser) {
	echo "$parser->packet_desc role=".$parser->long()."\n";
	echo "$parser->nl name=".$parser->string(24)."\n";
}

// packet 0xe2
function PACKET_CZ_REQ_EXPEL_MEMBER($parser) {
	echo "$parser->packet_desc name=".$parser->string(24)."\n";
}

// packet 0xe3
function PACKET_CZ_EXIT_ROOM($parser) {
	echo "$parser->packet_desc \n";
}

// packet 0xe4
function PACKET_CZ_REQ_EXCHANGE_ITEM($parser) {
	echo "$parser->packet_desc AID=".$parser->long()."\n";
}

// packet 0xe5
function PACKET_ZC_REQ_EXCHANGE_ITEM($parser) {
	echo "$parser->packet_desc name=".$parser->string(24)."\n";
}

// packet 0xe6
function PACKET_CZ_ACK_EXCHANGE_ITEM($parser) {
	echo "$parser->packet_desc result=".$parser->byte()."\n";
}

// packet 0xe7
function PACKET_ZC_ACK_EXCHANGE_ITEM($parser) {
	echo "$parser->packet_desc result=".$parser->byte()."\n";
}

// packet 0xe8
function PACKET_CZ_ADD_EXCHANGE_ITEM($parser) {
	echo "$parser->packet_desc index=".$parser->word()."\n";
	echo "$parser->nl count=".$parser->long()."\n";
}

// packet 0xe9
function PACKET_ZC_ADD_EXCHANGE_ITEM($parser) {
	echo "$parser->packet_desc count=".$parser->long()."\n";
	echo "$parser->nl ITID=".$parser->word()."\n";
	echo "$parser->nl IsIdentified=".$parser->byte()."\n";
	echo "$parser->nl IsDamaged=".$parser->byte()."\n";
	echo "$parser->nl refiningLevel=".$parser->byte()."\n";
		echo "$parser->nl card1=".$parser->word()."\n";
		echo "$parser->nl card2=".$parser->word()."\n";
		echo "$parser->nl card3=".$parser->word()."\n";
		echo "$parser->nl card4=".$parser->word()."\n";
}

// packet 0xea
function PACKET_ZC_ACK_ADD_EXCHANGE_ITEM($parser) {
	echo "$parser->packet_desc Index=".$parser->word()."\n";
	echo "$parser->nl result=".$parser->byte()."\n";
}

// packet 0xeb
function PACKET_CZ_CONCLUDE_EXCHANGE_ITEM($parser) {
	echo "$parser->packet_desc \n";
}

// packet 0xec
function PACKET_ZC_CONCLUDE_EXCHANGE_ITEM($parser) {
	echo "$parser->packet_desc who=".$parser->byte()."\n";
}

// packet 0xed
function PACKET_CZ_CANCEL_EXCHANGE_ITEM($parser) {
	echo "$parser->packet_desc \n";
}

// packet 0xee
function PACKET_ZC_CANCEL_EXCHANGE_ITEM($parser) {
	echo "$parser->packet_desc \n";
}

// packet 0xef
function PACKET_CZ_EXEC_EXCHANGE_ITEM($parser) {
	echo "$parser->packet_desc \n";
}

// packet 0xf0
function PACKET_ZC_EXEC_EXCHANGE_ITEM($parser) {
	echo "$parser->packet_desc result=".$parser->byte()."\n";
}

// packet 0xf1
function PACKET_ZC_EXCHANGEITEM_UNDO($parser) {
	echo "$parser->packet_desc \n";
}

// packet 0xf2
function PACKET_ZC_NOTIFY_STOREITEM_COUNTINFO($parser) {
	echo "$parser->packet_desc curCount=".$parser->word()."\n";
	echo "$parser->nl maxCount=".$parser->word()."\n";
}

// packet 0xf3
function PACKET_CZ_MOVE_ITEM_FROM_BODY_TO_STORE($parser) {
	echo "$parser->packet_desc index=".$parser->word()."\n";
	echo "$parser->nl count=".$parser->long()."\n";
}

// packet 0xf4
function PACKET_ZC_ADD_ITEM_TO_STORE($parser) {
	echo "$parser->packet_desc index=".$parser->word()."\n";
	echo "$parser->nl count=".$parser->long()."\n";
	echo "$parser->nl ITID=".$parser->word()."\n";
	echo "$parser->nl IsIdentified=".$parser->byte()."\n";
	echo "$parser->nl IsDamaged=".$parser->byte()."\n";
	echo "$parser->nl refiningLevel=".$parser->byte()."\n";
		echo "$parser->nl card1=".$parser->word()."\n";
		echo "$parser->nl card2=".$parser->word()."\n";
		echo "$parser->nl card3=".$parser->word()."\n";
		echo "$parser->nl card4=".$parser->word()."\n";
}

// packet 0xf5
function PACKET_CZ_MOVE_ITEM_FROM_STORE_TO_BODY($parser) {
	echo "$parser->packet_desc index=".$parser->word()."\n";
	echo "$parser->nl count=".$parser->long()."\n";
}

// packet 0xf6
function PACKET_ZC_DELETE_ITEM_FROM_STORE($parser) {
	echo "$parser->packet_desc index=".$parser->word()."\n";
	echo "$parser->nl count=".$parser->long()."\n";
}

// packet 0xf7
function PACKET_CZ_CLOSE_STORE($parser) {
	echo "$parser->packet_desc \n";
}

// packet 0xf8
function PACKET_ZC_CLOSE_STORE($parser) {
	echo "$parser->packet_desc \n";
}

// packet 0xf9
function PACKET_CZ_MAKE_GROUP($parser) {
	echo "$parser->packet_desc groupName=".$parser->string(24)."\n";
}

// packet 0xfa
function PACKET_ZC_ACK_MAKE_GROUP($parser) {
	echo "$parser->packet_desc result=".$parser->byte()."\n";
}

// packet 0xfb
function PACKET_ZC_GROUP_LIST($parser) {
	echo "$parser->packet_desc PacketLength=".$parser->word()."\n";
	echo "$parser->nl groupName=".$parser->string(24)."\n";
	$groupInfo = ($parser->packet_length - $parser->packet_pointer) / 46;
	for ($i = 0; $i < $groupInfo; $i++) {
		echo "$parser->nl AID=".$parser->long()."\n";
		echo "$parser->nl characterName=".$parser->string(24)."\n";
		echo "$parser->nl mapName=".$parser->string(16)."\n";
		echo "$parser->nl role=".$parser->byte()."\n";
		echo "$parser->nl state=".$parser->byte()."\n";
	}
}

// packet 0xfc
function PACKET_CZ_REQ_JOIN_GROUP($parser) {
	echo "$parser->packet_desc AID=".$parser->long()."\n";
}

// packet 0xfd
function PACKET_ZC_ACK_REQ_JOIN_GROUP($parser) {
	echo "$parser->packet_desc characterName=".$parser->string(24)."\n";
	echo "$parser->nl answer=".$parser->byte()."\n";
}

// packet 0xfe
function PACKET_ZC_REQ_JOIN_GROUP($parser) {
	echo "$parser->packet_desc GRID=".$parser->long()."\n";
	echo "$parser->nl groupName=".$parser->string(24)."\n";
}

// packet 0xff
function PACKET_CZ_JOIN_GROUP($parser) {
	echo "$parser->packet_desc GRID=".$parser->long()."\n";
	echo "$parser->nl answer=".$parser->long()."\n";
}

// packet 0x100
function PACKET_CZ_REQ_LEAVE_GROUP($parser) {
	echo "$parser->packet_desc \n";
}

// packet 0x101
function PACKET_ZC_GROUPINFO_CHANGE($parser) {
	echo "$parser->packet_desc expOption=".$parser->long()."\n";
}

// packet 0x102
function PACKET_CZ_CHANGE_GROUPEXPOPTION($parser) {
	echo "$parser->packet_desc expOption=".$parser->long()."\n";
}

// packet 0x103
function PACKET_CZ_REQ_EXPEL_GROUP_MEMBER($parser) {
	echo "$parser->packet_desc AID=".$parser->long()."\n";
	echo "$parser->nl characterName=".$parser->string(24)."\n";
}

// packet 0x104
function PACKET_ZC_ADD_MEMBER_TO_GROUP($parser) {
	echo "$parser->packet_desc AID=".$parser->long()."\n";
	echo "$parser->nl Role=".$parser->long()."\n";
	echo "$parser->nl xPos=".$parser->word()."\n";
	echo "$parser->nl yPos=".$parser->word()."\n";
	echo "$parser->nl state=".$parser->byte()."\n";
	echo "$parser->nl groupName=".$parser->string(24)."\n";
	echo "$parser->nl characterName=".$parser->string(24)."\n";
	echo "$parser->nl mapName=".$parser->string(16)."\n";
}

// packet 0x105
function PACKET_ZC_DELETE_MEMBER_FROM_GROUP($parser) {
	echo "$parser->packet_desc AID=".$parser->long()."\n";
	echo "$parser->nl characterName=".$parser->string(24)."\n";
	echo "$parser->nl result=".$parser->byte()."\n";
}

// packet 0x106
function PACKET_ZC_NOTIFY_HP_TO_GROUPM($parser) {
	echo "$parser->packet_desc AID=".$parser->long()."\n";
	echo "$parser->nl hp=".$parser->word()."\n";
	echo "$parser->nl maxhp=".$parser->word()."\n";
}

// packet 0x107
function PACKET_ZC_NOTIFY_POSITION_TO_GROUPM($parser) {
	echo "$parser->packet_desc AID=".$parser->long()."\n";
	echo "$parser->nl xPos=".$parser->word()."\n";
	echo "$parser->nl yPos=".$parser->word()."\n";
}

// packet 0x108
function PACKET_CZ_REQUEST_CHAT_PARTY($parser) {
	echo "$parser->packet_desc PacketLength=".$parser->word()."\n";
	echo "$parser->nl msg=".$parser->string($parser->packet_length - $parser->packet_pointer)."\n";
}

// packet 0x109
function PACKET_ZC_NOTIFY_CHAT_PARTY($parser) {
	echo "$parser->packet_desc PacketLength=".$parser->word()."\n";
	echo "$parser->nl AID=".$parser->long()."\n";
	echo "$parser->nl msg=".$parser->string($parser->packet_length - $parser->packet_pointer)."\n";
}

// packet 0x10a
function PACKET_ZC_MVP_GETTING_ITEM($parser) {
	echo "$parser->packet_desc ITID=".$parser->word()."\n";
}

// packet 0x10b
function PACKET_ZC_MVP_GETTING_SPECIAL_EXP($parser) {
	echo "$parser->packet_desc exp=".$parser->long()."\n";
}

// packet 0x10c
function PACKET_ZC_MVP($parser) {
	echo "$parser->packet_desc AID=".$parser->long()."\n";
}

// packet 0x10d
function PACKET_ZC_THROW_MVPITEM($parser) {
	echo "$parser->packet_desc \n";
}

// packet 0x10e
function PACKET_ZC_SKILLINFO_UPDATE($parser) {
	echo "$parser->packet_desc SKID=".$parser->word()."\n";
	echo "$parser->nl level=".$parser->word()."\n";
	echo "$parser->nl spcost=".$parser->word()."\n";
	echo "$parser->nl attackRange=".$parser->word()."\n";
	echo "$parser->nl upgradable=".$parser->byte()."\n";
}

// packet 0x10f
function PACKET_ZC_SKILLINFO_LIST($parser) {
	echo "$parser->packet_desc PacketLength=".$parser->word()."\n";
	$skillList = ($parser->packet_length - $parser->packet_pointer) / 37;
	for ($i = 0; $i < $skillList; $i++) {
		echo "$parser->nl SKID=".$parser->word()."\n";
		echo "$parser->nl type=".$parser->long()."\n";
		echo "$parser->nl level=".$parser->word()."\n";
		echo "$parser->nl spcost=".$parser->word()."\n";
		echo "$parser->nl attackRange=".$parser->word()."\n";
		echo "$parser->nl skillName=".$parser->string(24)."\n";
		echo "$parser->nl upgradable=".$parser->byte()."\n";
	}
}

// packet 0x110
function PACKET_ZC_ACK_TOUSESKILL($parser) {
	echo "$parser->packet_desc SKID=".$parser->word()."\n";
	echo "$parser->nl NUM=".$parser->long()."\n";
	echo "$parser->nl result=".$parser->byte()."\n";
	echo "$parser->nl cause=".$parser->byte()."\n";
}

// packet 0x111
function PACKET_ZC_ADD_SKILL($parser) {
	echo "$parser->packet_desc ";
		echo "$parser->nl SKID=".$parser->word()."\n";
		echo "$parser->nl type=".$parser->long()."\n";
		echo "$parser->nl level=".$parser->word()."\n";
		echo "$parser->nl spcost=".$parser->word()."\n";
		echo "$parser->nl attackRange=".$parser->word()."\n";
		echo "$parser->nl skillName=".$parser->string(24)."\n";
		echo "$parser->nl upgradable=".$parser->byte()."\n";
}

// packet 0x112
function PACKET_CZ_UPGRADE_SKILLLEVEL($parser) {
	echo "$parser->packet_desc SKID=".$parser->word()."\n";
}

// packet 0x113
function PACKET_CZ_USE_SKILL($parser) {
	echo "$parser->packet_desc selectedLevel=".$parser->word()."\n";
	echo "$parser->nl SKID=".$parser->word()."\n";
	echo "$parser->nl targetID=".$parser->long()."\n";
}

// packet 0x114
function PACKET_ZC_NOTIFY_SKILL($parser) {
	echo "$parser->packet_desc SKID=".$parser->word()."\n";
	echo "$parser->nl AID=".$parser->long()."\n";
	echo "$parser->nl targetID=".$parser->long()."\n";
	echo "$parser->nl startTime=".$parser->long()."\n";
	echo "$parser->nl attackMT=".$parser->long()."\n";
	echo "$parser->nl attackedMT=".$parser->long()."\n";
	echo "$parser->nl damage=".$parser->word()."\n";
	echo "$parser->nl level=".$parser->word()."\n";
	echo "$parser->nl count=".$parser->word()."\n";
	echo "$parser->nl action=".$parser->byte()."\n";
}

// packet 0x115
function PACKET_ZC_NOTIFY_SKILL_POSITION($parser) {
	echo "$parser->packet_desc SKID=".$parser->word()."\n";
	echo "$parser->nl AID=".$parser->long()."\n";
	echo "$parser->nl targetID=".$parser->long()."\n";
	echo "$parser->nl startTime=".$parser->long()."\n";
	echo "$parser->nl attackMT=".$parser->long()."\n";
	echo "$parser->nl attackedMT=".$parser->long()."\n";
	echo "$parser->nl xPos=".$parser->word()."\n";
	echo "$parser->nl yPos=".$parser->word()."\n";
	echo "$parser->nl damage=".$parser->word()."\n";
	echo "$parser->nl level=".$parser->word()."\n";
	echo "$parser->nl count=".$parser->word()."\n";
	echo "$parser->nl action=".$parser->byte()."\n";
}

// packet 0x116
function PACKET_CZ_USE_SKILL_TOGROUND($parser) {
	echo "$parser->packet_desc selectedLevel=".$parser->word()."\n";
	echo "$parser->nl SKID=".$parser->word()."\n";
	echo "$parser->nl xPos=".$parser->word()."\n";
	echo "$parser->nl yPos=".$parser->word()."\n";
}

// packet 0x117
function PACKET_ZC_NOTIFY_GROUNDSKILL($parser) {
	echo "$parser->packet_desc SKID=".$parser->word()."\n";
	echo "$parser->nl AID=".$parser->long()."\n";
	echo "$parser->nl level=".$parser->word()."\n";
	echo "$parser->nl xPos=".$parser->word()."\n";
	echo "$parser->nl yPos=".$parser->word()."\n";
	echo "$parser->nl startTime=".$parser->long()."\n";
}

// packet 0x118
function PACKET_CZ_CANCEL_LOCKON($parser) {
	echo "$parser->packet_desc \n";
}

// packet 0x119
function PACKET_ZC_STATE_CHANGE($parser) {
	echo "$parser->packet_desc AID=".$parser->long()."\n";
	echo "$parser->nl bodyState=".$parser->word()."\n";
	echo "$parser->nl healthState=".$parser->word()."\n";
	echo "$parser->nl effectState=".$parser->word()."\n";
	echo "$parser->nl isPKModeON=".$parser->byte()."\n";
}

// packet 0x11a
function PACKET_ZC_USE_SKILL($parser) {
	echo "$parser->packet_desc SKID=".$parser->word()."\n";
	echo "$parser->nl level=".$parser->word()."\n";
	echo "$parser->nl targetAID=".$parser->long()."\n";
	echo "$parser->nl srcAID=".$parser->long()."\n";
	echo "$parser->nl result=".$parser->byte()."\n";
}

// packet 0x11b
function PACKET_CZ_SELECT_WARPPOINT($parser) {
	echo "$parser->packet_desc SKID=".$parser->word()."\n";
	echo "$parser->nl mapName=".$parser->string(16)."\n";
}

// packet 0x11c
function PACKET_ZC_WARPLIST($parser) {
	echo "$parser->packet_desc SKID=".$parser->word()."\n";
	echo "$parser->nl mapName=".$parser->string(16)."\n";
}

// packet 0x11d
function PACKET_CZ_REMEMBER_WARPPOINT($parser) {
	echo "$parser->packet_desc \n";
}

// packet 0x11e
function PACKET_ZC_ACK_REMEMBER_WARPPOINT($parser) {
	echo "$parser->packet_desc errorCode=".$parser->byte()."\n";
}

// packet 0x11f
function PACKET_ZC_SKILL_ENTRY($parser) {
	echo "$parser->packet_desc AID=".$parser->long()."\n";
	echo "$parser->nl creatorAID=".$parser->long()."\n";
	echo "$parser->nl xPos=".$parser->word()."\n";
	echo "$parser->nl yPos=".$parser->word()."\n";
	echo "$parser->nl job=".$parser->byte()."\n";
	echo "$parser->nl isVisible=".$parser->byte()."\n";
}

// packet 0x120
function PACKET_ZC_SKILL_DISAPPEAR($parser) {
	echo "$parser->packet_desc AID=".$parser->long()."\n";
}

// packet 0x121
function PACKET_ZC_NOTIFY_CARTITEM_COUNTINFO($parser) {
	echo "$parser->packet_desc curCount=".$parser->word()."\n";
	echo "$parser->nl maxCount=".$parser->word()."\n";
	echo "$parser->nl curWeight=".$parser->long()."\n";
	echo "$parser->nl maxWeight=".$parser->long()."\n";
}

// packet 0x122
function PACKET_ZC_CART_EQUIPMENT_ITEMLIST($parser) {
	echo "$parser->packet_desc PacketLength=".$parser->word()."\n";
	$itemInfo = ($parser->packet_length - $parser->packet_pointer) / 20;
	for ($i = 0; $i < $itemInfo; $i++) {
		echo "$parser->nl index=".$parser->word()."\n";
		echo "$parser->nl ITID=".$parser->word()."\n";
		echo "$parser->nl type=".$parser->byte()."\n";
		echo "$parser->nl IsIdentified=".$parser->byte()."\n";
		echo "$parser->nl location=".$parser->word()."\n";
		echo "$parser->nl WearState=".$parser->word()."\n";
		echo "$parser->nl IsDamaged=".$parser->byte()."\n";
		echo "$parser->nl RefiningLevel=".$parser->byte()."\n";
		echo "$parser->nl card1=".$parser->word()."\n";
		echo "$parser->nl card2=".$parser->word()."\n";
		echo "$parser->nl card3=".$parser->word()."\n";
		echo "$parser->nl card4=".$parser->word()."\n";
	}
}

// packet 0x123
function PACKET_ZC_CART_NORMAL_ITEMLIST($parser) {
	echo "$parser->packet_desc PacketLength=".$parser->word()."\n";
	$itemInfo = ($parser->packet_length - $parser->packet_pointer) / 10;
	for ($i = 0; $i < $itemInfo; $i++) {
		echo "$parser->nl index=".$parser->word()."\n";
		echo "$parser->nl ITID=".$parser->word()."\n";
		echo "$parser->nl type=".$parser->byte()."\n";
		echo "$parser->nl IsIdentified=".$parser->byte()."\n";
		echo "$parser->nl count=".$parser->word()."\n";
		echo "$parser->nl WearState=".$parser->word()."\n";
	}
}

// packet 0x124
function PACKET_ZC_ADD_ITEM_TO_CART($parser) {
	echo "$parser->packet_desc index=".$parser->word()."\n";
	echo "$parser->nl count=".$parser->long()."\n";
	echo "$parser->nl ITID=".$parser->word()."\n";
	echo "$parser->nl IsIdentified=".$parser->byte()."\n";
	echo "$parser->nl IsDamaged=".$parser->byte()."\n";
	echo "$parser->nl refiningLevel=".$parser->byte()."\n";
		echo "$parser->nl card1=".$parser->word()."\n";
		echo "$parser->nl card2=".$parser->word()."\n";
		echo "$parser->nl card3=".$parser->word()."\n";
		echo "$parser->nl card4=".$parser->word()."\n";
}

// packet 0x125
function PACKET_ZC_DELETE_ITEM_FROM_CART($parser) {
	echo "$parser->packet_desc index=".$parser->word()."\n";
	echo "$parser->nl count=".$parser->long()."\n";
}

// packet 0x126
function PACKET_CZ_MOVE_ITEM_FROM_BODY_TO_CART($parser) {
	echo "$parser->packet_desc index=".$parser->word()."\n";
	echo "$parser->nl count=".$parser->long()."\n";
}

// packet 0x127
function PACKET_CZ_MOVE_ITEM_FROM_CART_TO_BODY($parser) {
	echo "$parser->packet_desc index=".$parser->word()."\n";
	echo "$parser->nl count=".$parser->long()."\n";
}

// packet 0x128
function PACKET_CZ_MOVE_ITEM_FROM_STORE_TO_CART($parser) {
	echo "$parser->packet_desc index=".$parser->word()."\n";
	echo "$parser->nl count=".$parser->long()."\n";
}

// packet 0x129
function PACKET_CZ_MOVE_ITEM_FROM_CART_TO_STORE($parser) {
	echo "$parser->packet_desc index=".$parser->word()."\n";
	echo "$parser->nl count=".$parser->long()."\n";
}

// packet 0x12a
function PACKET_CZ_REQ_CARTOFF($parser) {
	echo "$parser->packet_desc \n";
}

// packet 0x12b
function PACKET_ZC_CARTOFF($parser) {
	echo "$parser->packet_desc \n";
}

// packet 0x12c
function PACKET_ZC_ACK_ADDITEM_TO_CART($parser) {
	echo "$parser->packet_desc result=".$parser->byte()."\n";
}

// packet 0x12d
function PACKET_ZC_OPENSTORE($parser) {
	echo "$parser->packet_desc itemcount=".$parser->word()."\n";
}

// packet 0x12e
function PACKET_CZ_REQ_CLOSESTORE($parser) {
	echo "$parser->packet_desc \n";
}

// packet 0x12f
function PACKET_CZ_REQ_OPENSTORE($parser) {
	echo "$parser->packet_desc PacketLength=".$parser->word()."\n";
	echo "$parser->nl storeName=".$parser->string(80)."\n";
	$storeList = ($parser->packet_length - $parser->packet_pointer) / 8;
	for ($i = 0; $i < $storeList; $i++) {
		echo "$parser->nl index=".$parser->word()."\n";
		echo "$parser->nl count=".$parser->word()."\n";
		echo "$parser->nl Price=".$parser->long()."\n";
	}
}

// packet 0x130
function PACKET_CZ_REQ_BUY_FROMMC($parser) {
	echo "$parser->packet_desc AID=".$parser->long()."\n";
}

// packet 0x131
function PACKET_ZC_STORE_ENTRY($parser) {
	echo "$parser->packet_desc makerAID=".$parser->long()."\n";
	echo "$parser->nl storeName=".$parser->string(80)."\n";
}

// packet 0x132
function PACKET_ZC_DISAPPEAR_ENTRY($parser) {
	echo "$parser->packet_desc makerAID=".$parser->long()."\n";
}

// packet 0x133
function PACKET_ZC_PC_PURCHASE_ITEMLIST_FROMMC($parser) {
	echo "$parser->packet_desc PacketLength=".$parser->word()."\n";
	echo "$parser->nl AID=".$parser->long()."\n";
	$itemList = ($parser->packet_length - $parser->packet_pointer) / 22;
	for ($i = 0; $i < $itemList; $i++) {
		echo "$parser->nl price=".$parser->long()."\n";
		echo "$parser->nl count=".$parser->word()."\n";
		echo "$parser->nl index=".$parser->word()."\n";
		echo "$parser->nl type=".$parser->byte()."\n";
		echo "$parser->nl ITID=".$parser->word()."\n";
		echo "$parser->nl IsIdentified=".$parser->byte()."\n";
		echo "$parser->nl IsDamaged=".$parser->byte()."\n";
		echo "$parser->nl refiningLevel=".$parser->byte()."\n";
		echo "$parser->nl card1=".$parser->word()."\n";
		echo "$parser->nl card2=".$parser->word()."\n";
		echo "$parser->nl card3=".$parser->word()."\n";
		echo "$parser->nl card4=".$parser->word()."\n";
	}
}

// packet 0x134
function PACKET_CZ_PC_PURCHASE_ITEMLIST_FROMMC($parser) {
	echo "$parser->packet_desc PacketLength=".$parser->word()."\n";
	echo "$parser->nl AID=".$parser->long()."\n";
	$itemList = ($parser->packet_length - $parser->packet_pointer) / 4;
	for ($i = 0; $i < $itemList; $i++) {
		echo "$parser->nl count=".$parser->word()."\n";
		echo "$parser->nl index=".$parser->word()."\n";
	}
}

// packet 0x135
function PACKET_ZC_PC_PURCHASE_RESULT_FROMMC($parser) {
	echo "$parser->packet_desc index=".$parser->word()."\n";
	echo "$parser->nl curcount=".$parser->word()."\n";
	echo "$parser->nl result=".$parser->byte()."\n";
}

// packet 0x136
function PACKET_ZC_PC_PURCHASE_MYITEMLIST($parser) {
	echo "$parser->packet_desc PacketLength=".$parser->word()."\n";
	echo "$parser->nl AID=".$parser->long()."\n";
	$itemList = ($parser->packet_length - $parser->packet_pointer) / 22;
	for ($i = 0; $i < $itemList; $i++) {
		echo "$parser->nl price=".$parser->long()."\n";
		echo "$parser->nl index=".$parser->word()."\n";
		echo "$parser->nl count=".$parser->word()."\n";
		echo "$parser->nl type=".$parser->byte()."\n";
		echo "$parser->nl ITID=".$parser->word()."\n";
		echo "$parser->nl IsIdentified=".$parser->byte()."\n";
		echo "$parser->nl IsDamaged=".$parser->byte()."\n";
		echo "$parser->nl refiningLevel=".$parser->byte()."\n";
		echo "$parser->nl card1=".$parser->word()."\n";
		echo "$parser->nl card2=".$parser->word()."\n";
		echo "$parser->nl card3=".$parser->word()."\n";
		echo "$parser->nl card4=".$parser->word()."\n";
	}
}

// packet 0x137
function PACKET_ZC_DELETEITEM_FROM_MCSTORE($parser) {
	echo "$parser->packet_desc index=".$parser->word()."\n";
	echo "$parser->nl count=".$parser->word()."\n";
}

// packet 0x138
function PACKET_CZ_PKMODE_CHANGE($parser) {
	echo "$parser->packet_desc isTurnOn=".$parser->byte()."\n";
}

// packet 0x139
function PACKET_ZC_ATTACK_FAILURE_FOR_DISTANCE($parser) {
	echo "$parser->packet_desc targetAID=".$parser->long()."\n";
	echo "$parser->nl targetXPos=".$parser->word()."\n";
	echo "$parser->nl targetYPos=".$parser->word()."\n";
	echo "$parser->nl xPos=".$parser->word()."\n";
	echo "$parser->nl yPos=".$parser->word()."\n";
	echo "$parser->nl currentAttRange=".$parser->word()."\n";
}

// packet 0x13a
function PACKET_ZC_ATTACK_RANGE($parser) {
	echo "$parser->packet_desc currentAttRange=".$parser->word()."\n";
}

// packet 0x13b
function PACKET_ZC_ACTION_FAILURE($parser) {
	echo "$parser->packet_desc errorCode=".$parser->word()."\n";
}

// packet 0x13c
function PACKET_ZC_EQUIP_ARROW($parser) {
	echo "$parser->packet_desc index=".$parser->word()."\n";
}

// packet 0x13d
function PACKET_ZC_RECOVERY($parser) {
	echo "$parser->packet_desc varID=".$parser->word()."\n";
	echo "$parser->nl amount=".$parser->word()."\n";
}

// packet 0x13e
function PACKET_ZC_USESKILL_ACK($parser) {
	echo "$parser->packet_desc AID=".$parser->long()."\n";
	echo "$parser->nl targetID=".$parser->long()."\n";
	echo "$parser->nl xPos=".$parser->word()."\n";
	echo "$parser->nl yPos=".$parser->word()."\n";
	echo "$parser->nl SKID=".$parser->word()."\n";
	echo "$parser->nl property=".$parser->long()."\n";
	echo "$parser->nl delayTime=".$parser->long()."\n";
}

// packet 0x13f
function PACKET_CZ_ITEM_CREATE($parser) {
	echo "$parser->packet_desc itemName=".$parser->string(24)."\n";
}

// packet 0x140
function PACKET_CZ_MOVETO_MAP($parser) {
	echo "$parser->packet_desc mapName=".$parser->string(16)."\n";
	echo "$parser->nl xPos=".$parser->word()."\n";
	echo "$parser->nl yPos=".$parser->word()."\n";
}

// packet 0x141
function PACKET_ZC_COUPLESTATUS($parser) {
	echo "$parser->packet_desc statusType=".$parser->long()."\n";
	echo "$parser->nl defaultStatus=".$parser->long()."\n";
	echo "$parser->nl plusStatus=".$parser->long()."\n";
}

// packet 0x142
function PACKET_ZC_OPEN_EDITDLG($parser) {
	echo "$parser->packet_desc NAID=".$parser->long()."\n";
}

// packet 0x143
function PACKET_CZ_INPUT_EDITDLG($parser) {
	echo "$parser->packet_desc NAID=".$parser->long()."\n";
	echo "$parser->nl value=".$parser->long()."\n";
}

// packet 0x144
function PACKET_ZC_COMPASS($parser) {
	echo "$parser->packet_desc NAID=".$parser->long()."\n";
	echo "$parser->nl type=".$parser->long()."\n";
	echo "$parser->nl xPos=".$parser->long()."\n";
	echo "$parser->nl yPos=".$parser->long()."\n";
	echo "$parser->nl id=".$parser->byte()."\n";
	echo "$parser->nl color=".$parser->long()."\n";
}

// packet 0x145
function PACKET_ZC_SHOW_IMAGE($parser) {
	echo "$parser->packet_desc imageName=".$parser->string(16)."\n";
	echo "$parser->nl type=".$parser->byte()."\n";
}

// packet 0x146
function PACKET_CZ_CLOSE_DIALOG($parser) {
	echo "$parser->packet_desc NAID=".$parser->long()."\n";
}

// packet 0x147
function PACKET_ZC_AUTORUN_SKILL($parser) {
	echo "$parser->packet_desc ";
		echo "$parser->nl SKID=".$parser->word()."\n";
		echo "$parser->nl type=".$parser->long()."\n";
		echo "$parser->nl level=".$parser->word()."\n";
		echo "$parser->nl spcost=".$parser->word()."\n";
		echo "$parser->nl attackRange=".$parser->word()."\n";
		echo "$parser->nl skillName=".$parser->string(24)."\n";
		echo "$parser->nl upgradable=".$parser->byte()."\n";
}

// packet 0x148
function PACKET_ZC_RESURRECTION($parser) {
	echo "$parser->packet_desc AID=".$parser->long()."\n";
	echo "$parser->nl type=".$parser->word()."\n";
}

// packet 0x149
function PACKET_CZ_REQ_GIVE_MANNER_POINT($parser) {
	echo "$parser->packet_desc otherAID=".$parser->long()."\n";
	echo "$parser->nl type=".$parser->byte()."\n";
	echo "$parser->nl point=".$parser->word()."\n";
}

// packet 0x14a
function PACKET_ZC_ACK_GIVE_MANNER_POINT($parser) {
	echo "$parser->packet_desc result=".$parser->long()."\n";
}

// packet 0x14b
function PACKET_ZC_NOTIFY_MANNER_POINT_GIVEN($parser) {
	echo "$parser->packet_desc type=".$parser->byte()."\n";
	echo "$parser->nl otherCharName=".$parser->string(24)."\n";
}

// packet 0x14c
function PACKET_ZC_MYGUILD_BASIC_INFO($parser) {
	echo "$parser->packet_desc PacketLength=".$parser->word()."\n";
	$relatedGuildList = ($parser->packet_length - $parser->packet_pointer) / 32;
	for ($i = 0; $i < $relatedGuildList; $i++) {
		echo "$parser->nl GDID=".$parser->long()."\n";
		echo "$parser->nl relation=".$parser->long()."\n";
		echo "$parser->nl GuildName=".$parser->string(24)."\n";
	}
}

// packet 0x14d
function PACKET_CZ_REQ_GUILD_MENUINTERFACE($parser) {
	echo "$parser->packet_desc \n";
}

// packet 0x14e
function PACKET_ZC_ACK_GUILD_MENUINTERFACE($parser) {
	echo "$parser->packet_desc guildMemuFlag=".$parser->long()."\n";
}

// packet 0x14f
function PACKET_CZ_REQ_GUILD_MENU($parser) {
	echo "$parser->packet_desc Type=".$parser->long()."\n";
}

// packet 0x150
function PACKET_ZC_GUILD_INFO($parser) {
	echo "$parser->packet_desc GDID=".$parser->long()."\n";
	echo "$parser->nl level=".$parser->long()."\n";
	echo "$parser->nl userNum=".$parser->long()."\n";
	echo "$parser->nl maxUserNum=".$parser->long()."\n";
	echo "$parser->nl userAverageLevel=".$parser->long()."\n";
	echo "$parser->nl exp=".$parser->long()."\n";
	echo "$parser->nl maxExp=".$parser->long()."\n";
	echo "$parser->nl point=".$parser->long()."\n";
	echo "$parser->nl honor=".$parser->long()."\n";
	echo "$parser->nl virtue=".$parser->long()."\n";
	echo "$parser->nl emblemVersion=".$parser->long()."\n";
	echo "$parser->nl guildname=".$parser->string(24)."\n";
	echo "$parser->nl masterName=".$parser->string(24)."\n";
	echo "$parser->nl manageLand=".$parser->string(16)."\n";
}

// packet 0x151
function PACKET_CZ_REQ_GUILD_EMBLEM_IMG($parser) {
	echo "$parser->packet_desc GDID=".$parser->long()."\n";
}

// packet 0x152
function PACKET_ZC_GUILD_EMBLEM_IMG($parser) {
	echo "$parser->packet_desc PacketLength=".$parser->word()."\n";
	echo "$parser->nl GDID=".$parser->long()."\n";
	echo "$parser->nl emblemVersion=".$parser->long()."\n";
	echo "$parser->nl img=".$parser->string($parser->packet_length - $parser->packet_pointer)."\n";
}

// packet 0x153
function PACKET_CZ_REGISTER_GUILD_EMBLEM_IMG($parser) {
	echo "$parser->packet_desc PacketLength=".$parser->word()."\n";
	echo "$parser->nl img=".$parser->string($parser->packet_length - $parser->packet_pointer)."\n";
}

// packet 0x154
function PACKET_ZC_MEMBERMGR_INFO($parser) {
	echo "$parser->packet_desc PacketLength=".$parser->word()."\n";
	$memberInfo = ($parser->packet_length - $parser->packet_pointer) / 104;
	for ($i = 0; $i < $memberInfo; $i++) {
		echo "$parser->nl AID=".$parser->long()."\n";
		echo "$parser->nl GID=".$parser->long()."\n";
		echo "$parser->nl HeadType=".$parser->word()."\n";
		echo "$parser->nl HeadPalette=".$parser->word()."\n";
		echo "$parser->nl Sex=".$parser->word()."\n";
		echo "$parser->nl Job=".$parser->word()."\n";
		echo "$parser->nl Level=".$parser->word()."\n";
		echo "$parser->nl MemberExp=".$parser->long()."\n";
		echo "$parser->nl CurrentState=".$parser->long()."\n";
		echo "$parser->nl GPositionID=".$parser->long()."\n";
		echo "$parser->nl Memo=".$parser->string(50)."\n";
		echo "$parser->nl CharName=".$parser->string(24)."\n";
	}
}

// packet 0x155
function PACKET_CZ_REQ_CHANGE_MEMBERPOS($parser) {
	echo "$parser->packet_desc PacketLength=".$parser->word()."\n";
	$memberInfo = ($parser->packet_length - $parser->packet_pointer) / 12;
	for ($i = 0; $i < $memberInfo; $i++) {
		echo "$parser->nl AID=".$parser->long()."\n";
		echo "$parser->nl GID=".$parser->long()."\n";
		echo "$parser->nl positionID=".$parser->long()."\n";
	}
}

// packet 0x156
function PACKET_ZC_ACK_REQ_CHANGE_MEMBERS($parser) {
	echo "$parser->packet_desc PacketLength=".$parser->word()."\n";
	$memberInfo = ($parser->packet_length - $parser->packet_pointer) / 12;
	for ($i = 0; $i < $memberInfo; $i++) {
		echo "$parser->nl AID=".$parser->long()."\n";
		echo "$parser->nl GID=".$parser->long()."\n";
		echo "$parser->nl positionID=".$parser->long()."\n";
	}
}

// packet 0x157
function PACKET_CZ_REQ_OPEN_MEMBER_INFO($parser) {
	echo "$parser->packet_desc AID=".$parser->long()."\n";
}

// packet 0x158
function PACKET_ZC_ACK_OPEN_MEMBER_INFO($parser) {
	echo "$parser->packet_desc \n";
}

// packet 0x159
function PACKET_CZ_REQ_LEAVE_GUILD($parser) {
	echo "$parser->packet_desc GDID=".$parser->long()."\n";
	echo "$parser->nl AID=".$parser->long()."\n";
	echo "$parser->nl GID=".$parser->long()."\n";
	echo "$parser->nl reasonDesc=".$parser->string(40)."\n";
}

// packet 0x15a
function PACKET_ZC_ACK_LEAVE_GUILD($parser) {
	echo "$parser->packet_desc charName=".$parser->string(24)."\n";
	echo "$parser->nl reasonDesc=".$parser->string(40)."\n";
}

// packet 0x15b
function PACKET_CZ_REQ_BAN_GUILD($parser) {
	echo "$parser->packet_desc GDID=".$parser->long()."\n";
	echo "$parser->nl AID=".$parser->long()."\n";
	echo "$parser->nl GID=".$parser->long()."\n";
	echo "$parser->nl reasonDesc=".$parser->string(40)."\n";
}

// packet 0x15c
function PACKET_ZC_ACK_BAN_GUILD($parser) {
	echo "$parser->packet_desc charName=".$parser->string(24)."\n";
	echo "$parser->nl reasonDesc=".$parser->string(40)."\n";
	echo "$parser->nl account=".$parser->string(24)."\n";
}

// packet 0x15d
function PACKET_CZ_REQ_DISORGANIZE_GUILD($parser) {
	echo "$parser->packet_desc key=".$parser->string(40)."\n";
}

// packet 0x15e
function PACKET_ZC_ACK_DISORGANIZE_GUILD_RESULT($parser) {
	echo "$parser->packet_desc reason=".$parser->long()."\n";
}

// packet 0x15f
function PACKET_ZC_ACK_DISORGANIZE_GUILD($parser) {
	echo "$parser->packet_desc reasonDesc=".$parser->string(40)."\n";
}

// packet 0x160
function PACKET_ZC_POSITION_INFO($parser) {
	echo "$parser->packet_desc PacketLength=".$parser->word()."\n";
	$memberInfo = ($parser->packet_length - $parser->packet_pointer) / 16;
	for ($i = 0; $i < $memberInfo; $i++) {
		echo "$parser->nl positionID=".$parser->long()."\n";
		echo "$parser->nl right=".$parser->long()."\n";
		echo "$parser->nl ranking=".$parser->long()."\n";
		echo "$parser->nl payRate=".$parser->long()."\n";
	}
}

// packet 0x161
function PACKET_CZ_REG_CHANGE_GUILD_POSITIONINFO($parser) {
	echo "$parser->packet_desc PacketLength=".$parser->word()."\n";
	$memberList = ($parser->packet_length - $parser->packet_pointer) / 40;
	for ($i = 0; $i < $memberList; $i++) {
		echo "$parser->nl positionID=".$parser->long()."\n";
		echo "$parser->nl right=".$parser->long()."\n";
		echo "$parser->nl ranking=".$parser->long()."\n";
		echo "$parser->nl payRate=".$parser->long()."\n";
		echo "$parser->nl posName=".$parser->string(24)."\n";
	}
}

// packet 0x162
function PACKET_ZC_GUILD_SKILLINFO($parser) {
	echo "$parser->packet_desc PacketLength=".$parser->word()."\n";
	echo "$parser->nl skillPoint=".$parser->word()."\n";
	$skillList = ($parser->packet_length - $parser->packet_pointer) / 37;
	for ($i = 0; $i < $skillList; $i++) {
		echo "$parser->nl SKID=".$parser->word()."\n";
		echo "$parser->nl type=".$parser->long()."\n";
		echo "$parser->nl level=".$parser->word()."\n";
		echo "$parser->nl spcost=".$parser->word()."\n";
		echo "$parser->nl attackRange=".$parser->word()."\n";
		echo "$parser->nl skillName=".$parser->string(24)."\n";
		echo "$parser->nl upgradable=".$parser->byte()."\n";
	}
}

// packet 0x163
function PACKET_ZC_BAN_LIST($parser) {
	echo "$parser->packet_desc PacketLength=".$parser->word()."\n";
	$banList = ($parser->packet_length - $parser->packet_pointer) / 88;
	for ($i = 0; $i < $banList; $i++) {
		echo "$parser->nl charname=".$parser->string(24)."\n";
		echo "$parser->nl account=".$parser->string(24)."\n";
		echo "$parser->nl reason=".$parser->string(40)."\n";
	}
}

// packet 0x164
function PACKET_ZC_OTHER_GUILD_LIST($parser) {
	echo "$parser->packet_desc PacketLength=".$parser->word()."\n";
	$guildList = ($parser->packet_length - $parser->packet_pointer) / 36;
	for ($i = 0; $i < $guildList; $i++) {
		echo "$parser->nl guildname=".$parser->string(24)."\n";
		echo "$parser->nl guildLevel=".$parser->long()."\n";
		echo "$parser->nl guildMemberSize=".$parser->long()."\n";
		echo "$parser->nl guildRanking=".$parser->long()."\n";
	}
}

// packet 0x165
function PACKET_CZ_REQ_MAKE_GUILD($parser) {
	echo "$parser->packet_desc GID=".$parser->long()."\n";
	echo "$parser->nl GName=".$parser->string(24)."\n";
}

// packet 0x166
function PACKET_ZC_POSITION_ID_NAME_INFO($parser) {
	echo "$parser->packet_desc PacketLength=".$parser->word()."\n";
	$memberList = ($parser->packet_length - $parser->packet_pointer) / 28;
	for ($i = 0; $i < $memberList; $i++) {
		echo "$parser->nl positionID=".$parser->long()."\n";
		echo "$parser->nl posName=".$parser->string(24)."\n";
	}
}

// packet 0x167
function PACKET_ZC_RESULT_MAKE_GUILD($parser) {
	echo "$parser->packet_desc result=".$parser->byte()."\n";
}

// packet 0x168
function PACKET_CZ_REQ_JOIN_GUILD($parser) {
	echo "$parser->packet_desc AID=".$parser->long()."\n";
	echo "$parser->nl MyAID=".$parser->long()."\n";
	echo "$parser->nl MyGID=".$parser->long()."\n";
}

// packet 0x169
function PACKET_ZC_ACK_REQ_JOIN_GUILD($parser) {
	echo "$parser->packet_desc answer=".$parser->byte()."\n";
}

// packet 0x16a
function PACKET_ZC_REQ_JOIN_GUILD($parser) {
	echo "$parser->packet_desc GDID=".$parser->long()."\n";
	echo "$parser->nl guildName=".$parser->string(24)."\n";
}

// packet 0x16b
function PACKET_CZ_JOIN_GUILD($parser) {
	echo "$parser->packet_desc GDID=".$parser->long()."\n";
	echo "$parser->nl answer=".$parser->long()."\n";
}

// packet 0x16c
function PACKET_ZC_UPDATE_GDID($parser) {
	echo "$parser->packet_desc GDID=".$parser->long()."\n";
	echo "$parser->nl emblemVersion=".$parser->long()."\n";
	echo "$parser->nl right=".$parser->long()."\n";
	echo "$parser->nl isMaster=".$parser->byte()."\n";
	echo "$parser->nl InterSID=".$parser->long()."\n";
	echo "$parser->nl GName=".$parser->string(24)."\n";
}

// packet 0x16d
function PACKET_ZC_UPDATE_CHARSTAT($parser) {
	echo "$parser->packet_desc AID=".$parser->long()."\n";
	echo "$parser->nl GID=".$parser->long()."\n";
	echo "$parser->nl status=".$parser->long()."\n";
}

// packet 0x16e
function PACKET_CZ_GUILD_NOTICE($parser) {
	echo "$parser->packet_desc GDID=".$parser->long()."\n";
	echo "$parser->nl subject=".$parser->string(60)."\n";
	echo "$parser->nl notice=".$parser->string(120)."\n";
}

// packet 0x16f
function PACKET_ZC_GUILD_NOTICE($parser) {
	echo "$parser->packet_desc subject=".$parser->string(60)."\n";
	echo "$parser->nl notice=".$parser->string(120)."\n";
}

// packet 0x170
function PACKET_CZ_REQ_ALLY_GUILD($parser) {
	echo "$parser->packet_desc AID=".$parser->long()."\n";
	echo "$parser->nl MyAID=".$parser->long()."\n";
	echo "$parser->nl MyGID=".$parser->long()."\n";
}

// packet 0x171
function PACKET_ZC_REQ_ALLY_GUILD($parser) {
	echo "$parser->packet_desc otherAID=".$parser->long()."\n";
	echo "$parser->nl guildName=".$parser->string(24)."\n";
}

// packet 0x172
function PACKET_CZ_ALLY_GUILD($parser) {
	echo "$parser->packet_desc otherAID=".$parser->long()."\n";
	echo "$parser->nl answer=".$parser->long()."\n";
}

// packet 0x173
function PACKET_ZC_ACK_REQ_ALLY_GUILD($parser) {
	echo "$parser->packet_desc answer=".$parser->byte()."\n";
}

// packet 0x174
function PACKET_ZC_ACK_CHANGE_GUILD_POSITIONINFO($parser) {
	echo "$parser->packet_desc PacketLength=".$parser->word()."\n";
	$memberList = ($parser->packet_length - $parser->packet_pointer) / 30;
	for ($i = 0; $i < $memberList; $i++) {
		echo "$parser->nl positionID=".$parser->long()."\n";
		echo "$parser->nl right=".$parser->long()."\n";
		echo "$parser->nl ranking=".$parser->long()."\n";
		echo "$parser->nl payRate=".$parser->long()."\n";
		echo "$parser->nl posName=".$parser->string(24)."\n";
	}
}

// packet 0x175
function PACKET_CZ_REQ_GUILD_MEMBER_INFO($parser) {
	echo "$parser->packet_desc GID=".$parser->long()."\n";
}

// packet 0x176
function PACKET_ZC_ACK_GUILD_MEMBER_INFO($parser) {
	echo "$parser->packet_desc ";
		echo "$parser->nl AID=".$parser->long()."\n";
		echo "$parser->nl GID=".$parser->long()."\n";
		echo "$parser->nl head=".$parser->word()."\n";
		echo "$parser->nl headPalette=".$parser->word()."\n";
		echo "$parser->nl sex=".$parser->word()."\n";
		echo "$parser->nl job=".$parser->word()."\n";
		echo "$parser->nl level=".$parser->word()."\n";
		echo "$parser->nl contributionExp=".$parser->long()."\n";
		echo "$parser->nl currentState=".$parser->long()."\n";
		echo "$parser->nl positionID=".$parser->long()."\n";
		echo "$parser->nl intro=".$parser->string(50)."\n";
		echo "$parser->nl charname=".$parser->string(24)."\n";
}

// packet 0x177
function PACKET_ZC_ITEMIDENTIFY_LIST($parser) {
	echo "$parser->packet_desc PacketLength=".$parser->word()."\n";
	echo "$parser->nl ITIDList=".$parser->word()."\n";
}

// packet 0x178
function PACKET_CZ_REQ_ITEMIDENTIFY($parser) {
	echo "$parser->packet_desc index=".$parser->word()."\n";
}

// packet 0x179
function PACKET_ZC_ACK_ITEMIDENTIFY($parser) {
	echo "$parser->packet_desc index=".$parser->word()."\n";
	echo "$parser->nl result=".$parser->byte()."\n";
}

// packet 0x17a
function PACKET_CZ_REQ_ITEMCOMPOSITION_LIST($parser) {
	echo "$parser->packet_desc cardIndex=".$parser->word()."\n";
}

// packet 0x17b
function PACKET_ZC_ITEMCOMPOSITION_LIST($parser) {
	echo "$parser->packet_desc PacketLength=".$parser->word()."\n";
	echo "$parser->nl ITIDList=".$parser->word()."\n";
}

// packet 0x17c
function PACKET_CZ_REQ_ITEMCOMPOSITION($parser) {
	echo "$parser->packet_desc cardIndex=".$parser->word()."\n";
	echo "$parser->nl equipIndex=".$parser->word()."\n";
}

// packet 0x17d
function PACKET_ZC_ACK_ITEMCOMPOSITION($parser) {
	echo "$parser->packet_desc equipIndex=".$parser->word()."\n";
	echo "$parser->nl cardIndex=".$parser->word()."\n";
	echo "$parser->nl result=".$parser->byte()."\n";
}

// packet 0x17e
function PACKET_CZ_GUILD_CHAT($parser) {
	echo "$parser->packet_desc PacketLength=".$parser->word()."\n";
	echo "$parser->nl msg=".$parser->string($parser->packet_length - $parser->packet_pointer)."\n";
}

// packet 0x17f
function PACKET_ZC_GUILD_CHAT($parser) {
	echo "$parser->packet_desc PacketLength=".$parser->word()."\n";
	echo "$parser->nl msg=".$parser->string($parser->packet_length - $parser->packet_pointer)."\n";
}

// packet 0x180
function PACKET_CZ_REQ_HOSTILE_GUILD($parser) {
	echo "$parser->packet_desc AID=".$parser->long()."\n";
}

// packet 0x181
function PACKET_ZC_ACK_REQ_HOSTILE_GUILD($parser) {
	echo "$parser->packet_desc result=".$parser->byte()."\n";
}

// packet 0x182
function PACKET_ZC_MEMBER_ADD($parser) {
	echo "$parser->packet_desc ";
		echo "$parser->nl AID=".$parser->long()."\n";
		echo "$parser->nl GID=".$parser->long()."\n";
		echo "$parser->nl head=".$parser->word()."\n";
		echo "$parser->nl headPalette=".$parser->word()."\n";
		echo "$parser->nl sex=".$parser->word()."\n";
		echo "$parser->nl job=".$parser->word()."\n";
		echo "$parser->nl level=".$parser->word()."\n";
		echo "$parser->nl contributionExp=".$parser->long()."\n";
		echo "$parser->nl currentState=".$parser->long()."\n";
		echo "$parser->nl positionID=".$parser->long()."\n";
		echo "$parser->nl intro=".$parser->string(50)."\n";
		echo "$parser->nl charname=".$parser->string(24)."\n";
}

// packet 0x183
function PACKET_CZ_REQ_DELETE_RELATED_GUILD($parser) {
	echo "$parser->packet_desc OpponentGDID=".$parser->long()."\n";
	echo "$parser->nl Relation=".$parser->long()."\n";
}

// packet 0x184
function PACKET_ZC_DELETE_RELATED_GUILD($parser) {
	echo "$parser->packet_desc OpponentGDID=".$parser->long()."\n";
	echo "$parser->nl Relation=".$parser->long()."\n";
}

// packet 0x185
function PACKET_ZC_ADD_RELATED_GUILD($parser) {
	echo "$parser->packet_desc ";
		echo "$parser->nl relation=".$parser->long()."\n";
		echo "$parser->nl GDID=".$parser->long()."\n";
		echo "$parser->nl guildname=".$parser->string(24)."\n";
}

// packet 0x186
function PACKET_COLLECTORDEAD($parser) {
	echo "$parser->packet_desc ServerID=".$parser->long()."\n";
}

// packet 0x187
function PACKET_PING($parser) {
	echo "$parser->packet_desc AID=".$parser->long()."\n";
}

// packet 0x188
function PACKET_ZC_ACK_ITEMREFINING($parser) {
	echo "$parser->packet_desc result=".$parser->word()."\n";
	echo "$parser->nl itemIndex=".$parser->word()."\n";
	echo "$parser->nl refiningLevel=".$parser->word()."\n";
}

// packet 0x189
function PACKET_ZC_NOTIFY_MAPINFO($parser) {
	echo "$parser->packet_desc type=".$parser->word()."\n";
}

// packet 0x18a
function PACKET_CZ_REQ_DISCONNECT($parser) {
	echo "$parser->packet_desc type=".$parser->word()."\n";
}

// packet 0x18b
function PACKET_ZC_ACK_REQ_DISCONNECT($parser) {
	echo "$parser->packet_desc result=".$parser->word()."\n";
}

// packet 0x18c
function PACKET_ZC_MONSTER_INFO($parser) {
	echo "$parser->packet_desc job=".$parser->word()."\n";
	echo "$parser->nl level=".$parser->word()."\n";
	echo "$parser->nl size=".$parser->word()."\n";
	echo "$parser->nl hp=".$parser->long()."\n";
	echo "$parser->nl def=".$parser->word()."\n";
	echo "$parser->nl raceType=".$parser->word()."\n";
	echo "$parser->nl mdefPower=".$parser->word()."\n";
	echo "$parser->nl property=".$parser->word()."\n";
		echo "$parser->nl water=".$parser->byte()."\n";
		echo "$parser->nl earth=".$parser->byte()."\n";
		echo "$parser->nl fire=".$parser->byte()."\n";
		echo "$parser->nl wind=".$parser->byte()."\n";
		echo "$parser->nl poison=".$parser->byte()."\n";
		echo "$parser->nl saint=".$parser->byte()."\n";
		echo "$parser->nl dark=".$parser->byte()."\n";
		echo "$parser->nl mental=".$parser->byte()."\n";
		echo "$parser->nl undead=".$parser->byte()."\n";
}

// packet 0x18d
function PACKET_ZC_MAKABLEITEMLIST($parser) {
	echo "$parser->packet_desc PacketLength=".$parser->word()."\n";
		echo "$parser->nl ITID=".$parser->word()."\n";
		echo "$parser->nl material_ID=".$parser->word()."\n";
}

// packet 0x18e
function PACKET_CZ_REQMAKINGITEM($parser) {
	echo "$parser->packet_desc ";
		echo "$parser->nl ITID=".$parser->word()."\n";
		echo "$parser->nl material_ID=".$parser->word()."\n";
}

// packet 0x18f
function PACKET_ZC_ACK_REQMAKINGITEM($parser) {
	echo "$parser->packet_desc result=".$parser->word()."\n";
	echo "$parser->nl ITID=".$parser->word()."\n";
}

// packet 0x190
function PACKET_CZ_USE_SKILL_TOGROUND_WITHTALKBOX($parser) {
	echo "$parser->packet_desc selectedLevel=".$parser->word()."\n";
	echo "$parser->nl SKID=".$parser->word()."\n";
	echo "$parser->nl xPos=".$parser->word()."\n";
	echo "$parser->nl yPos=".$parser->word()."\n";
	echo "$parser->nl contents=".$parser->string(80)."\n";
}

// packet 0x191
function PACKET_ZC_TALKBOX_CHATCONTENTS($parser) {
	echo "$parser->packet_desc AID=".$parser->long()."\n";
	echo "$parser->nl contents=".$parser->string(80)."\n";
}

// packet 0x192
function PACKET_ZC_UPDATE_MAPINFO($parser) {
	echo "$parser->packet_desc xPos=".$parser->word()."\n";
	echo "$parser->nl yPos=".$parser->word()."\n";
	echo "$parser->nl type=".$parser->word()."\n";
	echo "$parser->nl mapName=".$parser->string(16)."\n";
}

// packet 0x193
function PACKET_CZ_REQNAME_BYGID($parser) {
	echo "$parser->packet_desc GID=".$parser->long()."\n";
}

// packet 0x194
function PACKET_ZC_ACK_REQNAME_BYGID($parser) {
	echo "$parser->packet_desc GID=".$parser->long()."\n";
	echo "$parser->nl CName=".$parser->string(24)."\n";
}

// packet 0x195
function PACKET_ZC_ACK_REQNAMEALL($parser) {
	echo "$parser->packet_desc AID=".$parser->long()."\n";
	echo "$parser->nl CName=".$parser->string(24)."\n";
	echo "$parser->nl PName=".$parser->string(24)."\n";
	echo "$parser->nl GName=".$parser->string(24)."\n";
	echo "$parser->nl RName=".$parser->string(24)."\n";
}

// packet 0x196
function PACKET_ZC_MSG_STATE_CHANGE($parser) {
	echo "$parser->packet_desc index=".$parser->word()."\n";
	echo "$parser->nl AID=".$parser->long()."\n";
	echo "$parser->nl state=".$parser->byte()."\n";
}

// packet 0x197
function PACKET_CZ_RESET($parser) {
	echo "$parser->packet_desc type=".$parser->word()."\n";
}

// packet 0x198
function PACKET_CZ_CHANGE_MAPTYPE($parser) {
	echo "$parser->packet_desc xPos=".$parser->word()."\n";
	echo "$parser->nl yPos=".$parser->word()."\n";
	echo "$parser->nl type=".$parser->word()."\n";
}

// packet 0x199
function PACKET_ZC_NOTIFY_MAPPROPERTY($parser) {
	echo "$parser->packet_desc type=".$parser->word()."\n";
}

// packet 0x19a
function PACKET_ZC_NOTIFY_RANKING($parser) {
	echo "$parser->packet_desc AID=".$parser->long()."\n";
	echo "$parser->nl ranking=".$parser->long()."\n";
	echo "$parser->nl total=".$parser->long()."\n";
}

// packet 0x19b
function PACKET_ZC_NOTIFY_EFFECT($parser) {
	echo "$parser->packet_desc AID=".$parser->long()."\n";
	echo "$parser->nl effectID=".$parser->long()."\n";
}

// packet 0x19d
function PACKET_CZ_CHANGE_EFFECTSTATE($parser) {
	echo "$parser->packet_desc EffectState=".$parser->long()."\n";
}

// packet 0x19e
function PACKET_ZC_START_CAPTURE($parser) {
	echo "$parser->packet_desc \n";
}

// packet 0x19f
function PACKET_CZ_TRYCAPTURE_MONSTER($parser) {
	echo "$parser->packet_desc targetAID=".$parser->long()."\n";
}

// packet 0x1a0
function PACKET_ZC_TRYCAPTURE_MONSTER($parser) {
	echo "$parser->packet_desc result=".$parser->byte()."\n";
}

// packet 0x1a1
function PACKET_CZ_COMMAND_PET($parser) {
	echo "$parser->packet_desc cSub=".$parser->byte()."\n";
}

// packet 0x1a2
function PACKET_ZC_PROPERTY_PET($parser) {
	echo "$parser->packet_desc szName=".$parser->string(24)."\n";
	echo "$parser->nl bModified=".$parser->byte()."\n";
	echo "$parser->nl nLevel=".$parser->word()."\n";
	echo "$parser->nl nFullness=".$parser->word()."\n";
	echo "$parser->nl nRelationship=".$parser->word()."\n";
	echo "$parser->nl ITID=".$parser->word()."\n";
	echo "$parser->nl job=".$parser->word()."\n";
}

// packet 0x1a3
function PACKET_ZC_FEED_PET($parser) {
	echo "$parser->packet_desc cRet=".$parser->byte()."\n";
	echo "$parser->nl ITID=".$parser->word()."\n";
}

// packet 0x1a4
function PACKET_ZC_CHANGESTATE_PET($parser) {
	echo "$parser->packet_desc type=".$parser->byte()."\n";
	echo "$parser->nl GID=".$parser->long()."\n";
	echo "$parser->nl data=".$parser->long()."\n";
}

// packet 0x1a5
function PACKET_CZ_RENAME_PET($parser) {
	echo "$parser->packet_desc szName=".$parser->string(24)."\n";
}

// packet 0x1a6
function PACKET_ZC_PETEGG_LIST($parser) {
	echo "$parser->packet_desc PacketLength=".$parser->word()."\n";
	$eggList = ($parser->packet_length - $parser->packet_pointer) / 2;
	for ($i = 0; $i < $eggList; $i++) {
		echo "$parser->nl index=".$parser->word()."\n";
	}
}

// packet 0x1a7
function PACKET_CZ_SELECT_PETEGG($parser) {
	echo "$parser->packet_desc index=".$parser->word()."\n";
}

// packet 0x1a8
function PACKET_CZ_PETEGG_INFO($parser) {
	echo "$parser->packet_desc index=".$parser->word()."\n";
}

// packet 0x1a9
function PACKET_CZ_PET_ACT($parser) {
	echo "$parser->packet_desc data=".$parser->long()."\n";
}

// packet 0x1aa
function PACKET_ZC_PET_ACT($parser) {
	echo "$parser->packet_desc GID=".$parser->long()."\n";
	echo "$parser->nl data=".$parser->long()."\n";
}

// packet 0x1ab
function PACKET_ZC_PAR_CHANGE_USER($parser) {
	echo "$parser->packet_desc AID=".$parser->long()."\n";
	echo "$parser->nl varID=".$parser->word()."\n";
	echo "$parser->nl count=".$parser->long()."\n";
}

// packet 0x1ac
function PACKET_ZC_SKILL_UPDATE($parser) {
	echo "$parser->packet_desc AID=".$parser->long()."\n";
}

// packet 0x1ad
function PACKET_ZC_MAKINGARROW_LIST($parser) {
	echo "$parser->packet_desc PacketLength=".$parser->word()."\n";
	$arrowList = ($parser->packet_length - $parser->packet_pointer) / 2;
	for ($i = 0; $i < $arrowList; $i++) {
		echo "$parser->nl index=".$parser->word()."\n";
	}
}

// packet 0x1ae
function PACKET_CZ_REQ_MAKINGARROW($parser) {
	echo "$parser->packet_desc id=".$parser->word()."\n";
}

// packet 0x1af
function PACKET_CZ_REQ_CHANGECART($parser) {
	echo "$parser->packet_desc num=".$parser->word()."\n";
}

// packet 0x1b0
function PACKET_ZC_NPCSPRITE_CHANGE($parser) {
	echo "$parser->packet_desc GID=".$parser->long()."\n";
	echo "$parser->nl type=".$parser->byte()."\n";
	echo "$parser->nl value=".$parser->long()."\n";
}

// packet 0x1b1
function PACKET_ZC_SHOWDIGIT($parser) {
	echo "$parser->packet_desc type=".$parser->byte()."\n";
	echo "$parser->nl value=".$parser->long()."\n";
}

// packet 0x1b2
function PACKET_CZ_REQ_OPENSTORE2($parser) {
	echo "$parser->packet_desc PacketLength=".$parser->word()."\n";
	echo "$parser->nl storeName=".$parser->string(80)."\n";
	echo "$parser->nl result=".$parser->byte()."\n";
	$storeList = ($parser->packet_length - $parser->packet_pointer) / 8;
	for ($i = 0; $i < $storeList; $i++) {
		echo "$parser->nl index=".$parser->word()."\n";
		echo "$parser->nl count=".$parser->word()."\n";
		echo "$parser->nl Price=".$parser->long()."\n";
	}
}

// packet 0x1b3
function PACKET_ZC_SHOW_IMAGE2($parser) {
	echo "$parser->packet_desc imageName=".$parser->string(64)."\n";
	echo "$parser->nl type=".$parser->byte()."\n";
}

// packet 0x1b4
function PACKET_ZC_CHANGE_GUILD($parser) {
	echo "$parser->packet_desc AID=".$parser->long()."\n";
	echo "$parser->nl GDID=".$parser->long()."\n";
	echo "$parser->nl emblemVersion=".$parser->word()."\n";
}

// packet 0x1b5
function PACKET_SC_BILLING_INFO($parser) {
	echo "$parser->packet_desc dwAmountRemain=".$parser->long()."\n";
	echo "$parser->nl dwQuantityRemain=".$parser->long()."\n";
	echo "$parser->nl dwReserved1=".$parser->long()."\n";
	echo "$parser->nl dwReserved2=".$parser->long()."\n";
}

// packet 0x1b6
function PACKET_ZC_GUILD_INFO2($parser) {
	echo "$parser->packet_desc GDID=".$parser->long()."\n";
	echo "$parser->nl level=".$parser->long()."\n";
	echo "$parser->nl userNum=".$parser->long()."\n";
	echo "$parser->nl maxUserNum=".$parser->long()."\n";
	echo "$parser->nl userAverageLevel=".$parser->long()."\n";
	echo "$parser->nl exp=".$parser->long()."\n";
	echo "$parser->nl maxExp=".$parser->long()."\n";
	echo "$parser->nl point=".$parser->long()."\n";
	echo "$parser->nl honor=".$parser->long()."\n";
	echo "$parser->nl virtue=".$parser->long()."\n";
	echo "$parser->nl emblemVersion=".$parser->long()."\n";
	echo "$parser->nl guildname=".$parser->string(24)."\n";
	echo "$parser->nl masterName=".$parser->string(24)."\n";
	echo "$parser->nl manageLand=".$parser->string(16)."\n";
	echo "$parser->nl zeny=".$parser->long()."\n";
}

// packet 0x1b7
function PACKET_CZ_GUILD_ZENY($parser) {
	echo "$parser->packet_desc zeny=".$parser->long()."\n";
}

// packet 0x1b8
function PACKET_ZC_GUILD_ZENY_ACK($parser) {
	echo "$parser->packet_desc ret=".$parser->byte()."\n";
}

// packet 0x1b9
function PACKET_ZC_DISPEL($parser) {
	echo "$parser->packet_desc AID=".$parser->long()."\n";
}

// packet 0x1ba
function PACKET_CZ_REMOVE_AID($parser) {
	echo "$parser->packet_desc AccountName=".$parser->string(24)."\n";
}

// packet 0x1bb
function PACKET_CZ_SHIFT($parser) {
	echo "$parser->packet_desc CharacterName=".$parser->string(24)."\n";
}

// packet 0x1bc
function PACKET_CZ_RECALL($parser) {
	echo "$parser->packet_desc AccountName=".$parser->string(24)."\n";
}

// packet 0x1bd
function PACKET_CZ_RECALL_GID($parser) {
	echo "$parser->packet_desc CharacterName=".$parser->string(24)."\n";
}

// packet 0x1be
function PACKET_AC_ASK_PNGAMEROOM($parser) {
	echo "$parser->packet_desc \n";
}

// packet 0x1bf
function PACKET_CA_REPLY_PNGAMEROOM($parser) {
	echo "$parser->packet_desc Permission=".$parser->byte()."\n";
}

// packet 0x1c0
function PACKET_CZ_REQ_REMAINTIME($parser) {
	echo "$parser->packet_desc \n";
}

// packet 0x1c1
function PACKET_ZC_REPLY_REMAINTIME($parser) {
	echo "$parser->packet_desc Result=".$parser->long()."\n";
	echo "$parser->nl ExpirationDate=".$parser->long()."\n";
	echo "$parser->nl RemainTime=".$parser->long()."\n";
}

// packet 0x1c2
function PACKET_ZC_INFO_REMAINTIME($parser) {
	echo "$parser->packet_desc Type=".$parser->long()."\n";
	echo "$parser->nl RemainTime=".$parser->long()."\n";
}

// packet 0x1c3
function PACKET_ZC_BROADCAST2($parser) {
	echo "$parser->packet_desc PacketLength=".$parser->word()."\n";
	echo "$parser->nl fontColor=".$parser->long()."\n";
	echo "$parser->nl fontType=".$parser->word()."\n";
	echo "$parser->nl fontSize=".$parser->word()."\n";
	echo "$parser->nl fontAlign=".$parser->word()."\n";
	echo "$parser->nl fontY=".$parser->word()."\n";
	echo "$parser->nl msg=".$parser->string($parser->packet_length - $parser->packet_pointer)."\n";
}

// packet 0x1c4
function PACKET_ZC_ADD_ITEM_TO_STORE2($parser) {
	echo "$parser->packet_desc index=".$parser->word()."\n";
	echo "$parser->nl count=".$parser->long()."\n";
	echo "$parser->nl ITID=".$parser->word()."\n";
	echo "$parser->nl type=".$parser->byte()."\n";
	echo "$parser->nl IsIdentified=".$parser->byte()."\n";
	echo "$parser->nl IsDamaged=".$parser->byte()."\n";
	echo "$parser->nl refiningLevel=".$parser->byte()."\n";
		echo "$parser->nl card1=".$parser->word()."\n";
		echo "$parser->nl card2=".$parser->word()."\n";
		echo "$parser->nl card3=".$parser->word()."\n";
		echo "$parser->nl card4=".$parser->word()."\n";
}

// packet 0x1c5
function PACKET_ZC_ADD_ITEM_TO_CART2($parser) {
	echo "$parser->packet_desc index=".$parser->word()."\n";
	echo "$parser->nl count=".$parser->long()."\n";
	echo "$parser->nl ITID=".$parser->word()."\n";
	echo "$parser->nl type=".$parser->byte()."\n";
	echo "$parser->nl IsIdentified=".$parser->byte()."\n";
	echo "$parser->nl IsDamaged=".$parser->byte()."\n";
	echo "$parser->nl refiningLevel=".$parser->byte()."\n";
		echo "$parser->nl card1=".$parser->word()."\n";
		echo "$parser->nl card2=".$parser->word()."\n";
		echo "$parser->nl card3=".$parser->word()."\n";
		echo "$parser->nl card4=".$parser->word()."\n";
}

// packet 0x1c6
function PACKET_CS_REQ_ENCRYPTION($parser) {
	echo "$parser->packet_desc encCount=".$parser->byte()."\n";
	echo "$parser->nl decCount=".$parser->byte()."\n";
}

// packet 0x1c7
function PACKET_SC_ACK_ENCRYPTION($parser) {
	echo "$parser->packet_desc \n";
}

// packet 0x1c8
function PACKET_ZC_USE_ITEM_ACK2($parser) {
	echo "$parser->packet_desc index=".$parser->word()."\n";
	echo "$parser->nl id=".$parser->word()."\n";
	echo "$parser->nl AID=".$parser->long()."\n";
	echo "$parser->nl count=".$parser->word()."\n";
	echo "$parser->nl result=".$parser->byte()."\n";
}

// packet 0x1c9
function PACKET_ZC_SKILL_ENTRY2($parser) {
	echo "$parser->packet_desc AID=".$parser->long()."\n";
	echo "$parser->nl creatorAID=".$parser->long()."\n";
	echo "$parser->nl xPos=".$parser->word()."\n";
	echo "$parser->nl yPos=".$parser->word()."\n";
	echo "$parser->nl job=".$parser->byte()."\n";
	echo "$parser->nl isVisible=".$parser->byte()."\n";
	echo "$parser->nl isContens=".$parser->byte()."\n";
	echo "$parser->nl msg=".$parser->string(80)."\n";
}

// packet 0x1ca
function PACKET_CZ_REQMAKINGHOMUN($parser) {
	echo "$parser->packet_desc result=".$parser->byte()."\n";
}

// packet 0x1cb
function PACKET_CZ_MONSTER_TALK($parser) {
	echo "$parser->packet_desc GID=".$parser->long()."\n";
	echo "$parser->nl stateId=".$parser->byte()."\n";
	echo "$parser->nl skillId=".$parser->byte()."\n";
	echo "$parser->nl arg1=".$parser->byte()."\n";
}

// packet 0x1cc
function PACKET_ZC_MONSTER_TALK($parser) {
	echo "$parser->packet_desc GID=".$parser->long()."\n";
	echo "$parser->nl stateId=".$parser->byte()."\n";
	echo "$parser->nl skillId=".$parser->byte()."\n";
	echo "$parser->nl arg1=".$parser->byte()."\n";
}

// packet 0x1cd
function PACKET_ZC_AUTOSPELLLIST($parser) {
	echo "$parser->packet_desc SKID=".$parser->long()."\n";
}

// packet 0x1ce
function PACKET_CZ_SELECTAUTOSPELL($parser) {
	echo "$parser->packet_desc SKID=".$parser->long()."\n";
}

// packet 0x1cf
function PACKET_ZC_DEVOTIONLIST($parser) {
	echo "$parser->packet_desc myAID=".$parser->long()."\n";
	echo "$parser->nl AID=".$parser->long()."\n";
	echo "$parser->nl range=".$parser->word()."\n";
}

// packet 0x1d0
function PACKET_ZC_SPIRITS($parser) {
	echo "$parser->packet_desc AID=".$parser->long()."\n";
	echo "$parser->nl num=".$parser->word()."\n";
}

// packet 0x1d1
function PACKET_ZC_BLADESTOP($parser) {
	echo "$parser->packet_desc srcAID=".$parser->long()."\n";
	echo "$parser->nl destAID=".$parser->long()."\n";
	echo "$parser->nl flag=".$parser->long()."\n";
}

// packet 0x1d2
function PACKET_ZC_COMBODELAY($parser) {
	echo "$parser->packet_desc AID=".$parser->long()."\n";
	echo "$parser->nl delayTime=".$parser->long()."\n";
}

// packet 0x1d3
function PACKET_ZC_SOUND($parser) {
	echo "$parser->packet_desc fileName=".$parser->string(24)."\n";
	echo "$parser->nl act=".$parser->byte()."\n";
	echo "$parser->nl term=".$parser->long()."\n";
	echo "$parser->nl NAID=".$parser->long()."\n";
}

// packet 0x1d4
function PACKET_ZC_OPEN_EDITDLGSTR($parser) {
	echo "$parser->packet_desc NAID=".$parser->long()."\n";
}

// packet 0x1d5
function PACKET_CZ_INPUT_EDITDLGSTR($parser) {
	echo "$parser->packet_desc PacketLength=".$parser->word()."\n";
	echo "$parser->nl NAID=".$parser->long()."\n";
	echo "$parser->nl msg=".$parser->string($parser->packet_length - $parser->packet_pointer)."\n";
}

// packet 0x1d6
function PACKET_ZC_NOTIFY_MAPPROPERTY2($parser) {
	echo "$parser->packet_desc type=".$parser->word()."\n";
}

// packet 0x1d7
function PACKET_ZC_SPRITE_CHANGE2($parser) {
	echo "$parser->packet_desc GID=".$parser->long()."\n";
	echo "$parser->nl type=".$parser->byte()."\n";
	echo "$parser->nl value=".$parser->long()."\n";
}

// packet 0x1d8
function PACKET_ZC_NOTIFY_STANDENTRY2($parser) {
	echo "$parser->packet_desc GID=".$parser->long()."\n";
	echo "$parser->nl speed=".$parser->word()."\n";
	echo "$parser->nl bodyState=".$parser->word()."\n";
	echo "$parser->nl healthState=".$parser->word()."\n";
	echo "$parser->nl effectState=".$parser->word()."\n";
	echo "$parser->nl job=".$parser->word()."\n";
	echo "$parser->nl head=".$parser->word()."\n";
	echo "$parser->nl weapon=".$parser->long()."\n";
	echo "$parser->nl accessory=".$parser->word()."\n";
	echo "$parser->nl accessory2=".$parser->word()."\n";
	echo "$parser->nl accessory3=".$parser->word()."\n";
	echo "$parser->nl headpalette=".$parser->word()."\n";
	echo "$parser->nl bodypalette=".$parser->word()."\n";
	echo "$parser->nl headDir=".$parser->word()."\n";
	echo "$parser->nl GUID=".$parser->long()."\n";
	echo "$parser->nl GEmblemVer=".$parser->word()."\n";
	echo "$parser->nl honor=".$parser->word()."\n";
	echo "$parser->nl virtue=".$parser->word()."\n";
	echo "$parser->nl isPKModeON=".$parser->byte()."\n";
	echo "$parser->nl sex=".$parser->byte()."\n";
	echo "$parser->nl PosDir=".$parser->xy()."\n";
	echo "$parser->nl xSize=".$parser->byte()."\n";
	echo "$parser->nl ySize=".$parser->byte()."\n";
	echo "$parser->nl state=".$parser->byte()."\n";
	echo "$parser->nl clevel=".$parser->word()."\n";
}

// packet 0x1d9
function PACKET_ZC_NOTIFY_NEWENTRY2($parser) {
	echo "$parser->packet_desc GID=".$parser->long()."\n";
	echo "$parser->nl speed=".$parser->word()."\n";
	echo "$parser->nl bodyState=".$parser->word()."\n";
	echo "$parser->nl healthState=".$parser->word()."\n";
	echo "$parser->nl effectState=".$parser->word()."\n";
	echo "$parser->nl job=".$parser->word()."\n";
	echo "$parser->nl head=".$parser->word()."\n";
	echo "$parser->nl weapon=".$parser->long()."\n";
	echo "$parser->nl accessory=".$parser->word()."\n";
	echo "$parser->nl accessory2=".$parser->word()."\n";
	echo "$parser->nl accessory3=".$parser->word()."\n";
	echo "$parser->nl headpalette=".$parser->word()."\n";
	echo "$parser->nl bodypalette=".$parser->word()."\n";
	echo "$parser->nl headDir=".$parser->word()."\n";
	echo "$parser->nl GUID=".$parser->long()."\n";
	echo "$parser->nl GEmblemVer=".$parser->word()."\n";
	echo "$parser->nl honor=".$parser->word()."\n";
	echo "$parser->nl virtue=".$parser->word()."\n";
	echo "$parser->nl isPKModeON=".$parser->byte()."\n";
	echo "$parser->nl sex=".$parser->byte()."\n";
	echo "$parser->nl PosDir=".$parser->xy()."\n";
	echo "$parser->nl xSize=".$parser->byte()."\n";
	echo "$parser->nl ySize=".$parser->byte()."\n";
	echo "$parser->nl clevel=".$parser->word()."\n";
}

// packet 0x1da
function PACKET_ZC_NOTIFY_MOVEENTRY2($parser) {
	echo "$parser->packet_desc GID=".$parser->long()."\n";
	echo "$parser->nl speed=".$parser->word()."\n";
	echo "$parser->nl bodyState=".$parser->word()."\n";
	echo "$parser->nl healthState=".$parser->word()."\n";
	echo "$parser->nl effectState=".$parser->word()."\n";
	echo "$parser->nl job=".$parser->word()."\n";
	echo "$parser->nl head=".$parser->word()."\n";
	echo "$parser->nl weapon=".$parser->long()."\n";
	echo "$parser->nl accessory=".$parser->word()."\n";
	echo "$parser->nl moveStartTime=".$parser->long()."\n";
	echo "$parser->nl accessory2=".$parser->word()."\n";
	echo "$parser->nl accessory3=".$parser->word()."\n";
	echo "$parser->nl headpalette=".$parser->word()."\n";
	echo "$parser->nl bodypalette=".$parser->word()."\n";
	echo "$parser->nl headDir=".$parser->word()."\n";
	echo "$parser->nl GUID=".$parser->long()."\n";
	echo "$parser->nl GEmblemVer=".$parser->word()."\n";
	echo "$parser->nl honor=".$parser->word()."\n";
	echo "$parser->nl virtue=".$parser->word()."\n";
	echo "$parser->nl isPKModeON=".$parser->byte()."\n";
	echo "$parser->nl sex=".$parser->byte()."\n";
	echo "$parser->nl MoveData=".$parser->xyxy()."\n";
	echo "$parser->nl xSize=".$parser->byte()."\n";
	echo "$parser->nl ySize=".$parser->byte()."\n";
	echo "$parser->nl clevel=".$parser->word()."\n";
}

// packet 0x1db
function PACKET_CA_REQ_HASH($parser) {
	echo "$parser->packet_desc \n";
}

// packet 0x1dc
function PACKET_AC_ACK_HASH($parser) {
	echo "$parser->packet_desc PacketLength=".$parser->word()."\n";
	echo "$parser->nl secret=".$parser->string($parser->packet_length - $parser->packet_pointer)."\n";
}

// packet 0x1dd
function PACKET_CA_LOGIN2($parser) {
	echo "$parser->packet_desc Version=".$parser->long()."\n";
	echo "$parser->nl ID=".$parser->string(24)."\n";
	echo "$parser->nl PasswdMD5=".$parser->string(16)."\n";
	echo "$parser->nl clienttype=".$parser->byte()."\n";
}

// packet 0x1de
function PACKET_ZC_NOTIFY_SKILL2($parser) {
	echo "$parser->packet_desc SKID=".$parser->word()."\n";
	echo "$parser->nl AID=".$parser->long()."\n";
	echo "$parser->nl targetID=".$parser->long()."\n";
	echo "$parser->nl startTime=".$parser->long()."\n";
	echo "$parser->nl attackMT=".$parser->long()."\n";
	echo "$parser->nl attackedMT=".$parser->long()."\n";
	echo "$parser->nl damage=".$parser->long()."\n";
	echo "$parser->nl level=".$parser->word()."\n";
	echo "$parser->nl count=".$parser->word()."\n";
	echo "$parser->nl action=".$parser->byte()."\n";
}

// packet 0x1df
function PACKET_CZ_REQ_ACCOUNTNAME($parser) {
	echo "$parser->packet_desc AID=".$parser->long()."\n";
}

// packet 0x1e0
function PACKET_ZC_ACK_ACCOUNTNAME($parser) {
	echo "$parser->packet_desc AID=".$parser->long()."\n";
	echo "$parser->nl name=".$parser->string(24)."\n";
}

// packet 0x1e1
function PACKET_ZC_SPIRITS2($parser) {
	echo "$parser->packet_desc AID=".$parser->long()."\n";
	echo "$parser->nl num=".$parser->word()."\n";
}

// packet 0x1e2
function PACKET_ZC_REQ_COUPLE($parser) {
	echo "$parser->packet_desc AID=".$parser->long()."\n";
	echo "$parser->nl GID=".$parser->long()."\n";
	echo "$parser->nl name=".$parser->string(24)."\n";
}

// packet 0x1e3
function PACKET_CZ_JOIN_COUPLE($parser) {
	echo "$parser->packet_desc AID=".$parser->long()."\n";
	echo "$parser->nl GID=".$parser->long()."\n";
	echo "$parser->nl answer=".$parser->long()."\n";
}

// packet 0x1e4
function PACKET_ZC_START_COUPLE($parser) {
	echo "$parser->packet_desc \n";
}

// packet 0x1e5
function PACKET_CZ_REQ_JOIN_COUPLE($parser) {
	echo "$parser->packet_desc AID=".$parser->long()."\n";
}

// packet 0x1e6
function PACKET_ZC_COUPLENAME($parser) {
	echo "$parser->packet_desc CoupleName=".$parser->string(24)."\n";
}

// packet 0x1e7
function PACKET_CZ_DORIDORI($parser) {
	echo "$parser->packet_desc \n";
}

// packet 0x1e8
function PACKET_CZ_MAKE_GROUP2($parser) {
	echo "$parser->packet_desc groupName=".$parser->string(24)."\n";
	echo "$parser->nl ItemPickupRule=".$parser->byte()."\n";
	echo "$parser->nl ItemDivisionRule=".$parser->byte()."\n";
}

// packet 0x1e9
function PACKET_ZC_ADD_MEMBER_TO_GROUP2($parser) {
	echo "$parser->packet_desc AID=".$parser->long()."\n";
	echo "$parser->nl Role=".$parser->long()."\n";
	echo "$parser->nl xPos=".$parser->word()."\n";
	echo "$parser->nl yPos=".$parser->word()."\n";
	echo "$parser->nl state=".$parser->byte()."\n";
	echo "$parser->nl groupName=".$parser->string(24)."\n";
	echo "$parser->nl characterName=".$parser->string(24)."\n";
	echo "$parser->nl mapName=".$parser->string(16)."\n";
	echo "$parser->nl ItemPickupRule=".$parser->byte()."\n";
	echo "$parser->nl ItemDivisionRule=".$parser->byte()."\n";
}

// packet 0x1ea
function PACKET_ZC_CONGRATULATION($parser) {
	echo "$parser->packet_desc AID=".$parser->long()."\n";
}

// packet 0x1eb
function PACKET_ZC_NOTIFY_POSITION_TO_GUILDM($parser) {
	echo "$parser->packet_desc AID=".$parser->long()."\n";
	echo "$parser->nl xPos=".$parser->word()."\n";
	echo "$parser->nl yPos=".$parser->word()."\n";
}

// packet 0x1ec
function PACKET_ZC_GUILD_MEMBER_MAP_CHANGE($parser) {
	echo "$parser->packet_desc GDID=".$parser->long()."\n";
	echo "$parser->nl AID=".$parser->long()."\n";
	echo "$parser->nl mapName=".$parser->string(16)."\n";
}

// packet 0x1ed
function PACKET_CZ_CHOPOKGI($parser) {
	echo "$parser->packet_desc \n";
}

// packet 0x1ee
function PACKET_ZC_NORMAL_ITEMLIST2($parser) {
	echo "$parser->packet_desc PacketLength=".$parser->word()."\n";
	$ItemInfo = ($parser->packet_length - $parser->packet_pointer) / 18;
	for ($i = 0; $i < $ItemInfo; $i++) {
		echo "$parser->nl index=".$parser->word()."\n";
		echo "$parser->nl ITID=".$parser->word()."\n";
		echo "$parser->nl type=".$parser->byte()."\n";
		echo "$parser->nl IsIdentified=".$parser->byte()."\n";
		echo "$parser->nl count=".$parser->word()."\n";
		echo "$parser->nl WearState=".$parser->word()."\n";
		echo "$parser->nl card1=".$parser->word()."\n";
		echo "$parser->nl card2=".$parser->word()."\n";
		echo "$parser->nl card3=".$parser->word()."\n";
		echo "$parser->nl card4=".$parser->word()."\n";
	}
}

// packet 0x1ef
function PACKET_ZC_CART_NORMAL_ITEMLIST2($parser) {
	echo "$parser->packet_desc PacketLength=".$parser->word()."\n";
	$ItemInfo = ($parser->packet_length - $parser->packet_pointer) / 18;
	for ($i = 0; $i < $ItemInfo; $i++) {
		echo "$parser->nl index=".$parser->word()."\n";
		echo "$parser->nl ITID=".$parser->word()."\n";
		echo "$parser->nl type=".$parser->byte()."\n";
		echo "$parser->nl IsIdentified=".$parser->byte()."\n";
		echo "$parser->nl count=".$parser->word()."\n";
		echo "$parser->nl WearState=".$parser->word()."\n";
		echo "$parser->nl card1=".$parser->word()."\n";
		echo "$parser->nl card2=".$parser->word()."\n";
		echo "$parser->nl card3=".$parser->word()."\n";
		echo "$parser->nl card4=".$parser->word()."\n";
	}
}

// packet 0x1f0
function PACKET_ZC_STORE_NORMAL_ITEMLIST2($parser) {
	echo "$parser->packet_desc PacketLength=".$parser->word()."\n";
	$ItemInfo = ($parser->packet_length - $parser->packet_pointer) / 18;
	for ($i = 0; $i < $ItemInfo; $i++) {
		echo "$parser->nl index=".$parser->word()."\n";
		echo "$parser->nl ITID=".$parser->word()."\n";
		echo "$parser->nl type=".$parser->byte()."\n";
		echo "$parser->nl IsIdentified=".$parser->byte()."\n";
		echo "$parser->nl count=".$parser->word()."\n";
		echo "$parser->nl WearState=".$parser->word()."\n";
		echo "$parser->nl card1=".$parser->word()."\n";
		echo "$parser->nl card2=".$parser->word()."\n";
		echo "$parser->nl card3=".$parser->word()."\n";
		echo "$parser->nl card4=".$parser->word()."\n";
	}
}

// packet 0x1f1
function PACKET_AC_NOTIFY_ERROR($parser) {
	echo "$parser->packet_desc PacketLength=".$parser->word()."\n";
	echo "$parser->nl msg=".$parser->string($parser->packet_length - $parser->packet_pointer)."\n";
}

// packet 0x1f2
function PACKET_ZC_UPDATE_CHARSTAT2($parser) {
	echo "$parser->packet_desc AID=".$parser->long()."\n";
	echo "$parser->nl GID=".$parser->long()."\n";
	echo "$parser->nl status=".$parser->long()."\n";
	echo "$parser->nl sex=".$parser->word()."\n";
	echo "$parser->nl head=".$parser->word()."\n";
	echo "$parser->nl headPalette=".$parser->word()."\n";
}

// packet 0x1f3
function PACKET_ZC_NOTIFY_EFFECT2($parser) {
	echo "$parser->packet_desc AID=".$parser->long()."\n";
	echo "$parser->nl effectID=".$parser->long()."\n";
}

// packet 0x1f4
function PACKET_ZC_REQ_EXCHANGE_ITEM2($parser) {
	echo "$parser->packet_desc name=".$parser->string(24)."\n";
	echo "$parser->nl GID=".$parser->long()."\n";
	echo "$parser->nl level=".$parser->word()."\n";
}

// packet 0x1f5
function PACKET_ZC_ACK_EXCHANGE_ITEM2($parser) {
	echo "$parser->packet_desc result=".$parser->byte()."\n";
	echo "$parser->nl GID=".$parser->long()."\n";
	echo "$parser->nl level=".$parser->word()."\n";
}

// packet 0x1f6
function PACKET_ZC_REQ_BABY($parser) {
	echo "$parser->packet_desc AID=".$parser->long()."\n";
	echo "$parser->nl GID=".$parser->long()."\n";
	echo "$parser->nl name=".$parser->string(24)."\n";
}

// packet 0x1f7
function PACKET_CZ_JOIN_BABY($parser) {
	echo "$parser->packet_desc AID=".$parser->long()."\n";
	echo "$parser->nl GID=".$parser->long()."\n";
	echo "$parser->nl answer=".$parser->long()."\n";
}

// packet 0x1f8
function PACKET_ZC_START_BABY($parser) {
	echo "$parser->packet_desc \n";
}

// packet 0x1f9
function PACKET_CZ_REQ_JOIN_BABY($parser) {
	echo "$parser->packet_desc AID=".$parser->long()."\n";
}

// packet 0x1fa
function PACKET_CA_LOGIN3($parser) {
	echo "$parser->packet_desc Version=".$parser->long()."\n";
	echo "$parser->nl ID=".$parser->string(24)."\n";
	echo "$parser->nl PasswdMD5=".$parser->string(16)."\n";
	echo "$parser->nl clienttype=".$parser->byte()."\n";
	echo "$parser->nl ClientInfo=".$parser->byte()."\n";
}

// packet 0x1fb
function PACKET_CH_DELETE_CHAR2($parser) {
	echo "$parser->packet_desc GID=".$parser->long()."\n";
	echo "$parser->nl key=".$parser->string(50)."\n";
}

// packet 0x1fc
function PACKET_ZC_REPAIRITEMLIST($parser) {
	echo "$parser->packet_desc PacketLength=".$parser->word()."\n";
	$itemList = ($parser->packet_length - $parser->packet_pointer) / 13;
	for ($i = 0; $i < $itemList; $i++) {
		echo "$parser->nl index=".$parser->word()."\n";
		echo "$parser->nl ITID=".$parser->word()."\n";
		echo "$parser->nl refiningLevel=".$parser->byte()."\n";
		echo "$parser->nl card1=".$parser->word()."\n";
		echo "$parser->nl card2=".$parser->word()."\n";
		echo "$parser->nl card3=".$parser->word()."\n";
		echo "$parser->nl card4=".$parser->word()."\n";
	}
}

// packet 0x1fd
function PACKET_CZ_REQ_ITEMREPAIR($parser) {
	echo "$parser->packet_desc ";
		echo "$parser->nl index=".$parser->word()."\n";
		echo "$parser->nl ITID=".$parser->word()."\n";
		echo "$parser->nl refiningLevel=".$parser->byte()."\n";
		echo "$parser->nl card1=".$parser->word()."\n";
		echo "$parser->nl card2=".$parser->word()."\n";
		echo "$parser->nl card3=".$parser->word()."\n";
		echo "$parser->nl card4=".$parser->word()."\n";
}

// packet 0x1fe
function PACKET_ZC_ACK_ITEMREPAIR($parser) {
	echo "$parser->packet_desc index=".$parser->word()."\n";
	echo "$parser->nl result=".$parser->byte()."\n";
}

// packet 0x1ff
function PACKET_ZC_HIGHJUMP($parser) {
	echo "$parser->packet_desc AID=".$parser->long()."\n";
	echo "$parser->nl xPos=".$parser->word()."\n";
	echo "$parser->nl yPos=".$parser->word()."\n";
}

// packet 0x200
function PACKET_CA_CONNECT_INFO_CHANGED($parser) {
	echo "$parser->packet_desc ID=".$parser->string(24)."\n";
}

// packet 0x201
function PACKET_ZC_FRIENDS_LIST($parser) {
	echo "$parser->packet_desc PacketLength=".$parser->word()."\n";
	$friendList = ($parser->packet_length - $parser->packet_pointer) / 32;
	for ($i = 0; $i < $friendList; $i++) {
		echo "$parser->nl AID=".$parser->long()."\n";
		echo "$parser->nl GID=".$parser->long()."\n";
		echo "$parser->nl Name=".$parser->string(24)."\n";
	}
}

// packet 0x202
function PACKET_CZ_ADD_FRIENDS($parser) {
	echo "$parser->packet_desc name=".$parser->string(24)."\n";
}

// packet 0x203
function PACKET_CZ_DELETE_FRIENDS($parser) {
	echo "$parser->packet_desc AID=".$parser->long()."\n";
	echo "$parser->nl GID=".$parser->long()."\n";
}

// packet 0x204
function PACKET_CA_EXE_HASHCHECK($parser) {
	echo "$parser->packet_desc HashValue=".$parser->string(16)."\n";
}

// packet 0x205
function PACKET_ZC_DIVORCE($parser) {
	echo "$parser->packet_desc name=".$parser->string(24)."\n";
}

// packet 0x206
function PACKET_ZC_FRIENDS_STATE($parser) {
	echo "$parser->packet_desc AID=".$parser->long()."\n";
	echo "$parser->nl GID=".$parser->long()."\n";
	echo "$parser->nl State=".$parser->byte()."\n";
}

// packet 0x207
function PACKET_ZC_REQ_ADD_FRIENDS($parser) {
	echo "$parser->packet_desc ReqAID=".$parser->long()."\n";
	echo "$parser->nl ReqGID=".$parser->long()."\n";
	echo "$parser->nl Name=".$parser->string(24)."\n";
}

// packet 0x208
function PACKET_CZ_ACK_REQ_ADD_FRIENDS($parser) {
	echo "$parser->packet_desc ReqAID=".$parser->long()."\n";
	echo "$parser->nl ReqGID=".$parser->long()."\n";
	echo "$parser->nl Result=".$parser->long()."\n";
}

// packet 0x209
function PACKET_ZC_ADD_FRIENDS_LIST($parser) {
	echo "$parser->packet_desc Result=".$parser->word()."\n";
	echo "$parser->nl AID=".$parser->long()."\n";
	echo "$parser->nl GID=".$parser->long()."\n";
	echo "$parser->nl Name=".$parser->string(24)."\n";
}

// packet 0x20a
function PACKET_ZC_DELETE_FRIENDS($parser) {
	echo "$parser->packet_desc AID=".$parser->long()."\n";
	echo "$parser->nl GID=".$parser->long()."\n";
}

// packet 0x20b
function PACKET_CH_EXE_HASHCHECK($parser) {
	echo "$parser->packet_desc ClientType=".$parser->byte()."\n";
	echo "$parser->nl HashValue=".$parser->string(16)."\n";
}

// packet 0x20c
function PACKET_CZ_EXE_HASHCHECK($parser) {
	echo "$parser->packet_desc ClientType=".$parser->byte()."\n";
	echo "$parser->nl HashValue=".$parser->string(16)."\n";
}

// packet 0x20d
function PACKET_HC_BLOCK_CHARACTER($parser) {
	echo "$parser->packet_desc PacketLength=".$parser->word()."\n";
	$characterList = ($parser->packet_length - $parser->packet_pointer) / 24;
	for ($i = 0; $i < $characterList; $i++) {
		echo "$parser->nl GID=".$parser->long()."\n";
		echo "$parser->nl szExpireDate=".$parser->string(20)."\n";
	}
}

// packet 0x20e
function PACKET_ZC_STARSKILL($parser) {
	echo "$parser->packet_desc mapName=".$parser->string(24)."\n";
	echo "$parser->nl monsterID=".$parser->long()."\n";
	echo "$parser->nl star=".$parser->byte()."\n";
	echo "$parser->nl result=".$parser->byte()."\n";
}

// packet 0x20f
function PACKET_CZ_REQ_PVPPOINT($parser) {
	echo "$parser->packet_desc AID=".$parser->long()."\n";
	echo "$parser->nl GID=".$parser->long()."\n";
}

// packet 0x210
function PACKET_ZC_ACK_PVPPOINT($parser) {
	echo "$parser->packet_desc AID=".$parser->long()."\n";
	echo "$parser->nl GID=".$parser->long()."\n";
		echo "$parser->nl WinPoint=".$parser->long()."\n";
		echo "$parser->nl LosePoint=".$parser->long()."\n";
		echo "$parser->nl Point=".$parser->long()."\n";
}

// packet 0x211
function PACKET_ZH_MOVE_PVPWORLD($parser) {
	echo "$parser->packet_desc GID=".$parser->long()."\n";
}

// packet 0x212
function PACKET_CZ_REQ_GIVE_MANNER_BYNAME($parser) {
	echo "$parser->packet_desc CharName=".$parser->string(24)."\n";
}

// packet 0x213
function PACKET_CZ_REQ_STATUS_GM($parser) {
	echo "$parser->packet_desc CharName=".$parser->string(24)."\n";
}

// packet 0x214
function PACKET_ZC_ACK_STATUS_GM($parser) {
	echo "$parser->packet_desc str=".$parser->byte()."\n";
	echo "$parser->nl standardStr=".$parser->byte()."\n";
	echo "$parser->nl agi=".$parser->byte()."\n";
	echo "$parser->nl standardAgi=".$parser->byte()."\n";
	echo "$parser->nl vit=".$parser->byte()."\n";
	echo "$parser->nl standardVit=".$parser->byte()."\n";
	echo "$parser->nl Int=".$parser->byte()."\n";
	echo "$parser->nl standardInt=".$parser->byte()."\n";
	echo "$parser->nl dex=".$parser->byte()."\n";
	echo "$parser->nl standardDex=".$parser->byte()."\n";
	echo "$parser->nl luk=".$parser->byte()."\n";
	echo "$parser->nl standardLuk=".$parser->byte()."\n";
	echo "$parser->nl attPower=".$parser->word()."\n";
	echo "$parser->nl refiningPower=".$parser->word()."\n";
	echo "$parser->nl max_mattPower=".$parser->word()."\n";
	echo "$parser->nl min_mattPower=".$parser->word()."\n";
	echo "$parser->nl itemdefPower=".$parser->word()."\n";
	echo "$parser->nl plusdefPower=".$parser->word()."\n";
	echo "$parser->nl mdefPower=".$parser->word()."\n";
	echo "$parser->nl plusmdefPower=".$parser->word()."\n";
	echo "$parser->nl hitSuccessValue=".$parser->word()."\n";
	echo "$parser->nl avoidSuccessValue=".$parser->word()."\n";
	echo "$parser->nl plusAvoidSuccessValue=".$parser->word()."\n";
	echo "$parser->nl criticalSuccessValue=".$parser->word()."\n";
	echo "$parser->nl ASPD=".$parser->word()."\n";
	echo "$parser->nl plusASPD=".$parser->word()."\n";
}

// packet 0x215
function PACKET_ZC_SKILLMSG($parser) {
	echo "$parser->packet_desc MsgNo=".$parser->long()."\n";
}

// packet 0x216
function PACKET_ZC_BABYMSG($parser) {
	echo "$parser->packet_desc MsgNo=".$parser->long()."\n";
}

// packet 0x217
function PACKET_CZ_BLACKSMITH_RANK($parser) {
	echo "$parser->packet_desc \n";
}

// packet 0x218
function PACKET_CZ_ALCHEMIST_RANK($parser) {
	echo "$parser->packet_desc \n";
}

// packet 0x219
function PACKET_ZC_BLACKSMITH_RANK($parser) {
	echo "$parser->packet_desc Name=".$parser->string(24)."\n";
	echo "$parser->nl Point=".$parser->long()."\n";
}

// packet 0x21a
function PACKET_ZC_ALCHEMIST_RANK($parser) {
	echo "$parser->packet_desc Name=".$parser->string(24)."\n";
	echo "$parser->nl Point=".$parser->long()."\n";
}

// packet 0x21b
function PACKET_ZC_BLACKSMITH_POINT($parser) {
	echo "$parser->packet_desc Point=".$parser->long()."\n";
	echo "$parser->nl TotalPoint=".$parser->long()."\n";
}

// packet 0x21c
function PACKET_ZC_ALCHEMIST_POINT($parser) {
	echo "$parser->packet_desc Point=".$parser->long()."\n";
	echo "$parser->nl TotalPoint=".$parser->long()."\n";
}

// packet 0x21d
function PACKET_CZ_LESSEFFECT($parser) {
	echo "$parser->packet_desc isLess=".$parser->long()."\n";
}

// packet 0x21e
function PACKET_ZC_LESSEFFECT($parser) {
	echo "$parser->packet_desc isLess=".$parser->long()."\n";
}

// packet 0x21f
function PACKET_ZC_NOTIFY_PKINFO($parser) {
	echo "$parser->packet_desc winPoint=".$parser->long()."\n";
	echo "$parser->nl losePoint=".$parser->long()."\n";
	echo "$parser->nl killName=".$parser->string(24)."\n";
	echo "$parser->nl killedName=".$parser->string(24)."\n";
		echo "$parser->nl dwLowDateTime=".$parser->long()."\n";
		echo "$parser->nl dwHighDateTime=".$parser->long()."\n";
}

// packet 0x220
function PACKET_ZC_NOTIFY_CRAZYKILLER($parser) {
	echo "$parser->packet_desc AID=".$parser->long()."\n";
	echo "$parser->nl isCrazyKiller=".$parser->long()."\n";
}

// packet 0x221
function PACKET_ZC_NOTIFY_WEAPONITEMLIST($parser) {
	echo "$parser->packet_desc PacketLength=".$parser->word()."\n";
	$itemList = ($parser->packet_length - $parser->packet_pointer) / 13;
	for ($i = 0; $i < $itemList; $i++) {
		echo "$parser->nl index=".$parser->word()."\n";
		echo "$parser->nl ITID=".$parser->word()."\n";
		echo "$parser->nl refiningLevel=".$parser->byte()."\n";
		echo "$parser->nl card1=".$parser->word()."\n";
		echo "$parser->nl card2=".$parser->word()."\n";
		echo "$parser->nl card3=".$parser->word()."\n";
		echo "$parser->nl card4=".$parser->word()."\n";
	}
}

// packet 0x222
function PACKET_CZ_REQ_WEAPONREFINE($parser) {
	echo "$parser->packet_desc Index=".$parser->long()."\n";
}

// packet 0x223
function PACKET_ZC_ACK_WEAPONREFINE($parser) {
	echo "$parser->packet_desc msg=".$parser->long()."\n";
	echo "$parser->nl ITID=".$parser->word()."\n";
}

// packet 0x224
function PACKET_ZC_TAEKWON_POINT($parser) {
	echo "$parser->packet_desc Point=".$parser->long()."\n";
	echo "$parser->nl TotalPoint=".$parser->long()."\n";
}

// packet 0x225
function PACKET_CZ_TAEKWON_RANK($parser) {
	echo "$parser->packet_desc \n";
}

// packet 0x226
function PACKET_ZC_TAEKWON_RANK($parser) {
	echo "$parser->packet_desc Name=".$parser->string(24)."\n";
	echo "$parser->nl Point=".$parser->long()."\n";
}

// packet 0x227
function PACKET_ZC_GAME_GUARD($parser) {
	echo "$parser->packet_desc AuthData=".$parser->long()."\n";
}

// packet 0x228
function PACKET_CZ_ACK_GAME_GUARD($parser) {
	echo "$parser->packet_desc AuthData=".$parser->long()."\n";
}

// packet 0x229
function PACKET_ZC_STATE_CHANGE3($parser) {
	echo "$parser->packet_desc AID=".$parser->long()."\n";
	echo "$parser->nl bodyState=".$parser->word()."\n";
	echo "$parser->nl healthState=".$parser->word()."\n";
	echo "$parser->nl effectState=".$parser->long()."\n";
	echo "$parser->nl isPKModeON=".$parser->byte()."\n";
}

// packet 0x22a
function PACKET_ZC_NOTIFY_STANDENTRY3($parser) {
	echo "$parser->packet_desc GID=".$parser->long()."\n";
	echo "$parser->nl speed=".$parser->word()."\n";
	echo "$parser->nl bodyState=".$parser->word()."\n";
	echo "$parser->nl healthState=".$parser->word()."\n";
	echo "$parser->nl effectState=".$parser->long()."\n";
	echo "$parser->nl job=".$parser->word()."\n";
	echo "$parser->nl head=".$parser->word()."\n";
	echo "$parser->nl weapon=".$parser->long()."\n";
	echo "$parser->nl accessory=".$parser->word()."\n";
	echo "$parser->nl accessory2=".$parser->word()."\n";
	echo "$parser->nl accessory3=".$parser->word()."\n";
	echo "$parser->nl headpalette=".$parser->word()."\n";
	echo "$parser->nl bodypalette=".$parser->word()."\n";
	echo "$parser->nl headDir=".$parser->word()."\n";
	echo "$parser->nl GUID=".$parser->long()."\n";
	echo "$parser->nl GEmblemVer=".$parser->word()."\n";
	echo "$parser->nl honor=".$parser->word()."\n";
	echo "$parser->nl virtue=".$parser->long()."\n";
	echo "$parser->nl isPKModeON=".$parser->byte()."\n";
	echo "$parser->nl sex=".$parser->byte()."\n";
	echo "$parser->nl PosDir=".$parser->xy()."\n";
	echo "$parser->nl xSize=".$parser->byte()."\n";
	echo "$parser->nl ySize=".$parser->byte()."\n";
	echo "$parser->nl state=".$parser->byte()."\n";
	echo "$parser->nl clevel=".$parser->word()."\n";
}

// packet 0x22b
function PACKET_ZC_NOTIFY_NEWENTRY3($parser) {
	echo "$parser->packet_desc GID=".$parser->long()."\n";
	echo "$parser->nl speed=".$parser->word()."\n";
	echo "$parser->nl bodyState=".$parser->word()."\n";
	echo "$parser->nl healthState=".$parser->word()."\n";
	echo "$parser->nl effectState=".$parser->long()."\n";
	echo "$parser->nl job=".$parser->word()."\n";
	echo "$parser->nl head=".$parser->word()."\n";
	echo "$parser->nl weapon=".$parser->long()."\n";
	echo "$parser->nl accessory=".$parser->word()."\n";
	echo "$parser->nl accessory2=".$parser->word()."\n";
	echo "$parser->nl accessory3=".$parser->word()."\n";
	echo "$parser->nl headpalette=".$parser->word()."\n";
	echo "$parser->nl bodypalette=".$parser->word()."\n";
	echo "$parser->nl headDir=".$parser->word()."\n";
	echo "$parser->nl GUID=".$parser->long()."\n";
	echo "$parser->nl GEmblemVer=".$parser->word()."\n";
	echo "$parser->nl honor=".$parser->word()."\n";
	echo "$parser->nl virtue=".$parser->long()."\n";
	echo "$parser->nl isPKModeON=".$parser->byte()."\n";
	echo "$parser->nl sex=".$parser->byte()."\n";
	echo "$parser->nl PosDir=".$parser->xy()."\n";
	echo "$parser->nl xSize=".$parser->byte()."\n";
	echo "$parser->nl ySize=".$parser->byte()."\n";
	echo "$parser->nl clevel=".$parser->word()."\n";
}

// packet 0x22c
function PACKET_ZC_NOTIFY_MOVEENTRY3($parser) {
	echo "$parser->packet_desc objecttype=".$parser->byte()."\n";
	echo "$parser->nl GID=".$parser->long()."\n";
	echo "$parser->nl speed=".$parser->word()."\n";
	echo "$parser->nl bodyState=".$parser->word()."\n";
	echo "$parser->nl healthState=".$parser->word()."\n";
	echo "$parser->nl effectState=".$parser->long()."\n";
	echo "$parser->nl job=".$parser->word()."\n";
	echo "$parser->nl head=".$parser->word()."\n";
	echo "$parser->nl weapon=".$parser->long()."\n";
	echo "$parser->nl accessory=".$parser->word()."\n";
	echo "$parser->nl moveStartTime=".$parser->long()."\n";
	echo "$parser->nl accessory2=".$parser->word()."\n";
	echo "$parser->nl accessory3=".$parser->word()."\n";
	echo "$parser->nl headpalette=".$parser->word()."\n";
	echo "$parser->nl bodypalette=".$parser->word()."\n";
	echo "$parser->nl headDir=".$parser->word()."\n";
	echo "$parser->nl GUID=".$parser->long()."\n";
	echo "$parser->nl GEmblemVer=".$parser->word()."\n";
	echo "$parser->nl honor=".$parser->word()."\n";
	echo "$parser->nl virtue=".$parser->long()."\n";
	echo "$parser->nl isPKModeON=".$parser->byte()."\n";
	echo "$parser->nl sex=".$parser->byte()."\n";
	echo "$parser->nl MoveData=".$parser->xyxy()."\n";
	echo "$parser->nl xSize=".$parser->byte()."\n";
	echo "$parser->nl ySize=".$parser->byte()."\n";
	echo "$parser->nl clevel=".$parser->word()."\n";
}

// packet 0x22d
function PACKET_CZ_COMMAND_MER($parser) {
	echo "$parser->packet_desc type=".$parser->word()."\n";
	echo "$parser->nl command=".$parser->byte()."\n";
}

// packet 0x22e
function PACKET_ZC_PROPERTY_HOMUN($parser) {
	echo "$parser->packet_desc szName=".$parser->string(24)."\n";
	echo "$parser->nl bModified=".$parser->byte()."\n";
	echo "$parser->nl nLevel=".$parser->word()."\n";
	echo "$parser->nl nFullness=".$parser->word()."\n";
	echo "$parser->nl nRelationship=".$parser->word()."\n";
	echo "$parser->nl ITID=".$parser->word()."\n";
	echo "$parser->nl atk=".$parser->word()."\n";
	echo "$parser->nl Matk=".$parser->word()."\n";
	echo "$parser->nl hit=".$parser->word()."\n";
	echo "$parser->nl critical=".$parser->word()."\n";
	echo "$parser->nl def=".$parser->word()."\n";
	echo "$parser->nl Mdef=".$parser->word()."\n";
	echo "$parser->nl flee=".$parser->word()."\n";
	echo "$parser->nl aspd=".$parser->word()."\n";
	echo "$parser->nl hp=".$parser->word()."\n";
	echo "$parser->nl maxHP=".$parser->word()."\n";
	echo "$parser->nl sp=".$parser->word()."\n";
	echo "$parser->nl maxSP=".$parser->word()."\n";
	echo "$parser->nl exp=".$parser->long()."\n";
	echo "$parser->nl maxEXP=".$parser->long()."\n";
	echo "$parser->nl SKPoint=".$parser->word()."\n";
	echo "$parser->nl ATKRange=".$parser->word()."\n";
}

// packet 0x230
function PACKET_ZC_CHANGESTATE_MER($parser) {
	echo "$parser->packet_desc type=".$parser->byte()."\n";
	echo "$parser->nl state=".$parser->byte()."\n";
	echo "$parser->nl GID=".$parser->long()."\n";
	echo "$parser->nl data=".$parser->long()."\n";
}

// packet 0x231
function PACKET_CZ_RENAME_MER($parser) {
	echo "$parser->packet_desc name=".$parser->string(24)."\n";
}

// packet 0x232
function PACKET_CZ_REQUEST_MOVENPC($parser) {
	echo "$parser->packet_desc GID=".$parser->long()."\n";
	echo "$parser->nl dest=".$parser->xy()."\n";
}

// packet 0x233
function PACKET_CZ_REQUEST_ACTNPC($parser) {
	echo "$parser->packet_desc GID=".$parser->long()."\n";
	echo "$parser->nl targetGID=".$parser->long()."\n";
	echo "$parser->nl action=".$parser->byte()."\n";
}

// packet 0x234
function PACKET_CZ_REQUEST_MOVETOOWNER($parser) {
	echo "$parser->packet_desc GID=".$parser->long()."\n";
}

// packet 0x23a
function PACKET_ZC_REQ_STORE_PASSWORD($parser) {
	echo "$parser->packet_desc Info=".$parser->word()."\n";
}

// packet 0x23b
function PACKET_CZ_ACK_STORE_PASSWORD($parser) {
	echo "$parser->packet_desc Type=".$parser->word()."\n";
	echo "$parser->nl Password=".$parser->string(16)."\n";
	echo "$parser->nl NewPassword=".$parser->string(16)."\n";
}

// packet 0x23c
function PACKET_ZC_RESULT_STORE_PASSWORD($parser) {
	echo "$parser->packet_desc Result=".$parser->word()."\n";
	echo "$parser->nl ErrorCount=".$parser->word()."\n";
}

// packet 0x23d
function PACKET_AC_EVENT_RESULT($parser) {
	echo "$parser->packet_desc EventItemCount=".$parser->long()."\n";
}

// packet 0x23e
function PACKET_HC_REQUEST_CHARACTER_PASSWORD($parser) {
	echo "$parser->packet_desc Result=".$parser->word()."\n";
	echo "$parser->nl dummyValue=".$parser->long()."\n";
}

// packet 0x23f
function PACKET_CZ_MAIL_GET_LIST($parser) {
	echo "$parser->packet_desc \n";
}

// packet 0x240
function PACKET_ZC_MAIL_REQ_GET_LIST($parser) {
	echo "$parser->packet_desc PacketLength=".$parser->word()."\n";
	echo "$parser->nl MailNumber=".$parser->long()."\n";
	$mailList = ($parser->packet_length - $parser->packet_pointer) / 73;
	for ($i = 0; $i < $mailList; $i++) {
		echo "$parser->nl MailID=".$parser->long()."\n";
		echo "$parser->nl HEADER=".$parser->string(40)."\n";
		echo "$parser->nl isOpen=".$parser->byte()."\n";
		echo "$parser->nl FromName=".$parser->string(24)."\n";
		echo "$parser->nl DeleteTime=".$parser->long()."\n";
	}
}

// packet 0x241
function PACKET_CZ_MAIL_OPEN($parser) {
	echo "$parser->packet_desc MailID=".$parser->long()."\n";
}

// packet 0x242
function PACKET_ZC_MAIL_REQ_OPEN($parser) {
	echo "$parser->packet_desc PacketLength=".$parser->word()."\n";
	echo "$parser->nl MailID=".$parser->long()."\n";
	echo "$parser->nl Header=".$parser->string(40)."\n";
	echo "$parser->nl FromName=".$parser->string(24)."\n";
	echo "$parser->nl DeleteTime=".$parser->long()."\n";
	echo "$parser->nl Money=".$parser->long()."\n";
	echo "$parser->nl count=".$parser->long()."\n";
	echo "$parser->nl ITID=".$parser->word()."\n";
	echo "$parser->nl Type=".$parser->word()."\n";
	echo "$parser->nl IsIdentified=".$parser->byte()."\n";
	echo "$parser->nl IsDamaged=".$parser->byte()."\n";
	echo "$parser->nl refiningLevel=".$parser->byte()."\n";
		echo "$parser->nl card1=".$parser->word()."\n";
		echo "$parser->nl card2=".$parser->word()."\n";
		echo "$parser->nl card3=".$parser->word()."\n";
		echo "$parser->nl card4=".$parser->word()."\n";
	echo "$parser->nl msg_len=".$parser->byte()."\n";
	echo "$parser->nl msg=".$parser->string($parser->packet_length - $parser->packet_pointer)."\n";
}

// packet 0x243
function PACKET_CZ_MAIL_DELETE($parser) {
	echo "$parser->packet_desc MailID=".$parser->long()."\n";
}

// packet 0x244
function PACKET_CZ_MAIL_GET_ITEM($parser) {
	echo "$parser->packet_desc MailID=".$parser->long()."\n";
}

// packet 0x245
function PACKET_ZC_MAIL_REQ_GET_ITEM($parser) {
	echo "$parser->packet_desc Result=".$parser->byte()."\n";
}

// packet 0x246
function PACKET_CZ_MAIL_RESET_ITEM($parser) {
	echo "$parser->packet_desc Type=".$parser->word()."\n";
}

// packet 0x247
function PACKET_CZ_MAIL_ADD_ITEM($parser) {
	echo "$parser->packet_desc index=".$parser->word()."\n";
	echo "$parser->nl count=".$parser->long()."\n";
}

// packet 0x248
function PACKET_CZ_MAIL_SEND($parser) {
	echo "$parser->packet_desc PacketLength=".$parser->word()."\n";
	echo "$parser->nl ReceiveName=".$parser->string(24)."\n";
	echo "$parser->nl Header=".$parser->string(40)."\n";
	echo "$parser->nl msg_len=".$parser->long()."\n";
	echo "$parser->nl msg=".$parser->string($parser->packet_length - $parser->packet_pointer)."\n";
}

// packet 0x249
function PACKET_ZC_MAIL_REQ_SEND($parser) {
	echo "$parser->packet_desc Result=".$parser->byte()."\n";
}

// packet 0x24a
function PACKET_ZC_MAIL_RECEIVE($parser) {
	echo "$parser->packet_desc MailID=".$parser->long()."\n";
	echo "$parser->nl Header=".$parser->string(40)."\n";
	echo "$parser->nl FromName=".$parser->string(24)."\n";
}

// packet 0x24b
function PACKET_CZ_AUCTION_CREATE($parser) {
	echo "$parser->packet_desc Type=".$parser->word()."\n";
}

// packet 0x24c
function PACKET_CZ_AUCTION_ADD_ITEM($parser) {
	echo "$parser->packet_desc index=".$parser->word()."\n";
	echo "$parser->nl count=".$parser->long()."\n";
}

// packet 0x24d
function PACKET_CZ_AUCTION_ADD($parser) {
	echo "$parser->packet_desc NowMoney=".$parser->long()."\n";
	echo "$parser->nl MaxMoney=".$parser->long()."\n";
	echo "$parser->nl DeleteHour=".$parser->word()."\n";
}

// packet 0x24e
function PACKET_CZ_AUCTION_ADD_CANCEL($parser) {
	echo "$parser->packet_desc AuctionID=".$parser->long()."\n";
}

// packet 0x24f
function PACKET_CZ_AUCTION_BUY($parser) {
	echo "$parser->packet_desc AuctionID=".$parser->long()."\n";
	echo "$parser->nl Money=".$parser->long()."\n";
}

// packet 0x250
function PACKET_ZC_AUCTION_RESULT($parser) {
	echo "$parser->packet_desc Result=".$parser->byte()."\n";
}

// packet 0x251
function PACKET_CZ_AUCTION_ITEM_SEARCH($parser) {
	echo "$parser->packet_desc Type=".$parser->word()."\n";
	echo "$parser->nl AuctionID=".$parser->long()."\n";
	echo "$parser->nl Name=".$parser->string(24)."\n";
	echo "$parser->nl Page=".$parser->word()."\n";
}

// packet 0x252
function PACKET_ZC_AUCTION_ITEM_REQ_SEARCH($parser) {
	echo "$parser->packet_desc PacketLength=".$parser->word()."\n";
	echo "$parser->nl MaxPage=".$parser->long()."\n";
	echo "$parser->nl Number=".$parser->long()."\n";
	$auctionItemList = ($parser->packet_length - $parser->packet_pointer) / 83;
	for ($i = 0; $i < $auctionItemList; $i++) {
		echo "$parser->nl AuctionID=".$parser->long()."\n";
		echo "$parser->nl SellerName=".$parser->string(24)."\n";
		echo "$parser->nl ITID=".$parser->word()."\n";
		echo "$parser->nl Type=".$parser->long()."\n";
		echo "$parser->nl count=".$parser->word()."\n";
		echo "$parser->nl IsIdentified=".$parser->byte()."\n";
		echo "$parser->nl IsDamaged=".$parser->byte()."\n";
		echo "$parser->nl refiningLevel=".$parser->byte()."\n";
		echo "$parser->nl card1=".$parser->word()."\n";
		echo "$parser->nl card2=".$parser->word()."\n";
		echo "$parser->nl card3=".$parser->word()."\n";
		echo "$parser->nl card4=".$parser->word()."\n";
		echo "$parser->nl NowPrice=".$parser->long()."\n";
		echo "$parser->nl MaxPrice=".$parser->long()."\n";
		echo "$parser->nl BuyerName=".$parser->string(24)."\n";
		echo "$parser->nl DeleteTime=".$parser->long()."\n";
	}
}

// packet 0x253
function PACKET_ZC_STARPLACE($parser) {
	echo "$parser->packet_desc which=".$parser->byte()."\n";
}

// packet 0x254
function PACKET_CZ_AGREE_STARPLACE($parser) {
	echo "$parser->packet_desc which=".$parser->byte()."\n";
}

// packet 0x255
function PACKET_ZC_ACK_MAIL_ADD_ITEM($parser) {
	echo "$parser->packet_desc Index=".$parser->word()."\n";
	echo "$parser->nl result=".$parser->byte()."\n";
}

// packet 0x256
function PACKET_ZC_ACK_AUCTION_ADD_ITEM($parser) {
	echo "$parser->packet_desc Index=".$parser->word()."\n";
	echo "$parser->nl result=".$parser->byte()."\n";
}

// packet 0x257
function PACKET_ZC_ACK_MAIL_DELETE($parser) {
	echo "$parser->packet_desc MailID=".$parser->long()."\n";
	echo "$parser->nl Result=".$parser->word()."\n";
}

// packet 0x258
function PACKET_CA_REQ_GAME_GUARD_CHECK($parser) {
	echo "$parser->packet_desc \n";
}

// packet 0x259
function PACKET_AC_ACK_GAME_GUARD($parser) {
	echo "$parser->packet_desc ucAnswer=".$parser->byte()."\n";
}

// packet 0x25a
function PACKET_ZC_MAKINGITEM_LIST($parser) {
	echo "$parser->packet_desc PacketLength=".$parser->word()."\n";
	echo "$parser->nl idList=".$parser->word()."\n";
}

// packet 0x25b
function PACKET_CZ_REQ_MAKINGITEM($parser) {
	echo "$parser->packet_desc mkType=".$parser->word()."\n";
	echo "$parser->nl id=".$parser->word()."\n";
}

// packet 0x25c
function PACKET_CZ_AUCTION_REQ_MY_INFO($parser) {
	echo "$parser->packet_desc Type=".$parser->word()."\n";
}

// packet 0x25d
function PACKET_CZ_AUCTION_REQ_MY_SELL_STOP($parser) {
	echo "$parser->packet_desc AuctionID=".$parser->long()."\n";
}

// packet 0x25e
function PACKET_ZC_AUCTION_ACK_MY_SELL_STOP($parser) {
	echo "$parser->packet_desc Result=".$parser->word()."\n";
}

// packet 0x25f
function PACKET_ZC_AUCTION_WINDOWS($parser) {
	echo "$parser->packet_desc Type=".$parser->long()."\n";
}

// packet 0x260
function PACKET_ZC_MAIL_WINDOWS($parser) {
	echo "$parser->packet_desc Type=".$parser->long()."\n";
}

// packet 0x261
function PACKET_AC_REQ_LOGIN_OLDEKEY($parser) {
	echo "$parser->packet_desc m_SeedValue=".$parser->string(9)."\n";
}

// packet 0x262
function PACKET_AC_REQ_LOGIN_NEWEKEY($parser) {
	echo "$parser->packet_desc m_SeedValue=".$parser->string(9)."\n";
}

// packet 0x263
function PACKET_AC_REQ_LOGIN_CARDPASS($parser) {
	echo "$parser->packet_desc m_SeedValue=".$parser->string(9)."\n";
}

// packet 0x264
function PACKET_CA_ACK_LOGIN_OLDEKEY($parser) {
	echo "$parser->packet_desc m_SeedValue=".$parser->string(9)."\n";
	echo "$parser->nl m_EKey=".$parser->string(9)."\n";
}

// packet 0x265
function PACKET_CA_ACK_LOGIN_NEWEKEY($parser) {
	echo "$parser->packet_desc m_SeedValue=".$parser->string(9)."\n";
	echo "$parser->nl m_EKey=".$parser->string(9)."\n";
}

// packet 0x266
function PACKET_CA_ACK_LOGIN_CARDPASS($parser) {
	echo "$parser->packet_desc m_cardPass=".$parser->string(28)."\n";
}

// packet 0x267
function PACKET_AC_ACK_EKEY_FAIL_NOTEXIST($parser) {
	echo "$parser->packet_desc errorCode=".$parser->word()."\n";
}

// packet 0x268
function PACKET_AC_ACK_EKEY_FAIL_NOTUSESEKEY($parser) {
	echo "$parser->packet_desc errorCode=".$parser->word()."\n";
}

// packet 0x269
function PACKET_AC_ACK_EKEY_FAIL_NOTUSEDEKEY($parser) {
	echo "$parser->packet_desc errorCode=".$parser->word()."\n";
}

// packet 0x26a
function PACKET_AC_ACK_EKEY_FAIL_AUTHREFUSE($parser) {
	echo "$parser->packet_desc errorCode=".$parser->word()."\n";
}

// packet 0x26b
function PACKET_AC_ACK_EKEY_FAIL_INPUTEKEY($parser) {
	echo "$parser->packet_desc errorCode=".$parser->word()."\n";
}

// packet 0x26c
function PACKET_AC_ACK_EKEY_FAIL_NOTICE($parser) {
	echo "$parser->packet_desc errorCode=".$parser->word()."\n";
}

// packet 0x26d
function PACKET_AC_ACK_EKEY_FAIL_NEEDCARDPASS($parser) {
	echo "$parser->packet_desc errorCode=".$parser->word()."\n";
}

// packet 0x26e
function PACKET_AC_ACK_AUTHEKEY_FAIL_NOTMATCHCARDPASS($parser) {
	echo "$parser->packet_desc errorCode=".$parser->word()."\n";
}

// packet 0x26f
function PACKET_AC_ACK_FIRST_LOGIN($parser) {
	echo "$parser->packet_desc \n";
}

// packet 0x270
function PACKET_AC_REQ_LOGIN_ACCOUNT_INFO($parser) {
	echo "$parser->packet_desc \n";
}

// packet 0x271
function PACKET_CA_ACK_LOGIN_ACCOUNT_INFO($parser) {
	echo "$parser->packet_desc sex=".$parser->word()."\n";
	echo "$parser->nl bPoint=".$parser->word()."\n";
	echo "$parser->nl E_mail=".$parser->string(34)."\n";
}

// packet 0x272
function PACKET_AC_ACK_PT_ID_INFO($parser) {
	echo "$parser->packet_desc szPTID=".$parser->string(21)."\n";
	echo "$parser->nl szPTNumID=".$parser->string(21)."\n";
}

// packet 0x273
function PACKET_CZ_REQ_MAIL_RETURN($parser) {
	echo "$parser->packet_desc MailID=".$parser->long()."\n";
	echo "$parser->nl ReceiveName=".$parser->string(24)."\n";
}

// packet 0x274
function PACKET_ZC_ACK_MAIL_RETURN($parser) {
	echo "$parser->packet_desc MailID=".$parser->long()."\n";
	echo "$parser->nl Result=".$parser->word()."\n";
}

// packet 0x275
function PACKET_CH_ENTER2($parser) {
	echo "$parser->packet_desc AID=".$parser->long()."\n";
	echo "$parser->nl AuthCode=".$parser->long()."\n";
	echo "$parser->nl userLevel=".$parser->long()."\n";
	echo "$parser->nl clientType=".$parser->word()."\n";
	echo "$parser->nl Sex=".$parser->byte()."\n";
	echo "$parser->nl macData=".$parser->string(16)."\n";
	echo "$parser->nl iAccountSID=".$parser->long()."\n";
}

// packet 0x276
function PACKET_AC_ACCEPT_LOGIN2($parser) {
	echo "$parser->packet_desc PacketLength=".$parser->word()."\n";
	echo "$parser->nl AuthCode=".$parser->long()."\n";
	echo "$parser->nl AID=".$parser->long()."\n";
	echo "$parser->nl userLevel=".$parser->long()."\n";
	echo "$parser->nl lastLoginIP=".$parser->ip()."\n";
	echo "$parser->nl lastLoginTime=".$parser->string(26)."\n";
	echo "$parser->nl Sex=".$parser->byte()."\n";
	echo "$parser->nl iAccountSID=".$parser->long()."\n";
}

// packet 0x277
function PACKET_CA_LOGIN_PCBANG($parser) {
	echo "$parser->packet_desc Version=".$parser->long()."\n";
	echo "$parser->nl ID=".$parser->string(24)."\n";
	echo "$parser->nl Passwd=".$parser->string(24)."\n";
	echo "$parser->nl clienttype=".$parser->byte()."\n";
	echo "$parser->nl IP=".$parser->string(16)."\n";
	echo "$parser->nl MacAdress=".$parser->string(13)."\n";
}

// packet 0x278
function PACKET_ZC_NOTIFY_PCBANG($parser) {
	echo "$parser->packet_desc \n";
}

// packet 0x279
function PACKET_CZ_HUNTINGLIST($parser) {
	echo "$parser->packet_desc \n";
}

// packet 0x27a
function PACKET_ZC_HUNTINGLIST($parser) {
	echo "$parser->packet_desc PacketLength=".$parser->word()."\n";
	$HuntingList = ($parser->packet_length - $parser->packet_pointer) / 12;
	for ($i = 0; $i < $HuntingList; $i++) {
		echo "$parser->nl questID=".$parser->long()."\n";
		echo "$parser->nl mobGID=".$parser->long()."\n";
		echo "$parser->nl maxCount=".$parser->word()."\n";
		echo "$parser->nl count=".$parser->word()."\n";
	}
}

// packet 0x27b
function PACKET_ZC_PCBANG_EFFECT($parser) {
	echo "$parser->packet_desc ExpFactor=".$parser->long()."\n";
	echo "$parser->nl ExpFactor2=".$parser->long()."\n";
	echo "$parser->nl DropFactor=".$parser->long()."\n";
}

// packet 0x27c
function PACKET_CA_LOGIN4($parser) {
	echo "$parser->packet_desc Version=".$parser->long()."\n";
	echo "$parser->nl ID=".$parser->string(24)."\n";
	echo "$parser->nl PasswdMD5=".$parser->string(16)."\n";
	echo "$parser->nl clienttype=".$parser->byte()."\n";
	echo "$parser->nl macData=".$parser->string(13)."\n";
}

// packet 0x27d
function PACKET_ZC_PROPERTY_MERCE($parser) {
	echo "$parser->packet_desc name=".$parser->string(24)."\n";
	echo "$parser->nl level=".$parser->word()."\n";
	echo "$parser->nl faith=".$parser->word()."\n";
	echo "$parser->nl summonCount=".$parser->word()."\n";
	echo "$parser->nl atk=".$parser->word()."\n";
	echo "$parser->nl Matk=".$parser->word()."\n";
	echo "$parser->nl hit=".$parser->word()."\n";
	echo "$parser->nl critical=".$parser->word()."\n";
	echo "$parser->nl def=".$parser->word()."\n";
	echo "$parser->nl Mdef=".$parser->word()."\n";
	echo "$parser->nl flee=".$parser->word()."\n";
	echo "$parser->nl aspd=".$parser->word()."\n";
	echo "$parser->nl hp=".$parser->word()."\n";
	echo "$parser->nl maxHP=".$parser->word()."\n";
	echo "$parser->nl sp=".$parser->word()."\n";
	echo "$parser->nl maxSP=".$parser->word()."\n";
	echo "$parser->nl ATKRange=".$parser->word()."\n";
	echo "$parser->nl exp=".$parser->long()."\n";
}

// packet 0x27e
function PACKET_ZC_SHANDA_PROTECT($parser) {
	echo "$parser->packet_desc PacketLength=".$parser->word()."\n";
	echo "$parser->nl CodeLen=".$parser->word()."\n";
	echo "$parser->nl Code=".$parser->string($parser->packet_length - $parser->packet_pointer)."\n";
}

// packet 0x27f
function PACKET_CA_CLIENT_TYPE($parser) {
	echo "$parser->packet_desc ClientType=".$parser->word()."\n";
	echo "$parser->nl nVer=".$parser->long()."\n";
}

// packet 0x280
function PACKET_ZC_GANGSI_POINT($parser) {
	echo "$parser->packet_desc Point=".$parser->long()."\n";
	echo "$parser->nl TotalPoint=".$parser->long()."\n";
	echo "$parser->nl PacketSwitch=".$parser->word()."\n";
}

// packet 0x281
function PACKET_CZ_GANGSI_RANK($parser) {
	echo "$parser->packet_desc PacketSwitch=".$parser->word()."\n";
}

// packet 0x282
function PACKET_ZC_GANGSI_RANK($parser) {
	echo "$parser->packet_desc Name=".$parser->string(24)."\n";
	echo "$parser->nl Point=".$parser->long()."\n";
	echo "$parser->nl PacketSwitch=".$parser->word()."\n";
}

// packet 0x283
function PACKET_ZC_AID($parser) {
	echo "$parser->packet_desc AID=".$parser->long()."\n";
}

// packet 0x284
function PACKET_ZC_NOTIFY_EFFECT3($parser) {
	echo "$parser->packet_desc AID=".$parser->long()."\n";
	echo "$parser->nl effectID=".$parser->long()."\n";
	echo "$parser->nl numdata=".$parser->long()."\n";
}

// packet 0x285
function PACKET_ZC_DEATH_QUESTION($parser) {
	echo "$parser->packet_desc Qcategory=".$parser->word()."\n";
	echo "$parser->nl Qnum=".$parser->word()."\n";
}

// packet 0x286
function PACKET_CZ_DEATH_QUESTION($parser) {
	echo "$parser->packet_desc Qanswer=".$parser->word()."\n";
}

// packet 0x287
function PACKET_ZC_PC_CASH_POINT_ITEMLIST($parser) {
	echo "$parser->packet_desc PacketLength=".$parser->word()."\n";
	echo "$parser->nl CashPoint=".$parser->long()."\n";
	$itemList = ($parser->packet_length - $parser->packet_pointer) / 11;
	for ($i = 0; $i < $itemList; $i++) {
		echo "$parser->nl price=".$parser->long()."\n";
		echo "$parser->nl discountprice=".$parser->long()."\n";
		echo "$parser->nl type=".$parser->byte()."\n";
		echo "$parser->nl ITID=".$parser->word()."\n";
	}
}

// packet 0x288
function PACKET_CZ_PC_BUY_CASH_POINT_ITEM($parser) {
	echo "$parser->packet_desc ITID=".$parser->word()."\n";
	echo "$parser->nl count=".$parser->word()."\n";
}

// packet 0x289
function PACKET_ZC_PC_CASH_POINT_UPDATE($parser) {
	echo "$parser->packet_desc CashPoint=".$parser->long()."\n";
	echo "$parser->nl Error=".$parser->word()."\n";
}

// packet 0x28a
function PACKET_ZC_NPC_SHOWEFST_UPDATE($parser) {
	echo "$parser->packet_desc AID=".$parser->long()."\n";
	echo "$parser->nl effectState=".$parser->long()."\n";
	echo "$parser->nl clevel=".$parser->long()."\n";
	echo "$parser->nl showEFST=".$parser->long()."\n";
}

// packet 0x28c
function PACKET_CH_SELECT_CHAR_GOINGTOBEUSED($parser) {
	echo "$parser->packet_desc dwAID=".$parser->long()."\n";
	echo "$parser->nl nCountSelectedChar=".$parser->long()."\n";
	echo "$parser->nl ardwSelectedGID=".$parser->long()."\n";
}

// packet 0x28d
function PACKET_CH_REQ_IS_VALID_CHARNAME($parser) {
	echo "$parser->packet_desc dwAID=".$parser->long()."\n";
	echo "$parser->nl dwGID=".$parser->long()."\n";
	echo "$parser->nl szCharName=".$parser->string(24)."\n";
}

// packet 0x28e
function PACKET_HC_ACK_IS_VALID_CHARNAME($parser) {
	echo "$parser->packet_desc sResult=".$parser->word()."\n";
}

// packet 0x28f
function PACKET_CH_REQ_CHANGE_CHARNAME($parser) {
	echo "$parser->packet_desc dwGID=".$parser->long()."\n";
}

// packet 0x290
function PACKET_HC_ACK_CHANGE_CHARNAME($parser) {
	echo "$parser->packet_desc sResult=".$parser->word()."\n";
}

// packet 0x291
function PACKET_ZC_MSG($parser) {
	echo "$parser->packet_desc msg=".$parser->word()."\n";
}

// packet 0x292
function PACKET_CZ_STANDING_RESURRECTION($parser) {
	echo "$parser->packet_desc \n";
}

// packet 0x293
function PACKET_ZC_BOSS_INFO($parser) {
	echo "$parser->packet_desc infoType=".$parser->byte()."\n";
	echo "$parser->nl xPos=".$parser->long()."\n";
	echo "$parser->nl yPos=".$parser->long()."\n";
	echo "$parser->nl minHour=".$parser->word()."\n";
	echo "$parser->nl minMinute=".$parser->word()."\n";
	echo "$parser->nl maxHour=".$parser->word()."\n";
	echo "$parser->nl maxMinute=".$parser->word()."\n";
	echo "$parser->nl name=".$parser->string(51)."\n";
}

// packet 0x294
function PACKET_ZC_READ_BOOK($parser) {
	echo "$parser->packet_desc bookID=".$parser->long()."\n";
	echo "$parser->nl page=".$parser->long()."\n";
}

// packet 0x295
function PACKET_ZC_EQUIPMENT_ITEMLIST2($parser) {
	echo "$parser->packet_desc PacketLength=".$parser->word()."\n";
	$ItemInfo = ($parser->packet_length - $parser->packet_pointer) / 24;
	for ($i = 0; $i < $ItemInfo; $i++) {
		echo "$parser->nl index=".$parser->word()."\n";
		echo "$parser->nl ITID=".$parser->word()."\n";
		echo "$parser->nl type=".$parser->byte()."\n";
		echo "$parser->nl IsIdentified=".$parser->byte()."\n";
		echo "$parser->nl location=".$parser->word()."\n";
		echo "$parser->nl WearState=".$parser->word()."\n";
		echo "$parser->nl IsDamaged=".$parser->byte()."\n";
		echo "$parser->nl RefiningLevel=".$parser->byte()."\n";
		echo "$parser->nl card1=".$parser->word()."\n";
		echo "$parser->nl card2=".$parser->word()."\n";
		echo "$parser->nl card3=".$parser->word()."\n";
		echo "$parser->nl card4=".$parser->word()."\n";
		echo "$parser->nl HireExpireDate=".$parser->long()."\n";
	}
}

// packet 0x296
function PACKET_ZC_STORE_EQUIPMENT_ITEMLIST2($parser) {
	echo "$parser->packet_desc PacketLength=".$parser->word()."\n";
	$ItemInfo = ($parser->packet_length - $parser->packet_pointer) / 24;
	for ($i = 0; $i < $ItemInfo; $i++) {
		echo "$parser->nl index=".$parser->word()."\n";
		echo "$parser->nl ITID=".$parser->word()."\n";
		echo "$parser->nl type=".$parser->byte()."\n";
		echo "$parser->nl IsIdentified=".$parser->byte()."\n";
		echo "$parser->nl location=".$parser->word()."\n";
		echo "$parser->nl WearState=".$parser->word()."\n";
		echo "$parser->nl IsDamaged=".$parser->byte()."\n";
		echo "$parser->nl RefiningLevel=".$parser->byte()."\n";
		echo "$parser->nl card1=".$parser->word()."\n";
		echo "$parser->nl card2=".$parser->word()."\n";
		echo "$parser->nl card3=".$parser->word()."\n";
		echo "$parser->nl card4=".$parser->word()."\n";
		echo "$parser->nl HireExpireDate=".$parser->long()."\n";
	}
}

// packet 0x297
function PACKET_ZC_CART_EQUIPMENT_ITEMLIST2($parser) {
	echo "$parser->packet_desc PacketLength=".$parser->word()."\n";
	$ItemInfo = ($parser->packet_length - $parser->packet_pointer) / 24;
	for ($i = 0; $i < $ItemInfo; $i++) {
		echo "$parser->nl index=".$parser->word()."\n";
		echo "$parser->nl ITID=".$parser->word()."\n";
		echo "$parser->nl type=".$parser->byte()."\n";
		echo "$parser->nl IsIdentified=".$parser->byte()."\n";
		echo "$parser->nl location=".$parser->word()."\n";
		echo "$parser->nl WearState=".$parser->word()."\n";
		echo "$parser->nl IsDamaged=".$parser->byte()."\n";
		echo "$parser->nl RefiningLevel=".$parser->byte()."\n";
		echo "$parser->nl card1=".$parser->word()."\n";
		echo "$parser->nl card2=".$parser->word()."\n";
		echo "$parser->nl card3=".$parser->word()."\n";
		echo "$parser->nl card4=".$parser->word()."\n";
		echo "$parser->nl HireExpireDate=".$parser->long()."\n";
	}
}

// packet 0x298
function PACKET_ZC_CASH_TIME_COUNTER($parser) {
	echo "$parser->packet_desc ITID=".$parser->word()."\n";
	echo "$parser->nl RemainSecond=".$parser->long()."\n";
}

// packet 0x299
function PACKET_ZC_CASH_ITEM_DELETE($parser) {
	echo "$parser->packet_desc index=".$parser->word()."\n";
	echo "$parser->nl ITID=".$parser->word()."\n";
}

// packet 0x29a
function PACKET_ZC_ITEM_PICKUP_ACK2($parser) {
	echo "$parser->packet_desc Index=".$parser->word()."\n";
	echo "$parser->nl count=".$parser->word()."\n";
	echo "$parser->nl ITID=".$parser->word()."\n";
	echo "$parser->nl IsIdentified=".$parser->byte()."\n";
	echo "$parser->nl IsDamaged=".$parser->byte()."\n";
	echo "$parser->nl refiningLevel=".$parser->byte()."\n";
		echo "$parser->nl card1=".$parser->word()."\n";
		echo "$parser->nl card2=".$parser->word()."\n";
		echo "$parser->nl card3=".$parser->word()."\n";
		echo "$parser->nl card4=".$parser->word()."\n";
	echo "$parser->nl location=".$parser->word()."\n";
	echo "$parser->nl type=".$parser->byte()."\n";
	echo "$parser->nl result=".$parser->byte()."\n";
	echo "$parser->nl HireExpireDate=".$parser->long()."\n";
}

// packet 0x29b
function PACKET_ZC_MER_INIT($parser) {
	echo "$parser->packet_desc AID=".$parser->long()."\n";
	echo "$parser->nl atk=".$parser->word()."\n";
	echo "$parser->nl Matk=".$parser->word()."\n";
	echo "$parser->nl hit=".$parser->word()."\n";
	echo "$parser->nl critical=".$parser->word()."\n";
	echo "$parser->nl def=".$parser->word()."\n";
	echo "$parser->nl Mdef=".$parser->word()."\n";
	echo "$parser->nl flee=".$parser->word()."\n";
	echo "$parser->nl aspd=".$parser->word()."\n";
	echo "$parser->nl name=".$parser->string(24)."\n";
	echo "$parser->nl level=".$parser->word()."\n";
	echo "$parser->nl hp=".$parser->long()."\n";
	echo "$parser->nl maxHP=".$parser->long()."\n";
	echo "$parser->nl sp=".$parser->long()."\n";
	echo "$parser->nl maxSP=".$parser->long()."\n";
	echo "$parser->nl ExpireDate=".$parser->long()."\n";
	echo "$parser->nl faith=".$parser->word()."\n";
	echo "$parser->nl toal_call_num=".$parser->long()."\n";
	echo "$parser->nl approval_monster_kill_counter=".$parser->long()."\n";
	echo "$parser->nl ATKRange=".$parser->word()."\n";
}

// packet 0x29c
function PACKET_ZC_MER_PROPERTY($parser) {
	echo "$parser->packet_desc atk=".$parser->word()."\n";
	echo "$parser->nl Matk=".$parser->word()."\n";
	echo "$parser->nl hit=".$parser->word()."\n";
	echo "$parser->nl critical=".$parser->word()."\n";
	echo "$parser->nl def=".$parser->word()."\n";
	echo "$parser->nl Mdef=".$parser->word()."\n";
	echo "$parser->nl flee=".$parser->word()."\n";
	echo "$parser->nl aspd=".$parser->word()."\n";
	echo "$parser->nl name=".$parser->string(24)."\n";
	echo "$parser->nl level=".$parser->word()."\n";
	echo "$parser->nl hp=".$parser->word()."\n";
	echo "$parser->nl maxHP=".$parser->word()."\n";
	echo "$parser->nl sp=".$parser->word()."\n";
	echo "$parser->nl maxSP=".$parser->word()."\n";
	echo "$parser->nl ExpireDate=".$parser->long()."\n";
	echo "$parser->nl faith=".$parser->word()."\n";
	echo "$parser->nl toal_call_num=".$parser->long()."\n";
	echo "$parser->nl approval_monster_kill_counter=".$parser->long()."\n";
}

// packet 0x29d
function PACKET_ZC_MER_SKILLINFO_LIST($parser) {
	echo "$parser->packet_desc PacketLength=".$parser->word()."\n";
	$skillList = ($parser->packet_length - $parser->packet_pointer) / 37;
	for ($i = 0; $i < $skillList; $i++) {
		echo "$parser->nl SKID=".$parser->word()."\n";
		echo "$parser->nl type=".$parser->long()."\n";
		echo "$parser->nl level=".$parser->word()."\n";
		echo "$parser->nl spcost=".$parser->word()."\n";
		echo "$parser->nl attackRange=".$parser->word()."\n";
		echo "$parser->nl skillName=".$parser->string(24)."\n";
		echo "$parser->nl upgradable=".$parser->byte()."\n";
	}
}

// packet 0x29e
function PACKET_ZC_MER_SKILLINFO_UPDATE($parser) {
	echo "$parser->packet_desc SKID=".$parser->word()."\n";
	echo "$parser->nl level=".$parser->word()."\n";
	echo "$parser->nl spcost=".$parser->word()."\n";
	echo "$parser->nl attackRange=".$parser->word()."\n";
	echo "$parser->nl upgradable=".$parser->byte()."\n";
}

// packet 0x29f
function PACKET_CZ_MER_COMMAND($parser) {
	echo "$parser->packet_desc command=".$parser->byte()."\n";
}

// packet 0x2a0
function UNUSED_PACKET_CZ_MER_USE_SKILL($parser) {
	echo "$parser->packet_desc selectedLevel=".$parser->word()."\n";
	echo "$parser->nl SKID=".$parser->word()."\n";
	echo "$parser->nl targetID=".$parser->long()."\n";
}

// packet 0x2a1
function UNUSED_PACKET_CZ_MER_UPGRADE_SKILLLEVEL($parser) {
	echo "$parser->packet_desc SKID=".$parser->word()."\n";
}

// packet 0x2a2
function PACKET_ZC_MER_PAR_CHANGE($parser) {
	echo "$parser->packet_desc var=".$parser->word()."\n";
	echo "$parser->nl value=".$parser->long()."\n";
}

// packet 0x2a3
function PACKET_ZC_GAMEGUARD_LINGO_KEY($parser) {
	echo "$parser->packet_desc packetType=".$parser->word()."\n";
		echo "$parser->nl dwAlgNum=".$parser->long()."\n";
		echo "$parser->nl dwAlgKey1=".$parser->long()."\n";
		echo "$parser->nl dwAlgKey2=".$parser->long()."\n";
		echo "$parser->nl dwSeed=".$parser->long()."\n";
}

// packet 0x2a5
function PACKET_CZ_KSY_EVENT($parser) {
	echo "$parser->packet_desc index=".$parser->word()."\n";
	echo "$parser->nl count=".$parser->long()."\n";
}

// packet 0x2aa
function PACKET_ZC_REQ_CASH_PASSWORD($parser) {
	echo "$parser->packet_desc Info=".$parser->word()."\n";
}

// packet 0x2ab
function PACKET_CZ_ACK_CASH_PASSWORD($parser) {
	echo "$parser->packet_desc Type=".$parser->word()."\n";
	echo "$parser->nl Password=".$parser->string(16)."\n";
	echo "$parser->nl NewPassword=".$parser->string(16)."\n";
}

// packet 0x2ac
function PACKET_ZC_RESULT_CASH_PASSWORD($parser) {
	echo "$parser->packet_desc Result=".$parser->word()."\n";
	echo "$parser->nl ErrorCount=".$parser->word()."\n";
}

// packet 0x2ad
function PACKET_AC_REQUEST_SECOND_PASSWORD($parser) {
	echo "$parser->packet_desc Result=".$parser->word()."\n";
	echo "$parser->nl dwSeed=".$parser->long()."\n";
}

// packet 0x2b0
function PACKET_CA_LOGIN_HAN($parser) {
	echo "$parser->packet_desc Version=".$parser->long()."\n";
	echo "$parser->nl ID=".$parser->string(24)."\n";
	echo "$parser->nl Passwd=".$parser->string(24)."\n";
	echo "$parser->nl clienttype=".$parser->byte()."\n";
	echo "$parser->nl m_szIP=".$parser->string(16)."\n";
	echo "$parser->nl m_szMacAddr=".$parser->string(13)."\n";
	echo "$parser->nl isHanGameUser=".$parser->byte()."\n";
}

// packet 0x2b1
function PACKET_ZC_ALL_QUEST_LIST($parser) {
	echo "$parser->packet_desc PacketLength=".$parser->word()."\n";
	echo "$parser->nl questCount=".$parser->long()."\n";
	$QuestList = ($parser->packet_length - $parser->packet_pointer) / 5;
	for ($i = 0; $i < $QuestList; $i++) {
		echo "$parser->nl questID=".$parser->long()."\n";
		echo "$parser->nl active=".$parser->byte()."\n";
	}
}

// packet 0x2b2
function PACKET_ZC_ALL_QUEST_MISSION($parser) {
	echo "$parser->packet_desc PacketLength=".$parser->word()."\n";
	echo "$parser->nl count=".$parser->long()."\n";
	$QuestMissionList = ($parser->packet_length - $parser->packet_pointer) / 104;
	for ($i = 0; $i < $QuestMissionList; $i++) {
		echo "$parser->nl questID=".$parser->long()."\n";
		echo "$parser->nl quest_svrTime=".$parser->long()."\n";
		echo "$parser->nl quest_endTime=".$parser->long()."\n";
		echo "$parser->nl count=".$parser->word()."\n";
	for ($i = 0; $i < 3; $i++) {
		echo "$parser->nl mobGID=".$parser->long()."\n";
		echo "$parser->nl huntCount=".$parser->word()."\n";
		echo "$parser->nl mobName=".$parser->string(24)."\n";
		}
	}
}

// packet 0x2b3
function PACKET_ZC_ADD_QUEST($parser) {
	echo "$parser->packet_desc questID=".$parser->long()."\n";
	echo "$parser->nl active=".$parser->byte()."\n";
	echo "$parser->nl quest_svrTime=".$parser->long()."\n";
	echo "$parser->nl quest_endTime=".$parser->long()."\n";
	echo "$parser->nl count=".$parser->word()."\n";
	for ($i = 0; $i < 3; $i++) {
		echo "$parser->nl mobGID=".$parser->long()."\n";
		echo "$parser->nl huntCount=".$parser->word()."\n";
		echo "$parser->nl mobName=".$parser->string(24)."\n";
	}
}

// packet 0x2b4
function PACKET_ZC_DEL_QUEST($parser) {
	echo "$parser->packet_desc questID=".$parser->long()."\n";
}

// packet 0x2b5
function PACKET_ZC_UPDATE_MISSION_HUNT($parser) {
	echo "$parser->packet_desc PacketLength=".$parser->word()."\n";
	echo "$parser->nl count=".$parser->word()."\n";
	$MobHuntList = ($parser->packet_length - $parser->packet_pointer) / 12;
	for ($i = 0; $i < $MobHuntList; $i++) {
		echo "$parser->nl questID=".$parser->long()."\n";
		echo "$parser->nl mobGID=".$parser->long()."\n";
		echo "$parser->nl maxCount=".$parser->word()."\n";
		echo "$parser->nl count=".$parser->word()."\n";
	}
}

// packet 0x2b6
function PACKET_CZ_ACTIVE_QUEST($parser) {
	echo "$parser->packet_desc questID=".$parser->long()."\n";
	echo "$parser->nl active=".$parser->byte()."\n";
}

// packet 0x2b7
function PACKET_ZC_ACTIVE_QUEST($parser) {
	echo "$parser->packet_desc questID=".$parser->long()."\n";
	echo "$parser->nl active=".$parser->byte()."\n";
}

// packet 0x2b8
function PACKET_ZC_ITEM_PICKUP_PARTY($parser) {
	echo "$parser->packet_desc accountID=".$parser->long()."\n";
	echo "$parser->nl ITID=".$parser->word()."\n";
	echo "$parser->nl IsIdentified=".$parser->byte()."\n";
	echo "$parser->nl IsDamaged=".$parser->byte()."\n";
	echo "$parser->nl refiningLevel=".$parser->byte()."\n";
		echo "$parser->nl card1=".$parser->word()."\n";
		echo "$parser->nl card2=".$parser->word()."\n";
		echo "$parser->nl card3=".$parser->word()."\n";
		echo "$parser->nl card4=".$parser->word()."\n";
	echo "$parser->nl location=".$parser->word()."\n";
	echo "$parser->nl type=".$parser->byte()."\n";
}

// packet 0x2b9
function PACKET_ZC_SHORTCUT_KEY_LIST($parser) {
	echo "$parser->packet_desc \n";
	for ($i = 0; $i < 27; $i++) {
		echo "$parser->nl isSkill=".$parser->byte()."\n";
		echo "$parser->nl ID=".$parser->long()."\n";
		echo "$parser->nl count=".$parser->word()."\n";
	}
}

// packet 0x2ba
function PACKET_CZ_SHORTCUT_KEY_CHANGE($parser) {
	echo "$parser->packet_desc Index=".$parser->word()."\n";
		echo "$parser->nl isSkill=".$parser->byte()."\n";
		echo "$parser->nl ID=".$parser->long()."\n";
		echo "$parser->nl count=".$parser->word()."\n";
}

// packet 0x2bb
function PACKET_ZC_EQUIPITEM_DAMAGED($parser) {
	echo "$parser->packet_desc wearLocation=".$parser->word()."\n";
	echo "$parser->nl accountID=".$parser->long()."\n";
}

// packet 0x2bc
function PACKET_ZC_NOTIFY_PCBANG_PLAYING_TIME($parser) {
	echo "$parser->packet_desc TimeMinute=".$parser->long()."\n";
}

// packet 0x2bf
function PACKET_ZC_SRPACKETR2_INIT($parser) {
	echo "$parser->packet_desc ProtectFactor=".$parser->word()."\n";
	echo "$parser->nl DeformSeedFactor=".$parser->long()."\n";
	echo "$parser->nl DeformAddFactor=".$parser->long()."\n";
}

// packet 0x2c0
function PACKET_CZ_SRPACKETR2_START($parser) {
	echo "$parser->packet_desc ProtectFactor=".$parser->word()."\n";
}

// packet 0x2c1
function PACKET_ZC_NPC_CHAT($parser) {
	echo "$parser->packet_desc PacketLength=".$parser->word()."\n";
	echo "$parser->nl accountID=".$parser->long()."\n";
	echo "$parser->nl color=".$parser->long()."\n";
	echo "$parser->nl msg=".$parser->string($parser->packet_length - $parser->packet_pointer)."\n";
}

// packet 0x2c2
function PACKET_ZC_FORMATSTRING_MSG($parser) {
	echo "$parser->packet_desc PacketLength=".$parser->word()."\n";
	echo "$parser->nl msg=".$parser->word()."\n";
	echo "$parser->nl value=".$parser->string($parser->packet_length - $parser->packet_pointer)."\n";
}

// packet 0x2c4
function PACKET_CZ_PARTY_JOIN_REQ($parser) {
	echo "$parser->packet_desc characterName=".$parser->string(24)."\n";
}

// packet 0x2c5
function PACKET_ZC_PARTY_JOIN_REQ_ACK($parser) {
	echo "$parser->packet_desc characterName=".$parser->string(24)."\n";
	echo "$parser->nl answer=".$parser->long()."\n";
}

// packet 0x2c6
function PACKET_ZC_PARTY_JOIN_REQ($parser) {
	echo "$parser->packet_desc GRID=".$parser->long()."\n";
	echo "$parser->nl groupName=".$parser->string(24)."\n";
}

// packet 0x2c7
function PACKET_CZ_PARTY_JOIN_REQ_ACK($parser) {
	echo "$parser->packet_desc GRID=".$parser->long()."\n";
	echo "$parser->nl bAccept=".$parser->byte()."\n";
}

// packet 0x2c8
function PACKET_CZ_PARTY_CONFIG($parser) {
	echo "$parser->packet_desc bRefuseJoinMsg=".$parser->byte()."\n";
}

// packet 0x2c9
function PACKET_ZC_PARTY_CONFIG($parser) {
	echo "$parser->packet_desc bRefuseJoinMsg=".$parser->byte()."\n";
}

// packet 0x2ca
function PACKET_HC_REFUSE_SELECTCHAR($parser) {
	echo "$parser->packet_desc ErrorCode=".$parser->byte()."\n";
}

// packet 0x2cb
function PACKET_ZC_MEMORIALDUNGEON_SUBSCRIPTION_INFO($parser) {
	echo "$parser->packet_desc MemorialDungeonName=".$parser->string(61)."\n";
	echo "$parser->nl PriorityOrderNum=".$parser->word()."\n";
}

// packet 0x2cc
function PACKET_ZC_MEMORIALDUNGEON_SUBSCRIPTION_NOTIFY($parser) {
	echo "$parser->packet_desc PriorityOrderNum=".$parser->word()."\n";
}

// packet 0x2cd
function PACKET_ZC_MEMORIALDUNGEON_INFO($parser) {
	echo "$parser->packet_desc MemorialDungeonName=".$parser->string(61)."\n";
	echo "$parser->nl DestroyDate=".$parser->long()."\n";
	echo "$parser->nl EnterTimeOutDate=".$parser->long()."\n";
}

// packet 0x2ce
function PACKET_ZC_MEMORIALDUNGEON_NOTIFY($parser) {
	echo "$parser->packet_desc Type=".$parser->long()."\n";
	echo "$parser->nl EnterLimitDate=".$parser->long()."\n";
}

// packet 0x2cf
function PACKET_CZ_MEMORIALDUNGEON_COMMAND($parser) {
	echo "$parser->packet_desc Command=".$parser->long()."\n";
}

// packet 0x2d0
function PACKET_ZC_EQUIPMENT_ITEMLIST3($parser) {
	echo "$parser->packet_desc PacketLength=".$parser->word()."\n";
	$ItemInfo = ($parser->packet_length - $parser->packet_pointer) / 28;
	for ($i = 0; $i < $ItemInfo; $i++) {
		echo "$parser->nl index=".$parser->word()."\n";
		echo "$parser->nl ITID=".$parser->word()."\n";
		echo "$parser->nl type=".$parser->byte()."\n";
		echo "$parser->nl IsIdentified=".$parser->byte()."\n";
		echo "$parser->nl location=".$parser->word()."\n";
		echo "$parser->nl WearState=".$parser->word()."\n";
		echo "$parser->nl IsDamaged=".$parser->byte()."\n";
		echo "$parser->nl RefiningLevel=".$parser->byte()."\n";
		echo "$parser->nl card1=".$parser->word()."\n";
		echo "$parser->nl card2=".$parser->word()."\n";
		echo "$parser->nl card3=".$parser->word()."\n";
		echo "$parser->nl card4=".$parser->word()."\n";
		echo "$parser->nl HireExpireDate=".$parser->long()."\n";
		echo "$parser->nl bindOnEquipType=".$parser->word()."\n";
		echo "$parser->nl wItemSpriteNumber=".$parser->word()."\n";
	}
}

// packet 0x2d1
function PACKET_ZC_STORE_EQUIPMENT_ITEMLIST3($parser) {
	echo "$parser->packet_desc PacketLength=".$parser->word()."\n";
	$ItemInfo = ($parser->packet_length - $parser->packet_pointer) / 28;
	for ($i = 0; $i < $ItemInfo; $i++) {
		echo "$parser->nl index=".$parser->word()."\n";
		echo "$parser->nl ITID=".$parser->word()."\n";
		echo "$parser->nl type=".$parser->byte()."\n";
		echo "$parser->nl IsIdentified=".$parser->byte()."\n";
		echo "$parser->nl location=".$parser->word()."\n";
		echo "$parser->nl WearState=".$parser->word()."\n";
		echo "$parser->nl IsDamaged=".$parser->byte()."\n";
		echo "$parser->nl RefiningLevel=".$parser->byte()."\n";
		echo "$parser->nl card1=".$parser->word()."\n";
		echo "$parser->nl card2=".$parser->word()."\n";
		echo "$parser->nl card3=".$parser->word()."\n";
		echo "$parser->nl card4=".$parser->word()."\n";
		echo "$parser->nl HireExpireDate=".$parser->long()."\n";
		echo "$parser->nl bindOnEquipType=".$parser->word()."\n";
		echo "$parser->nl wItemSpriteNumber=".$parser->word()."\n";
	}
}

// packet 0x2d2
function PACKET_ZC_CART_EQUIPMENT_ITEMLIST3($parser) {
	echo "$parser->packet_desc PacketLength=".$parser->word()."\n";
	$ItemInfo = ($parser->packet_length - $parser->packet_pointer) / 28;
	for ($i = 0; $i < $ItemInfo; $i++) {
		echo "$parser->nl index=".$parser->word()."\n";
		echo "$parser->nl ITID=".$parser->word()."\n";
		echo "$parser->nl type=".$parser->byte()."\n";
		echo "$parser->nl IsIdentified=".$parser->byte()."\n";
		echo "$parser->nl location=".$parser->word()."\n";
		echo "$parser->nl WearState=".$parser->word()."\n";
		echo "$parser->nl IsDamaged=".$parser->byte()."\n";
		echo "$parser->nl RefiningLevel=".$parser->byte()."\n";
		echo "$parser->nl card1=".$parser->word()."\n";
		echo "$parser->nl card2=".$parser->word()."\n";
		echo "$parser->nl card3=".$parser->word()."\n";
		echo "$parser->nl card4=".$parser->word()."\n";
		echo "$parser->nl HireExpireDate=".$parser->long()."\n";
		echo "$parser->nl bindOnEquipType=".$parser->word()."\n";
		echo "$parser->nl wItemSpriteNumber=".$parser->word()."\n";
	}
}

// packet 0x2d3
function PACKET_ZC_NOTIFY_BIND_ON_EQUIP($parser) {
	echo "$parser->packet_desc index=".$parser->word()."\n";
}

// packet 0x2d4
function PACKET_ZC_ITEM_PICKUP_ACK3($parser) {
	echo "$parser->packet_desc Index=".$parser->word()."\n";
	echo "$parser->nl count=".$parser->word()."\n";
	echo "$parser->nl ITID=".$parser->word()."\n";
	echo "$parser->nl IsIdentified=".$parser->byte()."\n";
	echo "$parser->nl IsDamaged=".$parser->byte()."\n";
	echo "$parser->nl refiningLevel=".$parser->byte()."\n";
		echo "$parser->nl card1=".$parser->word()."\n";
		echo "$parser->nl card2=".$parser->word()."\n";
		echo "$parser->nl card3=".$parser->word()."\n";
		echo "$parser->nl card4=".$parser->word()."\n";
	echo "$parser->nl location=".$parser->word()."\n";
	echo "$parser->nl type=".$parser->byte()."\n";
	echo "$parser->nl result=".$parser->byte()."\n";
	echo "$parser->nl HireExpireDate=".$parser->long()."\n";
	echo "$parser->nl bindOnEquipType=".$parser->word()."\n";
}

// packet 0x2d5
function PACKET_ZC_ISVR_DISCONNECT($parser) {
	echo "$parser->packet_desc \n";
}

// packet 0x2d6
function PACKET_CZ_EQUIPWIN_MICROSCOPE($parser) {
	echo "$parser->packet_desc AID=".$parser->long()."\n";
}

// packet 0x2d7
function PACKET_ZC_EQUIPWIN_MICROSCOPE($parser) {
	echo "$parser->packet_desc PacketLength=".$parser->word()."\n";
	echo "$parser->nl characterName=".$parser->string(24)."\n";
	echo "$parser->nl job=".$parser->word()."\n";
	echo "$parser->nl head=".$parser->word()."\n";
	echo "$parser->nl accessory=".$parser->word()."\n";
	echo "$parser->nl accessory2=".$parser->word()."\n";
	echo "$parser->nl accessory3=".$parser->word()."\n";
	echo "$parser->nl headpalette=".$parser->word()."\n";
	echo "$parser->nl bodypalette=".$parser->word()."\n";
	echo "$parser->nl sex=".$parser->byte()."\n";
	$ItemInfo = ($parser->packet_length - $parser->packet_pointer) / 28;
	for ($i = 0; $i < $ItemInfo; $i++) {
		echo "$parser->nl index=".$parser->word()."\n";
		echo "$parser->nl ITID=".$parser->word()."\n";
		echo "$parser->nl type=".$parser->byte()."\n";
		echo "$parser->nl IsIdentified=".$parser->byte()."\n";
		echo "$parser->nl location=".$parser->word()."\n";
		echo "$parser->nl WearState=".$parser->word()."\n";
		echo "$parser->nl IsDamaged=".$parser->byte()."\n";
		echo "$parser->nl RefiningLevel=".$parser->byte()."\n";
		echo "$parser->nl card1=".$parser->word()."\n";
		echo "$parser->nl card2=".$parser->word()."\n";
		echo "$parser->nl card3=".$parser->word()."\n";
		echo "$parser->nl card4=".$parser->word()."\n";
		echo "$parser->nl HireExpireDate=".$parser->long()."\n";
		echo "$parser->nl bindOnEquipType=".$parser->word()."\n";
		echo "$parser->nl wItemSpriteNumber=".$parser->word()."\n";
	}
}

// packet 0x2d8
function PACKET_CZ_CONFIG($parser) {
	echo "$parser->packet_desc Config=".$parser->long()."\n";
	echo "$parser->nl Value=".$parser->long()."\n";
}

// packet 0x2d9
function PACKET_ZC_CONFIG($parser) {
	echo "$parser->packet_desc Config=".$parser->long()."\n";
	echo "$parser->nl Value=".$parser->long()."\n";
}

// packet 0x2da
function PACKET_ZC_CONFIG_NOTIFY($parser) {
	echo "$parser->packet_desc bOpenEquipmentWin=".$parser->byte()."\n";
}

// packet 0x2db
function PACKET_CZ_BATTLEFIELD_CHAT($parser) {
	echo "$parser->packet_desc PacketLength=".$parser->word()."\n";
	echo "$parser->nl msg=".$parser->string($parser->packet_length - $parser->packet_pointer)."\n";
}

// packet 0x2dc
function PACKET_ZC_BATTLEFIELD_CHAT($parser) {
	echo "$parser->packet_desc PacketLength=".$parser->word()."\n";
	echo "$parser->nl accountID=".$parser->long()."\n";
	echo "$parser->nl name=".$parser->string(24)."\n";
	echo "$parser->nl msg=".$parser->string($parser->packet_length - $parser->packet_pointer)."\n";
}

// packet 0x2dd
function PACKET_ZC_BATTLEFIELD_NOTIFY_CAMPINFO($parser) {
	echo "$parser->packet_desc accountID=".$parser->long()."\n";
	echo "$parser->nl name=".$parser->string(24)."\n";
	echo "$parser->nl camp=".$parser->word()."\n";
}

// packet 0x2de
function PACKET_ZC_BATTLEFIELD_NOTIFY_POINT($parser) {
	echo "$parser->packet_desc pointCampA=".$parser->word()."\n";
	echo "$parser->nl pointCampB=".$parser->word()."\n";
}

// packet 0x2df
function PACKET_ZC_BATTLEFIELD_NOTIFY_POSITION($parser) {
	echo "$parser->packet_desc accountID=".$parser->long()."\n";
	echo "$parser->nl name=".$parser->string(24)."\n";
	echo "$parser->nl job=".$parser->word()."\n";
	echo "$parser->nl x=".$parser->word()."\n";
	echo "$parser->nl y=".$parser->word()."\n";
}

// packet 0x2e0
function PACKET_ZC_BATTLEFIELD_NOTIFY_HP($parser) {
	echo "$parser->packet_desc accountID=".$parser->long()."\n";
	echo "$parser->nl name=".$parser->string(24)."\n";
	echo "$parser->nl hp=".$parser->word()."\n";
	echo "$parser->nl maxHp=".$parser->word()."\n";
}

// packet 0x2e1
function PACKET_ZC_NOTIFY_ACT2($parser) {
	echo "$parser->packet_desc GID=".$parser->long()."\n";
	echo "$parser->nl targetGID=".$parser->long()."\n";
	echo "$parser->nl startTime=".$parser->long()."\n";
	echo "$parser->nl attackMT=".$parser->long()."\n";
	echo "$parser->nl attackedMT=".$parser->long()."\n";
	echo "$parser->nl damage=".$parser->long()."\n";
	echo "$parser->nl count=".$parser->word()."\n";
	echo "$parser->nl action=".$parser->byte()."\n";
	echo "$parser->nl leftDamage=".$parser->long()."\n";
}

// packet 0x2e6
function PACKET_CZ_BOT_CHECK($parser) {
	echo "$parser->packet_desc IsBot=".$parser->long()."\n";
}

// packet 0x2e7
function PACKET_ZC_MAPPROPERTY($parser) {
	echo "$parser->packet_desc PacketLength=".$parser->word()."\n";
	echo "$parser->nl type=".$parser->word()."\n";
	echo "$parser->nl mapInfoTable=".$parser->long()."\n";
}

// packet 0x2e8
function PACKET_ZC_NORMAL_ITEMLIST3($parser) {
	echo "$parser->packet_desc PacketLength=".$parser->word()."\n";
	$ItemInfo = ($parser->packet_length - $parser->packet_pointer) / 22;
	for ($i = 0; $i < $ItemInfo; $i++) {
		echo "$parser->nl index=".$parser->word()."\n";
		echo "$parser->nl ITID=".$parser->word()."\n";
		echo "$parser->nl type=".$parser->byte()."\n";
		echo "$parser->nl IsIdentified=".$parser->byte()."\n";
		echo "$parser->nl count=".$parser->word()."\n";
		echo "$parser->nl WearState=".$parser->word()."\n";
		echo "$parser->nl card1=".$parser->word()."\n";
		echo "$parser->nl card2=".$parser->word()."\n";
		echo "$parser->nl card3=".$parser->word()."\n";
		echo "$parser->nl card4=".$parser->word()."\n";
		echo "$parser->nl HireExpireDate=".$parser->long()."\n";
	}
}

// packet 0x2e9
function PACKET_ZC_CART_NORMAL_ITEMLIST3($parser) {
	echo "$parser->packet_desc PacketLength=".$parser->word()."\n";
	$ItemInfo = ($parser->packet_length - $parser->packet_pointer) / 22;
	for ($i = 0; $i < $ItemInfo; $i++) {
		echo "$parser->nl index=".$parser->word()."\n";
		echo "$parser->nl ITID=".$parser->word()."\n";
		echo "$parser->nl type=".$parser->byte()."\n";
		echo "$parser->nl IsIdentified=".$parser->byte()."\n";
		echo "$parser->nl count=".$parser->word()."\n";
		echo "$parser->nl WearState=".$parser->word()."\n";
		echo "$parser->nl card1=".$parser->word()."\n";
		echo "$parser->nl card2=".$parser->word()."\n";
		echo "$parser->nl card3=".$parser->word()."\n";
		echo "$parser->nl card4=".$parser->word()."\n";
		echo "$parser->nl HireExpireDate=".$parser->long()."\n";
	}
}

// packet 0x2ea
function PACKET_ZC_STORE_NORMAL_ITEMLIST3($parser) {
	echo "$parser->packet_desc PacketLength=".$parser->word()."\n";
	$ItemInfo = ($parser->packet_length - $parser->packet_pointer) / 22;
	for ($i = 0; $i < $ItemInfo; $i++) {
		echo "$parser->nl index=".$parser->word()."\n";
		echo "$parser->nl ITID=".$parser->word()."\n";
		echo "$parser->nl type=".$parser->byte()."\n";
		echo "$parser->nl IsIdentified=".$parser->byte()."\n";
		echo "$parser->nl count=".$parser->word()."\n";
		echo "$parser->nl WearState=".$parser->word()."\n";
		echo "$parser->nl card1=".$parser->word()."\n";
		echo "$parser->nl card2=".$parser->word()."\n";
		echo "$parser->nl card3=".$parser->word()."\n";
		echo "$parser->nl card4=".$parser->word()."\n";
		echo "$parser->nl HireExpireDate=".$parser->long()."\n";
	}
}

// packet 0x2eb
function PACKET_ZC_ACCEPT_ENTER2($parser) {
	echo "$parser->packet_desc startTime=".$parser->long()."\n";
	echo "$parser->nl PosDir=".$parser->xy()."\n";
	echo "$parser->nl xSize=".$parser->byte()."\n";
	echo "$parser->nl ySize=".$parser->byte()."\n";
	echo "$parser->nl font=".$parser->word()."\n";
}

// packet 0x2ec
function PACKET_ZC_NOTIFY_MOVEENTRY4($parser) {
	echo "$parser->packet_desc objecttype=".$parser->byte()."\n";
	echo "$parser->nl GID=".$parser->long()."\n";
	echo "$parser->nl speed=".$parser->word()."\n";
	echo "$parser->nl bodyState=".$parser->word()."\n";
	echo "$parser->nl healthState=".$parser->word()."\n";
	echo "$parser->nl effectState=".$parser->long()."\n";
	echo "$parser->nl job=".$parser->word()."\n";
	echo "$parser->nl head=".$parser->word()."\n";
	echo "$parser->nl weapon=".$parser->long()."\n";
	echo "$parser->nl accessory=".$parser->word()."\n";
	echo "$parser->nl moveStartTime=".$parser->long()."\n";
	echo "$parser->nl accessory2=".$parser->word()."\n";
	echo "$parser->nl accessory3=".$parser->word()."\n";
	echo "$parser->nl headpalette=".$parser->word()."\n";
	echo "$parser->nl bodypalette=".$parser->word()."\n";
	echo "$parser->nl headDir=".$parser->word()."\n";
	echo "$parser->nl GUID=".$parser->long()."\n";
	echo "$parser->nl GEmblemVer=".$parser->word()."\n";
	echo "$parser->nl honor=".$parser->word()."\n";
	echo "$parser->nl virtue=".$parser->long()."\n";
	echo "$parser->nl isPKModeON=".$parser->byte()."\n";
	echo "$parser->nl sex=".$parser->byte()."\n";
	echo "$parser->nl MoveData=".$parser->xyxy()."\n";
	echo "$parser->nl xSize=".$parser->byte()."\n";
	echo "$parser->nl ySize=".$parser->byte()."\n";
	echo "$parser->nl clevel=".$parser->word()."\n";
	echo "$parser->nl font=".$parser->word()."\n";
}

// packet 0x2ed
function PACKET_ZC_NOTIFY_NEWENTRY4($parser) {
	echo "$parser->packet_desc GID=".$parser->long()."\n";
	echo "$parser->nl speed=".$parser->word()."\n";
	echo "$parser->nl bodyState=".$parser->word()."\n";
	echo "$parser->nl healthState=".$parser->word()."\n";
	echo "$parser->nl effectState=".$parser->long()."\n";
	echo "$parser->nl job=".$parser->word()."\n";
	echo "$parser->nl head=".$parser->word()."\n";
	echo "$parser->nl weapon=".$parser->long()."\n";
	echo "$parser->nl accessory=".$parser->word()."\n";
	echo "$parser->nl accessory2=".$parser->word()."\n";
	echo "$parser->nl accessory3=".$parser->word()."\n";
	echo "$parser->nl headpalette=".$parser->word()."\n";
	echo "$parser->nl bodypalette=".$parser->word()."\n";
	echo "$parser->nl headDir=".$parser->word()."\n";
	echo "$parser->nl GUID=".$parser->long()."\n";
	echo "$parser->nl GEmblemVer=".$parser->word()."\n";
	echo "$parser->nl honor=".$parser->word()."\n";
	echo "$parser->nl virtue=".$parser->long()."\n";
	echo "$parser->nl isPKModeON=".$parser->byte()."\n";
	echo "$parser->nl sex=".$parser->byte()."\n";
	echo "$parser->nl PosDir=".$parser->xy()."\n";
	echo "$parser->nl xSize=".$parser->byte()."\n";
	echo "$parser->nl ySize=".$parser->byte()."\n";
	echo "$parser->nl clevel=".$parser->word()."\n";
	echo "$parser->nl font=".$parser->word()."\n";
}

// packet 0x2ee
function PACKET_ZC_NOTIFY_STANDENTRY4($parser) {
	echo "$parser->packet_desc GID=".$parser->long()."\n";
	echo "$parser->nl speed=".$parser->word()."\n";
	echo "$parser->nl bodyState=".$parser->word()."\n";
	echo "$parser->nl healthState=".$parser->word()."\n";
	echo "$parser->nl effectState=".$parser->long()."\n";
	echo "$parser->nl job=".$parser->word()."\n";
	echo "$parser->nl head=".$parser->word()."\n";
	echo "$parser->nl weapon=".$parser->long()."\n";
	echo "$parser->nl accessory=".$parser->word()."\n";
	echo "$parser->nl accessory2=".$parser->word()."\n";
	echo "$parser->nl accessory3=".$parser->word()."\n";
	echo "$parser->nl headpalette=".$parser->word()."\n";
	echo "$parser->nl bodypalette=".$parser->word()."\n";
	echo "$parser->nl headDir=".$parser->word()."\n";
	echo "$parser->nl GUID=".$parser->long()."\n";
	echo "$parser->nl GEmblemVer=".$parser->word()."\n";
	echo "$parser->nl honor=".$parser->word()."\n";
	echo "$parser->nl virtue=".$parser->long()."\n";
	echo "$parser->nl isPKModeON=".$parser->byte()."\n";
	echo "$parser->nl sex=".$parser->byte()."\n";
	echo "$parser->nl PosDir=".$parser->xy()."\n";
	echo "$parser->nl xSize=".$parser->byte()."\n";
	echo "$parser->nl ySize=".$parser->byte()."\n";
	echo "$parser->nl state=".$parser->byte()."\n";
	echo "$parser->nl clevel=".$parser->word()."\n";
	echo "$parser->nl font=".$parser->word()."\n";
}

// packet 0x2ef
function PACKET_ZC_NOTIFY_FONT($parser) {
	echo "$parser->packet_desc AID=".$parser->long()."\n";
	echo "$parser->nl font=".$parser->word()."\n";
}

// packet 0x2f0
function PACKET_ZC_PROGRESS($parser) {
	echo "$parser->packet_desc color=".$parser->long()."\n";
	echo "$parser->nl time=".$parser->long()."\n";
}

// packet 0x2f1
function PACKET_CZ_PROGRESS($parser) {
	echo "$parser->packet_desc \n";
}

// packet 0x2f2
function PACKET_ZC_PROGRESS_CANCEL($parser) {
	echo "$parser->packet_desc \n";
}

// packet 0x2f3
function PACKET_CZ_IRMAIL_SEND($parser) {
	echo "$parser->packet_desc PacketLength=".$parser->word()."\n";
	echo "$parser->nl ReceiveName=".$parser->string(24)."\n";
	echo "$parser->nl Title=".$parser->string(40)."\n";
	echo "$parser->nl Zeny=".$parser->long()."\n";
	echo "$parser->nl index=".$parser->word()."\n";
	echo "$parser->nl id=".$parser->word()."\n";
	echo "$parser->nl cnt=".$parser->word()."\n";
}

// packet 0x2f4
function PACKET_ZC_IRMAIL_SEND_RES($parser) {
	echo "$parser->packet_desc Result=".$parser->byte()."\n";
}

// packet 0x2f5
function PACKET_ZC_IRMAIL_NOTIFY($parser) {
	echo "$parser->packet_desc ";
	echo "$parser->nl office=".$parser->byte()."\n";
	echo "$parser->nl id=".$parser->long()."\n";
}

// packet 0x2f6
function PACKET_CZ_IRMAIL_LIST($parser) {
	echo "$parser->packet_desc ";
	echo "$parser->nl office=".$parser->byte()."\n";
	echo "$parser->nl id=".$parser->long()."\n";
}

// packet 0x35c
function PACKET_CZ_OPEN_SIMPLE_CASHSHOP_ITEMLIST($parser) {
	echo "$parser->packet_desc \n";
}

// packet 0x35d
function PACKET_ZC_SIMPLE_CASHSHOP_POINT_ITEMLIST($parser) {
	echo "$parser->packet_desc PacketLength=".$parser->word()."\n";
	echo "$parser->nl CashPoint=".$parser->long()."\n";
	echo "$parser->nl md_itemcount=".$parser->word()."\n";
	echo "$parser->nl md_itemSize=".$parser->word()."\n";
	echo "$parser->nl best_itemcount=".$parser->word()."\n";
	echo "$parser->nl best_itemsize=".$parser->word()."\n";
	$ItemList = ($parser->packet_length - $parser->packet_pointer) / 11;
	for ($i = 0; $i < $ItemList; $i++) {
		echo "$parser->nl price=".$parser->long()."\n";
		echo "$parser->nl discountprice=".$parser->long()."\n";
		echo "$parser->nl type=".$parser->byte()."\n";
		echo "$parser->nl ITID=".$parser->word()."\n";
	}
}

// packet 0x35e
function PACKET_CZ_CLOSE_WINDOW($parser) {
	echo "$parser->packet_desc \n";
}

// packet 0x35f
function PACKET_CZ_REQUEST_MOVE2($parser) {
	echo "$parser->packet_desc dest=".$parser->xy()."\n";
}

// packet 0x360
function PACKET_CZ_REQUEST_TIME2($parser) {
	echo "$parser->packet_desc clientTime=".$parser->long()."\n";
}

// packet 0x361
function PACKET_CZ_CHANGE_DIRECTION2($parser) {
	echo "$parser->packet_desc headDir=".$parser->word()."\n";
	echo "$parser->nl dir=".$parser->byte()."\n";
}

// packet 0x362
function PACKET_CZ_ITEM_PICKUP2($parser) {
	echo "$parser->packet_desc ITAID=".$parser->long()."\n";
}

// packet 0x363
function PACKET_CZ_ITEM_THROW2($parser) {
	echo "$parser->packet_desc Index=".$parser->word()."\n";
	echo "$parser->nl count=".$parser->word()."\n";
}

// packet 0x364
function PACKET_CZ_MOVE_ITEM_FROM_BODY_TO_STORE2($parser) {
	echo "$parser->packet_desc index=".$parser->word()."\n";
	echo "$parser->nl count=".$parser->long()."\n";
}

// packet 0x365
function PACKET_CZ_MOVE_ITEM_FROM_STORE_TO_BODY2($parser) {
	echo "$parser->packet_desc index=".$parser->word()."\n";
	echo "$parser->nl count=".$parser->long()."\n";
}

// packet 0x366
function PACKET_CZ_USE_SKILL_TOGROUND2($parser) {
	echo "$parser->packet_desc selectedLevel=".$parser->word()."\n";
	echo "$parser->nl SKID=".$parser->word()."\n";
	echo "$parser->nl xPos=".$parser->word()."\n";
	echo "$parser->nl yPos=".$parser->word()."\n";
}

// packet 0x367
function PACKET_CZ_USE_SKILL_TOGROUND_WITHTALKBOX2($parser) {
	echo "$parser->packet_desc selectedLevel=".$parser->word()."\n";
	echo "$parser->nl SKID=".$parser->word()."\n";
	echo "$parser->nl xPos=".$parser->word()."\n";
	echo "$parser->nl yPos=".$parser->word()."\n";
	echo "$parser->nl contents=".$parser->string(80)."\n";
}

// packet 0x368
function PACKET_CZ_REQNAME2($parser) {
	echo "$parser->packet_desc AID=".$parser->long()."\n";
}

// packet 0x369
function PACKET_CZ_REQNAME_BYGID2($parser) {
	echo "$parser->packet_desc GID=".$parser->long()."\n";
}

// packet 0x3de
function PACKET_CAH_ACK_GAME_GUARD($parser) {
	echo "$parser->packet_desc AuthData=".$parser->long()."\n";
}

// packet 0x436
function PACKET_CZ_ENTER2($parser) {
	echo "$parser->packet_desc AID=".$parser->long()."\n";
	echo "$parser->nl GID=".$parser->long()."\n";
	echo "$parser->nl AuthCode=".$parser->long()."\n";
	echo "$parser->nl clientTime=".$parser->long()."\n";
	echo "$parser->nl Sex=".$parser->byte()."\n";
}

// packet 0x437
function PACKET_CZ_REQUEST_ACT2($parser) {
	echo "$parser->packet_desc targetGID=".$parser->long()."\n";
	echo "$parser->nl action=".$parser->byte()."\n";
}

// packet 0x438
function PACKET_CZ_USE_SKILL2($parser) {
	echo "$parser->packet_desc selectedLevel=".$parser->word()."\n";
	echo "$parser->nl SKID=".$parser->word()."\n";
	echo "$parser->nl targetID=".$parser->long()."\n";
}

// packet 0x439
function PACKET_CZ_USE_ITEM2($parser) {
	echo "$parser->packet_desc index=".$parser->word()."\n";
	echo "$parser->nl AID=".$parser->long()."\n";
}

// packet 0x43d
function PACKET_ZC_SKILL_POSTDELAY($parser) {
	echo "$parser->packet_desc SKID=".$parser->word()."\n";
	echo "$parser->nl DelayTM=".$parser->long()."\n";
}

// packet 0x43e
function PACKET_ZC_SKILL_POSTDELAY_LIST($parser) {
	echo "$parser->packet_desc PacketLength=".$parser->word()."\n";
	$delayList = ($parser->packet_length - $parser->packet_pointer) / 6;
	for ($i = 0; $i < $delayList; $i++) {
		echo "$parser->nl SKID=".$parser->word()."\n";
		echo "$parser->nl DelayTM=".$parser->long()."\n";
	}
}

// packet 0x43f
function PACKET_ZC_MSG_STATE_CHANGE2($parser) {
	echo "$parser->packet_desc index=".$parser->word()."\n";
	echo "$parser->nl AID=".$parser->long()."\n";
	echo "$parser->nl state=".$parser->byte()."\n";
	echo "$parser->nl RemainMS=".$parser->long()."\n";
	echo "$parser->nl val=".$parser->long()."\n";
}

// packet 0x440
function PACKET_ZC_MILLENNIUMSHIELD($parser) {
	echo "$parser->packet_desc AID=".$parser->long()."\n";
	echo "$parser->nl num=".$parser->word()."\n";
	echo "$parser->nl state=".$parser->word()."\n";
}

// packet 0x441
function PACKET_ZC_SKILLINFO_DELETE($parser) {
	echo "$parser->packet_desc SKID=".$parser->word()."\n";
}

// packet 0x442
function PACKET_ZC_SKILL_SELECT_REQUEST($parser) {
	echo "$parser->packet_desc PacketLength=".$parser->word()."\n";
	echo "$parser->nl why=".$parser->long()."\n";
	echo "$parser->nl SKIDList=".$parser->word()."\n";
}

// packet 0x443
function PACKET_CZ_SKILL_SELECT_RESPONSE($parser) {
	echo "$parser->packet_desc why=".$parser->long()."\n";
	echo "$parser->nl SKID=".$parser->word()."\n";
}

// packet 0x444
function PACKET_ZC_SIMPLE_CASH_POINT_ITEMLIST($parser) {
	echo "$parser->packet_desc PacketLength=".$parser->word()."\n";
	echo "$parser->nl CashPoint=".$parser->long()."\n";
	$ItemList = ($parser->packet_length - $parser->packet_pointer) / 11;
	for ($i = 0; $i < $ItemList; $i++) {
		echo "$parser->nl price=".$parser->long()."\n";
		echo "$parser->nl discountprice=".$parser->long()."\n";
		echo "$parser->nl type=".$parser->byte()."\n";
		echo "$parser->nl ITID=".$parser->word()."\n";
	}
}

// packet 0x445
function PACKET_CZ_SIMPLE_BUY_CASH_POINT_ITEM($parser) {
	echo "$parser->packet_desc ITID=".$parser->word()."\n";
	echo "$parser->nl count=".$parser->word()."\n";
}

// packet 0x446
function PACKET_ZC_QUEST_NOTIFY_EFFECT($parser) {
	echo "$parser->packet_desc npcID=".$parser->long()."\n";
	echo "$parser->nl xPos=".$parser->word()."\n";
	echo "$parser->nl yPos=".$parser->word()."\n";
	echo "$parser->nl effect=".$parser->word()."\n";
	echo "$parser->nl type=".$parser->word()."\n";
}

// packet 0x447
function PACKET_CZ_BLOCKING_PLAY_CANCEL($parser) {
	echo "$parser->packet_desc \n";
}

// packet 0x448
function PACKET_HC_CHARACTER_LIST($parser) {
	echo "$parser->packet_desc PacketLength=".$parser->word()."\n";
	$CharacterList = ($parser->packet_length - $parser->packet_pointer) / 5;
	for ($i = 0; $i < $CharacterList; $i++) {
		echo "$parser->nl dwGID=".$parser->long()."\n";
		echo "$parser->nl SlotIdx=".$parser->byte()."\n";
	}
}

// packet 0x449
function PACKET_ZC_HACKSH_ERROR_MSG($parser) {
	echo "$parser->packet_desc ErrorID=".$parser->word()."\n";
}

// packet 0x44a
function PACKET_CZ_CLIENT_VERSION($parser) {
	echo "$parser->packet_desc clientVer=".$parser->long()."\n";
}

// packet 0x44b
function PACKET_CZ_CLOSE_SIMPLECASH_SHOP($parser) {
	echo "$parser->packet_desc \n";
}

// packet 0x7d0
function PACKET_ZC_ES_RESULT($parser) {
	echo "$parser->packet_desc esNo=".$parser->word()."\n";
	echo "$parser->nl esMsg=".$parser->word()."\n";
}

// packet 0x7d1
function PACKET_CZ_ES_GET_LIST($parser) {
	echo "$parser->packet_desc \n";
}

// packet 0x7d2
function PACKET_ZC_ES_LIST($parser) {
	echo "$parser->packet_desc PacketLength=".$parser->word()."\n";
	echo "$parser->nl Count=".$parser->word()."\n";
}

// packet 0x7d3
function PACKET_CZ_ES_CHOOSE($parser) {
	echo "$parser->packet_desc esNo=".$parser->word()."\n";
}

// packet 0x7d4
function PACKET_CZ_ES_CANCEL($parser) {
	echo "$parser->packet_desc esNo=".$parser->word()."\n";
}

// packet 0x7d5
function PACKET_ZC_ES_READY($parser) {
	echo "$parser->packet_desc esNo=".$parser->word()."\n";
}

// packet 0x7d6
function PACKET_ZC_ES_GOTO($parser) {
	echo "$parser->packet_desc esNo=".$parser->word()."\n";
}

// packet 0x7d7
function PACKET_CZ_GROUPINFO_CHANGE_V2($parser) {
	echo "$parser->packet_desc expOption=".$parser->long()."\n";
	echo "$parser->nl ItemPickupRule=".$parser->byte()."\n";
	echo "$parser->nl ItemDivisionRule=".$parser->byte()."\n";
}

// packet 0x7d8
function PACKET_ZC_REQ_GROUPINFO_CHANGE_V2($parser) {
	echo "$parser->packet_desc expOption=".$parser->long()."\n";
	echo "$parser->nl ItemPickupRule=".$parser->byte()."\n";
	echo "$parser->nl ItemDivisionRule=".$parser->byte()."\n";
}

// packet 0x7d9
function PACKET_ZC_SHORTCUT_KEY_LIST_V2($parser) {
	echo "$parser->packet_desc \n";
	for ($i = 0; $i < 38; $i++) {
		echo "$parser->nl isSkill=".$parser->byte()."\n";
		echo "$parser->nl ID=".$parser->long()."\n";
		echo "$parser->nl count=".$parser->word()."\n";
	}
}

// packet 0x7da
function PACKET_CZ_CHANGE_GROUP_MASTER($parser) {
	echo "$parser->packet_desc AID=".$parser->long()."\n";
}

// packet 0x7db
function PACKET_ZC_HO_PAR_CHANGE($parser) {
	echo "$parser->packet_desc var=".$parser->word()."\n";
	echo "$parser->nl value=".$parser->long()."\n";
}

// packet 0x7dc
function PACKET_CZ_SEEK_PARTY($parser) {
	echo "$parser->packet_desc Option=".$parser->long()."\n";
}

// packet 0x7dd
function PACKET_ZC_SEEK_PARTY($parser) {
	echo "$parser->packet_desc Name=".$parser->string(24)."\n";
	echo "$parser->nl Job=".$parser->long()."\n";
	echo "$parser->nl Level=".$parser->long()."\n";
	echo "$parser->nl mapName=".$parser->string(16)."\n";
	echo "$parser->nl Option=".$parser->long()."\n";
}

// packet 0x7de
function PACKET_CZ_SEEK_PARTY_MEMBER($parser) {
	echo "$parser->packet_desc Job=".$parser->long()."\n";
	echo "$parser->nl Level=".$parser->long()."\n";
	echo "$parser->nl mapName=".$parser->string(16)."\n";
	echo "$parser->nl Option=".$parser->long()."\n";
}

// packet 0x7df
function PACKET_ZC_SEEK_PARTY_MEMBER($parser) {
	echo "$parser->packet_desc Name=".$parser->string(24)."\n";
	echo "$parser->nl Job=".$parser->long()."\n";
	echo "$parser->nl Level=".$parser->long()."\n";
	echo "$parser->nl mapName=".$parser->string(16)."\n";
	echo "$parser->nl Option=".$parser->long()."\n";
}

// packet 0x7e0
function PACKET_ZC_ES_NOTI_MYINFO($parser) {
	echo "$parser->packet_desc esNo=".$parser->word()."\n";
	echo "$parser->nl esname=".$parser->string(54)."\n";
}

// packet 0x7e1
function PACKET_ZC_SKILLINFO_UPDATE2($parser) {
	echo "$parser->packet_desc SKID=".$parser->word()."\n";
	echo "$parser->nl type=".$parser->long()."\n";
	echo "$parser->nl level=".$parser->word()."\n";
	echo "$parser->nl spcost=".$parser->word()."\n";
	echo "$parser->nl attackRange=".$parser->word()."\n";
	echo "$parser->nl upgradable=".$parser->byte()."\n";
}

// packet 0x7e2
function PACKET_ZC_MSG_VALUE($parser) {
	echo "$parser->packet_desc msg=".$parser->word()."\n";
	echo "$parser->nl value=".$parser->long()."\n";
}

// packet 0x7e3
function PACKET_ZC_ITEMLISTWIN_OPEN($parser) {
	echo "$parser->packet_desc Type=".$parser->long()."\n";
}

// packet 0x7e4
function PACKET_CZ_ITEMLISTWIN_RES($parser) {
	echo "$parser->packet_desc PacketLength=".$parser->word()."\n";
	echo "$parser->nl Type=".$parser->long()."\n";
	echo "$parser->nl Action=".$parser->long()."\n";
	echo "$parser->nl MaterialList=".$parser->word()."\n";
}

// packet 0x7e5
function PACKET_CH_ENTER_CHECKBOT($parser) {
	echo "$parser->packet_desc PacketLength=".$parser->word()."\n";
	echo "$parser->nl dwAID=".$parser->long()."\n";
	echo "$parser->nl szStringInfo=".$parser->string($parser->packet_length - $parser->packet_pointer)."\n";
}

// packet 0x7e6
function PACKET_ZC_MSG_SKILL($parser) {
	echo "$parser->packet_desc SKID=".$parser->word()."\n";
	echo "$parser->nl MSGID=".$parser->long()."\n";
}

// packet 0x7e7
function PACKET_CH_CHECKBOT($parser) {
	echo "$parser->packet_desc PacketLength=".$parser->word()."\n";
	echo "$parser->nl dwAID=".$parser->long()."\n";
	echo "$parser->nl szStringInfo=".$parser->string(24)."\n";
}

// packet 0x7e8
function PACKET_HC_CHECKBOT($parser) {
	echo "$parser->packet_desc PacketLength=".$parser->word()."\n";
	echo "$parser->nl img=".$parser->string($parser->packet_length - $parser->packet_pointer)."\n";
}

// packet 0x7e9
function PACKET_HC_CHECKBOT_RESULT($parser) {
	echo "$parser->packet_desc PacketLength=".$parser->word()."\n";
	echo "$parser->nl Result=".$parser->byte()."\n";
}

// packet 0x7ea
function PACKET_CZ_BATTLE_FIELD_LIST($parser) {
	echo "$parser->packet_desc \n";
}

// packet 0x7eb
function PACKET_ZC_BATTLE_FIELD_LIST($parser) {
	echo "$parser->packet_desc PacketLength=".$parser->word()."\n";
	echo "$parser->nl Count=".$parser->word()."\n";
	echo "$parser->nl ack_type=".$parser->word()."\n";
	$InfoList = ($parser->packet_length - $parser->packet_pointer) / 62;
	for ($i = 0; $i < $InfoList; $i++) {
		echo "$parser->nl BFNO=".$parser->long()."\n";
		echo "$parser->nl BattleFieldName=".$parser->string(56)."\n";
		echo "$parser->nl JoinTeam=".$parser->word()."\n";
	}
}

// packet 0x7ec
function PACKET_CZ_JOIN_BATTLE_FIELD($parser) {
	echo "$parser->packet_desc BFNO=".$parser->long()."\n";
	echo "$parser->nl JoinTeam=".$parser->word()."\n";
}

// packet 0x7ed
function PACKET_ZC_JOIN_BATTLE_FIELD($parser) {
	echo "$parser->packet_desc BFNO=".$parser->long()."\n";
	echo "$parser->nl JoinTeam=".$parser->word()."\n";
	echo "$parser->nl Result=".$parser->word()."\n";
}

// packet 0x7ee
function PACKET_CZ_CANCEL_BATTLE_FIELD($parser) {
	echo "$parser->packet_desc BFNO=".$parser->long()."\n";
}

// packet 0x7ef
function PACKET_ZC_CANCEL_BATTLE_FIELD($parser) {
	echo "$parser->packet_desc BFNO=".$parser->long()."\n";
	echo "$parser->nl Result=".$parser->word()."\n";
}

// packet 0x7f0
function PACKET_CZ_REQ_BATTLE_STATE_MONITOR($parser) {
	echo "$parser->packet_desc BFNO=".$parser->long()."\n";
	echo "$parser->nl PowerSwitch=".$parser->word()."\n";
}

// packet 0x7f1
function PACKET_ZC_ACK_BATTLE_STATE_MONITOR($parser) {
	echo "$parser->packet_desc BFNO=".$parser->long()."\n";
	echo "$parser->nl PlayCount=".$parser->word()."\n";
	echo "$parser->nl BattleState=".$parser->word()."\n";
	echo "$parser->nl TeamCount_A=".$parser->word()."\n";
	echo "$parser->nl TeamCount_B=".$parser->word()."\n";
	echo "$parser->nl MyCount=".$parser->word()."\n";
	echo "$parser->nl JoinTeam=".$parser->word()."\n";
}

// packet 0x7f2
function PACKET_ZC_BATTLE_NOTI_START_STEP($parser) {
	echo "$parser->packet_desc BFNO=".$parser->long()."\n";
	echo "$parser->nl Result=".$parser->word()."\n";
}

// packet 0x7f3
function PACKET_ZC_BATTLE_JOIN_NOTI_DEFER($parser) {
	echo "$parser->packet_desc BFNO=".$parser->long()."\n";
}

// packet 0x7f4
function PACKET_ZC_BATTLE_JOIN_DISABLE_STATE($parser) {
	echo "$parser->packet_desc Enable=".$parser->byte()."\n";
}

// packet 0x7f5
function PACKET_CZ_GM_FULLSTRIP($parser) {
	echo "$parser->packet_desc TargetAID=".$parser->long()."\n";
}

// packet 0x7f6
function PACKET_ZC_NOTIFY_EXP($parser) {
	echo "$parser->packet_desc AID=".$parser->long()."\n";
	echo "$parser->nl amount=".$parser->long()."\n";
	echo "$parser->nl varID=".$parser->word()."\n";
	echo "$parser->nl expType=".$parser->word()."\n";
}

// packet 0x7f7
function PACKET_ZC_NOTIFY_MOVEENTRY7($parser) {
	echo "$parser->packet_desc PacketLength=".$parser->word()."\n";
	echo "$parser->nl objecttype=".$parser->byte()."\n";
	echo "$parser->nl GID=".$parser->long()."\n";
	echo "$parser->nl speed=".$parser->word()."\n";
	echo "$parser->nl bodyState=".$parser->word()."\n";
	echo "$parser->nl healthState=".$parser->word()."\n";
	echo "$parser->nl effectState=".$parser->long()."\n";
	echo "$parser->nl job=".$parser->word()."\n";
	echo "$parser->nl head=".$parser->word()."\n";
	echo "$parser->nl weapon=".$parser->long()."\n";
	echo "$parser->nl accessory=".$parser->word()."\n";
	echo "$parser->nl moveStartTime=".$parser->long()."\n";
	echo "$parser->nl accessory2=".$parser->word()."\n";
	echo "$parser->nl accessory3=".$parser->word()."\n";
	echo "$parser->nl headpalette=".$parser->word()."\n";
	echo "$parser->nl bodypalette=".$parser->word()."\n";
	echo "$parser->nl headDir=".$parser->word()."\n";
	echo "$parser->nl GUID=".$parser->long()."\n";
	echo "$parser->nl GEmblemVer=".$parser->word()."\n";
	echo "$parser->nl honor=".$parser->word()."\n";
	echo "$parser->nl virtue=".$parser->long()."\n";
	echo "$parser->nl isPKModeON=".$parser->byte()."\n";
	echo "$parser->nl sex=".$parser->byte()."\n";
	echo "$parser->nl MoveData=".$parser->xyxy()."\n";
	echo "$parser->nl xSize=".$parser->byte()."\n";
	echo "$parser->nl ySize=".$parser->byte()."\n";
	echo "$parser->nl clevel=".$parser->word()."\n";
	echo "$parser->nl font=".$parser->word()."\n";
	echo "$parser->nl name=".$parser->string(24)."\n";
}

// packet 0x7f8
function PACKET_ZC_NOTIFY_NEWENTRY5($parser) {
	echo "$parser->packet_desc PacketLength=".$parser->word()."\n";
	echo "$parser->nl objecttype=".$parser->byte()."\n";
	echo "$parser->nl GID=".$parser->long()."\n";
	echo "$parser->nl speed=".$parser->word()."\n";
	echo "$parser->nl bodyState=".$parser->word()."\n";
	echo "$parser->nl healthState=".$parser->word()."\n";
	echo "$parser->nl effectState=".$parser->long()."\n";
	echo "$parser->nl job=".$parser->word()."\n";
	echo "$parser->nl head=".$parser->word()."\n";
	echo "$parser->nl weapon=".$parser->long()."\n";
	echo "$parser->nl accessory=".$parser->word()."\n";
	echo "$parser->nl accessory2=".$parser->word()."\n";
	echo "$parser->nl accessory3=".$parser->word()."\n";
	echo "$parser->nl headpalette=".$parser->word()."\n";
	echo "$parser->nl bodypalette=".$parser->word()."\n";
	echo "$parser->nl headDir=".$parser->word()."\n";
	echo "$parser->nl GUID=".$parser->long()."\n";
	echo "$parser->nl GEmblemVer=".$parser->word()."\n";
	echo "$parser->nl honor=".$parser->word()."\n";
	echo "$parser->nl virtue=".$parser->long()."\n";
	echo "$parser->nl isPKModeON=".$parser->byte()."\n";
	echo "$parser->nl sex=".$parser->byte()."\n";
	echo "$parser->nl PosDir=".$parser->xy()."\n";
	echo "$parser->nl xSize=".$parser->byte()."\n";
	echo "$parser->nl ySize=".$parser->byte()."\n";
	echo "$parser->nl clevel=".$parser->word()."\n";
	echo "$parser->nl font=".$parser->word()."\n";
	echo "$parser->nl name=".$parser->string(24)."\n";
}

// packet 0x7f9
function PACKET_ZC_NOTIFY_STANDENTRY5($parser) {
	echo "$parser->packet_desc PacketLength=".$parser->word()."\n";
	echo "$parser->nl objecttype=".$parser->byte()."\n";
	echo "$parser->nl GID=".$parser->long()."\n";
	echo "$parser->nl speed=".$parser->word()."\n";
	echo "$parser->nl bodyState=".$parser->word()."\n";
	echo "$parser->nl healthState=".$parser->word()."\n";
	echo "$parser->nl effectState=".$parser->long()."\n";
	echo "$parser->nl job=".$parser->word()."\n";
	echo "$parser->nl head=".$parser->word()."\n";
	echo "$parser->nl weapon=".$parser->long()."\n";
	echo "$parser->nl accessory=".$parser->word()."\n";
	echo "$parser->nl accessory2=".$parser->word()."\n";
	echo "$parser->nl accessory3=".$parser->word()."\n";
	echo "$parser->nl headpalette=".$parser->word()."\n";
	echo "$parser->nl bodypalette=".$parser->word()."\n";
	echo "$parser->nl headDir=".$parser->word()."\n";
	echo "$parser->nl GUID=".$parser->long()."\n";
	echo "$parser->nl GEmblemVer=".$parser->word()."\n";
	echo "$parser->nl honor=".$parser->word()."\n";
	echo "$parser->nl virtue=".$parser->long()."\n";
	echo "$parser->nl isPKModeON=".$parser->byte()."\n";
	echo "$parser->nl sex=".$parser->byte()."\n";
	echo "$parser->nl PosDir=".$parser->xy()."\n";
	echo "$parser->nl xSize=".$parser->byte()."\n";
	echo "$parser->nl ySize=".$parser->byte()."\n";
	echo "$parser->nl state=".$parser->byte()."\n";
	echo "$parser->nl clevel=".$parser->word()."\n";
	echo "$parser->nl font=".$parser->word()."\n";
	echo "$parser->nl name=".$parser->string(24)."\n";
}

// packet 0x7fa
function PACKET_ZC_DELETE_ITEM_FROM_BODY($parser) {
	echo "$parser->packet_desc DeleteType=".$parser->word()."\n";
	echo "$parser->nl Index=".$parser->word()."\n";
	echo "$parser->nl Count=".$parser->word()."\n";
}

// packet 0x7fb
function PACKET_ZC_USESKILL_ACK2($parser) {
	echo "$parser->packet_desc AID=".$parser->long()."\n";
	echo "$parser->nl targetID=".$parser->long()."\n";
	echo "$parser->nl xPos=".$parser->word()."\n";
	echo "$parser->nl yPos=".$parser->word()."\n";
	echo "$parser->nl SKID=".$parser->word()."\n";
	echo "$parser->nl property=".$parser->long()."\n";
	echo "$parser->nl delayTime=".$parser->long()."\n";
	echo "$parser->nl isDisposable=".$parser->byte()."\n";
}

// packet 0x7fc
function PACKET_ZC_CHANGE_GROUP_MASTER($parser) {
	echo "$parser->packet_desc OldMasterAID=".$parser->long()."\n";
	echo "$parser->nl NewMasterAID=".$parser->long()."\n";
}

// packet 0x7fe
function PACKET_ZC_PLAY_NPC_BGM($parser) {
	echo "$parser->packet_desc Bgm=".$parser->string(24)."\n";
}

// packet 0x7ff
function PACKET_ZC_DEFINE_CHECK($parser) {
	echo "$parser->packet_desc PacketLength=".$parser->word()."\n";
	echo "$parser->nl Result=".$parser->long()."\n";
}

// packet 0x800
function PACKET_ZC_PC_PURCHASE_ITEMLIST_FROMMC2($parser) {
	echo "$parser->packet_desc PacketLength=".$parser->word()."\n";
	echo "$parser->nl AID=".$parser->long()."\n";
	echo "$parser->nl UniqueID=".$parser->long()."\n";
	$itemList = ($parser->packet_length - $parser->packet_pointer) / 22;
	for ($i = 0; $i < $itemList; $i++) {
		echo "$parser->nl price=".$parser->long()."\n";
		echo "$parser->nl count=".$parser->word()."\n";
		echo "$parser->nl index=".$parser->word()."\n";
		echo "$parser->nl type=".$parser->byte()."\n";
		echo "$parser->nl ITID=".$parser->word()."\n";
		echo "$parser->nl IsIdentified=".$parser->byte()."\n";
		echo "$parser->nl IsDamaged=".$parser->byte()."\n";
		echo "$parser->nl refiningLevel=".$parser->byte()."\n";
		echo "$parser->nl card1=".$parser->word()."\n";
		echo "$parser->nl card2=".$parser->word()."\n";
		echo "$parser->nl card3=".$parser->word()."\n";
		echo "$parser->nl card4=".$parser->word()."\n";
	}
}

// packet 0x801
function PACKET_CZ_PC_PURCHASE_ITEMLIST_FROMMC2($parser) {
	echo "$parser->packet_desc PacketLength=".$parser->word()."\n";
	echo "$parser->nl AID=".$parser->long()."\n";
	echo "$parser->nl UniqueID=".$parser->long()."\n";
	$itemList = ($parser->packet_length - $parser->packet_pointer) / 4;
	for ($i = 0; $i < $itemList; $i++) {
		echo "$parser->nl count=".$parser->word()."\n";
		echo "$parser->nl index=".$parser->word()."\n";
	}
}

// packet 0x802
function PACKET_CZ_PARTY_BOOKING_REQ_REGISTER($parser) {
	echo "$parser->packet_desc ";
		echo "$parser->nl Level=".$parser->word()."\n";
		echo "$parser->nl MapID=".$parser->word()."\n";
		echo "$parser->nl Job=".$parser->word()."\n";
}

// packet 0x803
function PACKET_ZC_PARTY_BOOKING_ACK_REGISTER($parser) {
	echo "$parser->packet_desc Result=".$parser->word()."\n";
}

// packet 0x804
function PACKET_CZ_PARTY_BOOKING_REQ_SEARCH($parser) {
	echo "$parser->packet_desc Level=".$parser->word()."\n";
	echo "$parser->nl MapID=".$parser->word()."\n";
	echo "$parser->nl Job=".$parser->word()."\n";
	echo "$parser->nl LastIndex=".$parser->long()."\n";
	echo "$parser->nl ResultCount=".$parser->word()."\n";
}

// packet 0x805
function PACKET_ZC_PARTY_BOOKING_ACK_SEARCH($parser) {
	echo "$parser->packet_desc PacketLength=".$parser->word()."\n";
	echo "$parser->nl IsExistMoreResult=".$parser->byte()."\n";
	$Info = ($parser->packet_length - $parser->packet_pointer) / 48;
	for ($i = 0; $i < $Info; $i++) {
		echo "$parser->nl Index=".$parser->long()."\n";
		echo "$parser->nl CharName=".$parser->string(24)."\n";
		echo "$parser->nl ExpireTime=".$parser->long()."\n";
		echo "$parser->nl Level=".$parser->word()."\n";
		echo "$parser->nl MapID=".$parser->word()."\n";
		echo "$parser->nl Job=".$parser->word()."\n";
	}
}

// packet 0x806
function PACKET_CZ_PARTY_BOOKING_REQ_DELETE($parser) {
	echo "$parser->packet_desc \n";
}

// packet 0x807
function PACKET_ZC_PARTY_BOOKING_ACK_DELETE($parser) {
	echo "$parser->packet_desc Result=".$parser->word()."\n";
}

// packet 0x808
function PACKET_CZ_PARTY_BOOKING_REQ_UPDATE($parser) {
	echo "$parser->packet_desc Job=".$parser->word()."\n";
}

// packet 0x809
function PACKET_ZC_PARTY_BOOKING_NOTIFY_INSERT($parser) {
	echo "$parser->packet_desc ";
		echo "$parser->nl Index=".$parser->long()."\n";
		echo "$parser->nl CharName=".$parser->string(24)."\n";
		echo "$parser->nl ExpireTime=".$parser->long()."\n";
		echo "$parser->nl Level=".$parser->word()."\n";
		echo "$parser->nl MapID=".$parser->word()."\n";
		echo "$parser->nl Job1=".$parser->word()."\n";
		echo "$parser->nl Job2=".$parser->word()."\n";
		echo "$parser->nl Job3=".$parser->word()."\n";
		echo "$parser->nl Job4=".$parser->word()."\n";
		echo "$parser->nl Job5=".$parser->word()."\n";
		echo "$parser->nl Job6=".$parser->word()."\n";
}

// packet 0x80a
function PACKET_ZC_PARTY_BOOKING_NOTIFY_UPDATE($parser) {
	echo "$parser->packet_desc Index=".$parser->long()."\n";
	echo "$parser->nl Job1=".$parser->word()."\n";
	echo "$parser->nl Job2=".$parser->word()."\n";
	echo "$parser->nl Job3=".$parser->word()."\n";
	echo "$parser->nl Job4=".$parser->word()."\n";
	echo "$parser->nl Job5=".$parser->word()."\n";
	echo "$parser->nl Job6=".$parser->word()."\n";
}

// packet 0x80b
function PACKET_ZC_PARTY_BOOKING_NOTIFY_DELETE($parser) {
	echo "$parser->packet_desc Index=".$parser->long()."\n";
}

// packet 0x80c
function PACKET_CZ_SIMPLE_CASH_BTNSHOW($parser) {
	echo "$parser->packet_desc \n";
}

// packet 0x80d
function PACKET_ZC_SIMPLE_CASH_BTNSHOW($parser) {
	echo "$parser->packet_desc show=".$parser->byte()."\n";
}

// packet 0x80e
function PACKET_ZC_NOTIFY_HP_TO_GROUPM_R2($parser) {
	echo "$parser->packet_desc AID=".$parser->long()."\n";
	echo "$parser->nl hp=".$parser->long()."\n";
	echo "$parser->nl maxhp=".$parser->long()."\n";
}

// packet 0x80f
function PACKET_ZC_ADD_EXCHANGE_ITEM2($parser) {
	echo "$parser->packet_desc ITID=".$parser->word()."\n";
	echo "$parser->nl type=".$parser->byte()."\n";
	echo "$parser->nl count=".$parser->long()."\n";
	echo "$parser->nl IsIdentified=".$parser->byte()."\n";
	echo "$parser->nl IsDamaged=".$parser->byte()."\n";
	echo "$parser->nl refiningLevel=".$parser->byte()."\n";
		echo "$parser->nl card1=".$parser->word()."\n";
		echo "$parser->nl card2=".$parser->word()."\n";
		echo "$parser->nl card3=".$parser->word()."\n";
		echo "$parser->nl card4=".$parser->word()."\n";
}

// packet 0x810
function PACKET_ZC_OPEN_BUYING_STORE($parser) {
	echo "$parser->packet_desc count=".$parser->byte()."\n";
}

// packet 0x811
function PACKET_CZ_REQ_OPEN_BUYING_STORE($parser) {
	echo "$parser->packet_desc PacketLength=".$parser->word()."\n";
	echo "$parser->nl LimitZeny=".$parser->long()."\n";
	echo "$parser->nl result=".$parser->byte()."\n";
	echo "$parser->nl storeName=".$parser->string(80)."\n";
	$ItemList = ($parser->packet_length - $parser->packet_pointer) / 8;
	for ($i = 0; $i < $ItemList; $i++) {
		echo "$parser->nl ITID=".$parser->word()."\n";
		echo "$parser->nl count=".$parser->word()."\n";
		echo "$parser->nl price=".$parser->long()."\n";
	}
}

// packet 0x812
function PACKET_ZC_FAILED_OPEN_BUYING_STORE_TO_BUYER($parser) {
	echo "$parser->packet_desc Result=".$parser->word()."\n";
	echo "$parser->nl total_weight=".$parser->long()."\n";
}

// packet 0x813
function PACKET_ZC_MYITEMLIST_BUYING_STORE($parser) {
	echo "$parser->packet_desc PacketLength=".$parser->word()."\n";
	echo "$parser->nl AID=".$parser->long()."\n";
	echo "$parser->nl limitZeny=".$parser->long()."\n";
	$ItemList = ($parser->packet_length - $parser->packet_pointer) / 9;
	for ($i = 0; $i < $ItemList; $i++) {
		echo "$parser->nl price=".$parser->long()."\n";
		echo "$parser->nl count=".$parser->word()."\n";
		echo "$parser->nl type=".$parser->byte()."\n";
		echo "$parser->nl ITID=".$parser->word()."\n";
	}
}

// packet 0x814
function PACKET_ZC_BUYING_STORE_ENTRY($parser) {
	echo "$parser->packet_desc makerAID=".$parser->long()."\n";
	echo "$parser->nl storeName=".$parser->string(80)."\n";
}

// packet 0x815
function PACKET_CZ_REQ_CLOSE_BUYING_STORE($parser) {
	echo "$parser->packet_desc \n";
}

// packet 0x816
function PACKET_ZC_DISAPPEAR_BUYING_STORE_ENTRY($parser) {
	echo "$parser->packet_desc makerAID=".$parser->long()."\n";
}

// packet 0x817
function PACKET_CZ_REQ_CLICK_TO_BUYING_STORE($parser) {
	echo "$parser->packet_desc makerAID=".$parser->long()."\n";
}

// packet 0x818
function PACKET_ZC_ACK_ITEMLIST_BUYING_STORE($parser) {
	echo "$parser->packet_desc PacketLength=".$parser->word()."\n";
	echo "$parser->nl makerAID=".$parser->long()."\n";
	echo "$parser->nl StoreID=".$parser->long()."\n";
	echo "$parser->nl limitZeny=".$parser->long()."\n";
	$ItemList = ($parser->packet_length - $parser->packet_pointer) / 9;
	for ($i = 0; $i < $ItemList; $i++) {
		echo "$parser->nl price=".$parser->long()."\n";
		echo "$parser->nl count=".$parser->word()."\n";
		echo "$parser->nl type=".$parser->byte()."\n";
		echo "$parser->nl ITID=".$parser->word()."\n";
	}
}

// packet 0x819
function PACKET_CZ_REQ_TRADE_BUYING_STORE($parser) {
	echo "$parser->packet_desc PacketLength=".$parser->word()."\n";
	echo "$parser->nl makerAID=".$parser->long()."\n";
	echo "$parser->nl StoreID=".$parser->long()."\n";
	$ItemList = ($parser->packet_length - $parser->packet_pointer) / 6;
	for ($i = 0; $i < $ItemList; $i++) {
		echo "$parser->nl index=".$parser->word()."\n";
		echo "$parser->nl ITID=".$parser->word()."\n";
		echo "$parser->nl count=".$parser->word()."\n";
	}
}

// packet 0x81a
function PACKET_ZC_FAILED_TRADE_BUYING_STORE_TO_BUYER($parser) {
	echo "$parser->packet_desc Result=".$parser->word()."\n";
}

// packet 0x81b
function PACKET_ZC_UPDATE_ITEM_FROM_BUYING_STORE($parser) {
	echo "$parser->packet_desc ITID=".$parser->word()."\n";
	echo "$parser->nl count=".$parser->word()."\n";
	echo "$parser->nl limitZeny=".$parser->long()."\n";
}

// packet 0x81c
function PACKET_ZC_ITEM_DELETE_BUYING_STORE($parser) {
	echo "$parser->packet_desc index=".$parser->word()."\n";
	echo "$parser->nl count=".$parser->word()."\n";
	echo "$parser->nl zeny=".$parser->long()."\n";
}

// packet 0x81d
function PACKET_ZC_EL_INIT($parser) {
	echo "$parser->packet_desc AID=".$parser->long()."\n";
	echo "$parser->nl hp=".$parser->long()."\n";
	echo "$parser->nl maxHP=".$parser->long()."\n";
	echo "$parser->nl sp=".$parser->long()."\n";
	echo "$parser->nl maxSP=".$parser->long()."\n";
}

// packet 0x81e
function PACKET_ZC_EL_PAR_CHANGE($parser) {
	echo "$parser->packet_desc var=".$parser->word()."\n";
	echo "$parser->nl value=".$parser->long()."\n";
}

// packet 0x81f
function PACKET_ZC_BROADCAST4($parser) {
	echo "$parser->packet_desc PakcetType=".$parser->word()."\n";
	echo "$parser->nl PacketLength=".$parser->word()."\n";
	echo "$parser->nl Msgtype=".$parser->byte()."\n";
	echo "$parser->nl ColorRGB=".$parser->long()."\n";
	echo "$parser->nl msg=".$parser->string($parser->packet_length - $parser->packet_pointer)."\n";
}

// packet 0x820
function PACKET_ZC_COSTUME_SPRITE_CHANGE($parser) {
	echo "$parser->packet_desc GID=".$parser->long()."\n";
	echo "$parser->nl type=".$parser->byte()."\n";
	echo "$parser->nl value=".$parser->long()."\n";
}

// packet 0x821
function PACKET_AC_OTP_USER($parser) {
	echo "$parser->packet_desc \n";
}

// packet 0x822
function PACKET_CA_OTP_AUTH_REQ($parser) {
	echo "$parser->packet_desc OTPCode=".$parser->string(7)."\n";
}

// packet 0x823
function PACKET_AC_OTP_AUTH_ACK($parser) {
	echo "$parser->packet_desc PacketLength=".$parser->word()."\n";
	echo "$parser->nl LoginResult=".$parser->word()."\n";
}

// packet 0x824
function PACKET_ZC_FAILED_TRADE_BUYING_STORE_TO_SELLER($parser) {
	echo "$parser->packet_desc Result=".$parser->word()."\n";
	echo "$parser->nl ITID=".$parser->word()."\n";
}

// packet 0x825a
function PACKET_CA_SSO_LOGIN_REQa($parser) {
	echo "$parser->packet_desc PacketLength=".$parser->word()."\n";
	echo "$parser->nl Version=".$parser->long()."\n";
	echo "$parser->nl clienttype=".$parser->byte()."\n";
	echo "$parser->nl ID=".$parser->string(24)."\n";
	echo "$parser->nl MacAddr=".$parser->string(17)."\n";
	echo "$parser->nl IpAddr=".$parser->string(15)."\n";
	echo "$parser->nl t1=".$parser->string($parser->packet_length - $parser->packet_pointer)."\n";
}

// packet 0x825
function PACKET_CA_SSO_LOGIN_REQ($parser) {
	echo "$parser->packet_desc PacketLength=".$parser->word()."\n";
	echo "$parser->nl Version=".$parser->long()."\n";
	echo "$parser->nl clienttype=".$parser->byte()."\n";
	echo "$parser->nl ID=".$parser->string(24)."\n";
	echo "$parser->nl Passwd=".$parser->string(27)."\n";
	echo "$parser->nl MacAdress=".$parser->string(17)."\n";
	echo "$parser->nl IP=".$parser->string(15)."\n";
	echo "$parser->nl t1=".$parser->string($parser->packet_length - $parser->packet_pointer)."\n";
}

// packet 0x826
function PACKET_AC_SSO_LOGIN_ACK($parser) {
	echo "$parser->packet_desc Result=".$parser->word()."\n";
}

// packet 0x827
function PACKET_CH_DELETE_CHAR3_RESERVED($parser) {
	echo "$parser->packet_desc GID=".$parser->long()."\n";
}

// packet 0x828
function PACKET_HC_DELETE_CHAR3_RESERVED($parser) {
	echo "$parser->packet_desc GID=".$parser->long()."\n";
	echo "$parser->nl Result=".$parser->long()."\n";
	echo "$parser->nl DeleteReservedDate=".$parser->long()."\n";
}

// packet 0x829
function PACKET_CH_DELETE_CHAR3($parser) {
	echo "$parser->packet_desc GID=".$parser->long()."\n";
	echo "$parser->nl Birth=".$parser->string(6)."\n";
}

// packet 0x82a
function PACKET_HC_DELETE_CHAR3($parser) {
	echo "$parser->packet_desc GID=".$parser->long()."\n";
	echo "$parser->nl Result=".$parser->long()."\n";
}

// packet 0x82b
function PACKET_CH_DELETE_CHAR3_CANCEL($parser) {
	echo "$parser->packet_desc GID=".$parser->long()."\n";
}

// packet 0x82c
function PACKET_HC_DELETE_CHAR3_CANCEL($parser) {
	echo "$parser->packet_desc GID=".$parser->long()."\n";
	echo "$parser->nl Result=".$parser->long()."\n";
}

// packet 0x82d
function PACKET_HC_ACCEPT2($parser) {
	echo "$parser->packet_desc PacketLength=".$parser->word()."\n";
	echo "$parser->nl NormalSlotNum=".$parser->byte()."\n";
	echo "$parser->nl PremiumSlotNum=".$parser->byte()."\n";
	echo "$parser->nl BillingSlotNum=".$parser->byte()."\n";
	echo "$parser->nl ProducibleSlotNum=".$parser->byte()."\n";
	echo "$parser->nl ValidSlotNum=".$parser->byte()."\n";
	echo "$parser->nl m_extension=".$parser->string(20)."\n";
	$charInfo = ($parser->packet_length - $parser->packet_pointer) / 116;
	for ($i = 0; $i < $charInfo; $i++) {
		echo "$parser->nl GID=".$parser->long()."\n";
		echo "$parser->nl exp=".$parser->long()."\n";
		echo "$parser->nl money=".$parser->long()."\n";
		echo "$parser->nl jobexp=".$parser->long()."\n";
		echo "$parser->nl joblevel=".$parser->long()."\n";
		echo "$parser->nl bodystate=".$parser->long()."\n";
		echo "$parser->nl healthstate=".$parser->long()."\n";
		echo "$parser->nl effectstate=".$parser->long()."\n";
		echo "$parser->nl virtue=".$parser->long()."\n";
		echo "$parser->nl honor=".$parser->long()."\n";
		echo "$parser->nl jobpoint=".$parser->word()."\n";
		echo "$parser->nl hp=".$parser->long()."\n";
		echo "$parser->nl maxhp=".$parser->long()."\n";
		echo "$parser->nl sp=".$parser->word()."\n";
		echo "$parser->nl maxsp=".$parser->word()."\n";
		echo "$parser->nl speed=".$parser->word()."\n";
		echo "$parser->nl job=".$parser->word()."\n";
		echo "$parser->nl head=".$parser->word()."\n";
		echo "$parser->nl weapon=".$parser->word()."\n";
		echo "$parser->nl level=".$parser->word()."\n";
		echo "$parser->nl sppoint=".$parser->word()."\n";
		echo "$parser->nl accessory=".$parser->word()."\n";
		echo "$parser->nl shield=".$parser->word()."\n";
		echo "$parser->nl accessory2=".$parser->word()."\n";
		echo "$parser->nl accessory3=".$parser->word()."\n";
		echo "$parser->nl headpalette=".$parser->word()."\n";
		echo "$parser->nl bodypalette=".$parser->word()."\n";
		echo "$parser->nl name=".$parser->string(24)."\n";
		echo "$parser->nl Str=".$parser->byte()."\n";
		echo "$parser->nl Agi=".$parser->byte()."\n";
		echo "$parser->nl Vit=".$parser->byte()."\n";
		echo "$parser->nl Int=".$parser->byte()."\n";
		echo "$parser->nl Dex=".$parser->byte()."\n";
		echo "$parser->nl Luk=".$parser->byte()."\n";
		echo "$parser->nl CharNum=".$parser->byte()."\n";
		echo "$parser->nl haircolor=".$parser->byte()."\n";
		echo "$parser->nl bIsChangedCharName=".$parser->word()."\n";
		echo "$parser->nl Robe=".$parser->long()."\n";
	}
}

// packet 0x835
function PACKET_CZ_SEARCH_STORE_INFO($parser) {
	echo "$parser->packet_desc PacketLength=".$parser->word()."\n";
	echo "$parser->nl StoreType=".$parser->byte()."\n";
	echo "$parser->nl maxPrice=".$parser->long()."\n";
	echo "$parser->nl minPrice=".$parser->long()."\n";
	echo "$parser->nl ItemIDListSize=".$parser->byte()."\n";
	echo "$parser->nl CardIDListSize=".$parser->byte()."\n";
}

// packet 0x836
function PACKET_ZC_SEARCH_STORE_INFO_ACK($parser) {
	echo "$parser->packet_desc PacketLength=".$parser->word()."\n";
	echo "$parser->nl IsFirstPage=".$parser->byte()."\n";
	echo "$parser->nl IsNexPage=".$parser->byte()."\n";
	echo "$parser->nl RemainedSearchCnt=".$parser->byte()."\n";
	$SSI_List = ($parser->packet_length - $parser->packet_pointer) / 106;
	for ($i = 0; $i < $SSI_List; $i++) {
		echo "$parser->nl SSI_ID=".$parser->long()."\n";
		echo "$parser->nl AID=".$parser->long()."\n";
		echo "$parser->nl StoreName=".$parser->string(80)."\n";
		echo "$parser->nl ITID=".$parser->word()."\n";
		echo "$parser->nl ItemType=".$parser->byte()."\n";
		echo "$parser->nl price=".$parser->long()."\n";
		echo "$parser->nl count=".$parser->word()."\n";
		echo "$parser->nl refiningLevel=".$parser->byte()."\n";
		echo "$parser->nl card1=".$parser->word()."\n";
		echo "$parser->nl card2=".$parser->word()."\n";
		echo "$parser->nl card3=".$parser->word()."\n";
		echo "$parser->nl card4=".$parser->word()."\n";
	}
}

// packet 0x837
function PACKET_ZC_SEARCH_STORE_INFO_FAILED($parser) {
	echo "$parser->packet_desc Reason=".$parser->byte()."\n";
}

// packet 0x838
function PACKET_CZ_SEARCH_STORE_INFO_NEXT_PAGE($parser) {
	echo "$parser->packet_desc \n";
}

// packet 0x839
function PACKET_ZC_ACK_BAN_GUILD_SSO($parser) {
	echo "$parser->packet_desc charName=".$parser->string(24)."\n";
	echo "$parser->nl reasonDesc=".$parser->string(40)."\n";
}

// packet 0x83a
function PACKET_ZC_OPEN_SEARCH_STORE_INFO($parser) {
	echo "$parser->packet_desc OpenType=".$parser->word()."\n";
	echo "$parser->nl SearchCntMax=".$parser->byte()."\n";
}

// packet 0x83b
function PACKET_CZ_CLOSE_SEARCH_STORE_INFO($parser) {
	echo "$parser->packet_desc \n";
}

// packet 0x83c
function PACKET_CZ_SSILIST_ITEM_CLICK($parser) {
	echo "$parser->packet_desc AID=".$parser->long()."\n";
	echo "$parser->nl SSI_ID=".$parser->long()."\n";
	echo "$parser->nl ITID=".$parser->word()."\n";
}

// packet 0x83d
function PACKET_ZC_SSILIST_ITEM_CLICK_ACK($parser) {
	echo "$parser->packet_desc x=".$parser->word()."\n";
	echo "$parser->nl y=".$parser->word()."\n";
}

// packet 0x83e
function PACKET_AC_REFUSE_LOGIN_R2($parser) {
	echo "$parser->packet_desc ErrorCode=".$parser->long()."\n";
	echo "$parser->nl blockDate=".$parser->string(20)."\n";
}

// packet 0x841
function PACKET_CH_SELECT_ACCESSIBLE_MAPNAME($parser) {
	echo "$parser->packet_desc CharNum=".$parser->byte()."\n";
	echo "$parser->nl mapListNum=".$parser->byte()."\n";
}

// packet 0x856
function PACKET_ZC_NOTIFY_MOVEENTRY8($parser) {
	echo "$parser->packet_desc PacketLength=".$parser->word()."\n";
	echo "$parser->nl objecttype=".$parser->byte()."\n";
	echo "$parser->nl GID=".$parser->long()."\n";
	echo "$parser->nl speed=".$parser->word()."\n";
	echo "$parser->nl bodyState=".$parser->word()."\n";
	echo "$parser->nl healthState=".$parser->word()."\n";
	echo "$parser->nl effectState=".$parser->long()."\n";
	echo "$parser->nl job=".$parser->word()."\n";
	echo "$parser->nl head=".$parser->word()."\n";
	echo "$parser->nl weapon=".$parser->long()."\n";
	echo "$parser->nl accessory=".$parser->word()."\n";
	echo "$parser->nl moveStartTime=".$parser->long()."\n";
	echo "$parser->nl accessory2=".$parser->word()."\n";
	echo "$parser->nl accessory3=".$parser->word()."\n";
	echo "$parser->nl headpalette=".$parser->word()."\n";
	echo "$parser->nl bodypalette=".$parser->word()."\n";
	echo "$parser->nl headDir=".$parser->word()."\n";
	echo "$parser->nl robe=".$parser->word()."\n";
	echo "$parser->nl GUID=".$parser->long()."\n";
	echo "$parser->nl GEmblemVer=".$parser->word()."\n";
	echo "$parser->nl honor=".$parser->word()."\n";
	echo "$parser->nl virtue=".$parser->long()."\n";
	echo "$parser->nl isPKModeON=".$parser->byte()."\n";
	echo "$parser->nl sex=".$parser->byte()."\n";
	echo "$parser->nl MoveData=".$parser->xyxy()."\n";
	echo "$parser->nl xSize=".$parser->byte()."\n";
	echo "$parser->nl ySize=".$parser->byte()."\n";
	echo "$parser->nl clevel=".$parser->word()."\n";
	echo "$parser->nl font=".$parser->word()."\n";
}

// packet 0x857
function PACKET_ZC_NOTIFY_STANDENTRY7($parser) {
	echo "$parser->packet_desc PacketLength=".$parser->word()."\n";
	echo "$parser->nl objecttype=".$parser->byte()."\n";
	echo "$parser->nl GID=".$parser->long()."\n";
	echo "$parser->nl speed=".$parser->word()."\n";
	echo "$parser->nl bodyState=".$parser->word()."\n";
	echo "$parser->nl healthState=".$parser->word()."\n";
	echo "$parser->nl effectState=".$parser->long()."\n";
	echo "$parser->nl job=".$parser->word()."\n";
	echo "$parser->nl head=".$parser->word()."\n";
	echo "$parser->nl weapon=".$parser->long()."\n";
	echo "$parser->nl accessory=".$parser->word()."\n";
	echo "$parser->nl accessory2=".$parser->word()."\n";
	echo "$parser->nl accessory3=".$parser->word()."\n";
	echo "$parser->nl headpalette=".$parser->word()."\n";
	echo "$parser->nl bodypalette=".$parser->word()."\n";
	echo "$parser->nl headDir=".$parser->word()."\n";
	echo "$parser->nl robe=".$parser->word()."\n";
	echo "$parser->nl GUID=".$parser->long()."\n";
	echo "$parser->nl GEmblemVer=".$parser->word()."\n";
	echo "$parser->nl honor=".$parser->word()."\n";
	echo "$parser->nl virtue=".$parser->long()."\n";
	echo "$parser->nl isPKModeON=".$parser->byte()."\n";
	echo "$parser->nl sex=".$parser->byte()."\n";
	echo "$parser->nl PosDir=".$parser->xy()."\n";
	echo "$parser->nl xSize=".$parser->byte()."\n";
	echo "$parser->nl ySize=".$parser->byte()."\n";
	echo "$parser->nl state=".$parser->byte()."\n";
	echo "$parser->nl clevel=".$parser->word()."\n";
	echo "$parser->nl font=".$parser->word()."\n";
}

// packet 0x858
function PACKET_ZC_NOTIFY_NEWENTRY6($parser) {
	echo "$parser->packet_desc PacketLength=".$parser->word()."\n";
	echo "$parser->nl objecttype=".$parser->byte()."\n";
	echo "$parser->nl GID=".$parser->long()."\n";
	echo "$parser->nl speed=".$parser->word()."\n";
	echo "$parser->nl bodyState=".$parser->word()."\n";
	echo "$parser->nl healthState=".$parser->word()."\n";
	echo "$parser->nl effectState=".$parser->long()."\n";
	echo "$parser->nl job=".$parser->word()."\n";
	echo "$parser->nl head=".$parser->word()."\n";
	echo "$parser->nl weapon=".$parser->long()."\n";
	echo "$parser->nl accessory=".$parser->word()."\n";
	echo "$parser->nl accessory2=".$parser->word()."\n";
	echo "$parser->nl accessory3=".$parser->word()."\n";
	echo "$parser->nl headpalette=".$parser->word()."\n";
	echo "$parser->nl bodypalette=".$parser->word()."\n";
	echo "$parser->nl headDir=".$parser->word()."\n";
	echo "$parser->nl robe=".$parser->word()."\n";
	echo "$parser->nl GUID=".$parser->long()."\n";
	echo "$parser->nl GEmblemVer=".$parser->word()."\n";
	echo "$parser->nl honor=".$parser->word()."\n";
	echo "$parser->nl virtue=".$parser->long()."\n";
	echo "$parser->nl isPKModeON=".$parser->byte()."\n";
	echo "$parser->nl sex=".$parser->byte()."\n";
	echo "$parser->nl PosDir=".$parser->xy()."\n";
	echo "$parser->nl xSize=".$parser->byte()."\n";
	echo "$parser->nl ySize=".$parser->byte()."\n";
	echo "$parser->nl clevel=".$parser->word()."\n";
	echo "$parser->nl font=".$parser->word()."\n";
}

// packet 0x859
function PACKET_ZC_EQUIPWIN_MICROSCOPE2($parser) {
	echo "$parser->packet_desc Length=".$parser->word()."\n";
	echo "$parser->nl characterName=".$parser->string(24)."\n";
	echo "$parser->nl job=".$parser->word()."\n";
	echo "$parser->nl head=".$parser->word()."\n";
	echo "$parser->nl accessory=".$parser->word()."\n";
	echo "$parser->nl accessory2=".$parser->word()."\n";
	echo "$parser->nl accessory3=".$parser->word()."\n";
	echo "$parser->nl robe=".$parser->word()."\n";
	echo "$parser->nl headpalette=".$parser->word()."\n";
	echo "$parser->nl bodypalette=".$parser->word()."\n";
	echo "$parser->nl sex=".$parser->byte()."\n";
}

// packet 0x8af
function PACKET_HC_WAITING_LOGIN($parser) {
	echo "$parser->packet_desc AID=".$parser->long()."\n";
	echo "$parser->nl CurWaitingNum=".$parser->long()."\n";
}

// packet 0x8b0
function PACKET_CH_WAITING_LOGIN($parser) {
	echo "$parser->packet_desc AID=".$parser->long()."\n";
	echo "$parser->nl AuthCode=".$parser->long()."\n";
	echo "$parser->nl userLevel=".$parser->long()."\n";
	echo "$parser->nl clientType=".$parser->word()."\n";
	echo "$parser->nl Sex=".$parser->byte()."\n";
}

// packet 0x8b7
function PACKET_HC_SECOND_PASSWD_REQ($parser) {
	echo "$parser->packet_desc AID=".$parser->long()."\n";
	echo "$parser->nl Seed=".$parser->long()."\n";
}

// packet 0x8b8
function PACKET_CH_SECOND_PASSWD_ACK($parser) {
	echo "$parser->packet_desc AID=".$parser->long()."\n";
	echo "$parser->nl SecondPWIdx=".$parser->string(6)."\n";
}

// packet 0x8b9
function PACKET_HC_SECOND_PASSWD_LOGIN($parser) {
	echo "$parser->packet_desc Result=".$parser->word()."\n";
}

// packet 0x8ba
function PACKET_CH_MAKE_SECOND_PASSWD($parser) {
	echo "$parser->packet_desc AID=".$parser->long()."\n";
	echo "$parser->nl Seed=".$parser->long()."\n";
	echo "$parser->nl SecondPWIdx=".$parser->string(6)."\n";
}

// packet 0x8bb
function PACKET_HC_MAKE_SECOND_PASSWD($parser) {
	echo "$parser->packet_desc Result=".$parser->word()."\n";
}

// packet 0x8bc
function PACKET_CH_DELETE_SECOND_PASSWD($parser) {
	echo "$parser->packet_desc AID=".$parser->long()."\n";
	echo "$parser->nl Seed=".$parser->long()."\n";
	echo "$parser->nl SecondPWIdx=".$parser->string(6)."\n";
}

// packet 0x8bd
function PACKET_HC_DELETE_SECOND_PASSWD($parser) {
	echo "$parser->packet_desc Result=".$parser->word()."\n";
}

// packet 0x8be
function PACKET_CH_EDIT_SECOND_PASSWD($parser) {
	echo "$parser->packet_desc AID=".$parser->long()."\n";
	echo "$parser->nl Seed=".$parser->long()."\n";
	echo "$parser->nl SecondPWIdx=".$parser->string(6)."\n";
}

// packet 0x8bf
function PACKET_HC_EDIT_SECOND_PASSWD($parser) {
	echo "$parser->packet_desc Result=".$parser->word()."\n";
}

?>
