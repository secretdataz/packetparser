<?php

// packet_parser functions
function PP_MODE_INIT($parser) {
	$parser->mode["mode_name"] = "eAthena_npc";	//
	$parser->mode["extra_bytes"] = false;		// warning about extra packet data
	$parser->mode["debug"] = true;				// write packets to file
	$parser->mode["save_npc"] = true;
	
	$parser->data['talking_to_npc'] = false;
	$parser->data['money'] = false;
	$parser->data['indent'] = 0;
	
	if($parser->mode["debug"]) {
		$debug_filename = "debug/".date("Ymd-gis").".txt";
		$parser->debug = fopen($debug_filename, "w");
	}
	if($parser->mode["save_npc"]) {
		$npc_filename = "npc_capture/".date("Ymd-gis").".txt";
		$parser->npc_file = fopen($npc_filename, "w");
	}
}

function echo_save($parser, $text){
	if($parser->data['indent'] < 0)
		$parser->data['indent'] = 0;
	$text = str_repeat("\t",$parser->data['indent']) . $text . "\n";
	echo $text;
	fwrite($parser->npc_file, $text);
}

function PACKET_HC_NOTIFY_ZONESVR($parser) {
	$parser->data['map'] = $parser->string(16, 6);
}

function PACKET_ZC_SAY_DIALOG($parser){
    $gid = $parser->long(4);
    if($parser->data['talking_to_npc'] == false){
        $parser->data['talking_to_npc'] = $gid;
        echo_save($parser,"\n\n".$parser->npc_list[$gid]['map'].",".$parser->npc_list[$gid]['x'].",".$parser->npc_list[$gid]['y'].","."4"."\tscript\t".$parser->npc_list[$gid]['name']."\t".$parser->npc_list[$gid]['job'].",{");
        echo_save($parser,"OnClick:");
		$parser->data['indent'] = $parser->data['indent'] + 1;
    }
    echo_save($parser,"mes \"" .$parser->string($parser->word(2)-8,8) ."\";");
}

function PACKET_ZC_WAIT_DIALOG($parser){
    echo_save($parser,"next;");
}

function PACKET_ZC_CLOSE_DIALOG($parser){
    echo_save($parser,"close2;");
	$parser->data['indent'] = $parser->data['indent'] - 1;
    echo_save($parser,"end;");
	$parser->data['indent'] = $parser->data['indent'] - 1;
	echo_save($parser,"}");
    $parser->data['talking_to_npc'] = false;
}

function PACKET_ZC_MENU_LIST($parser){
	$select = $parser->string($parser->word(2)-8,8);
	$parser->menu_list = explode(":",":".$select); // begin with : to create a blank entry at begining
	$parser->menu_list[255] = "cancel clicked";
	echo_save($parser,"switch(select(\"$select\") {");
}

function PACKET_CZ_CHOOSE_MENU($parser){
	$chose = $parser->byte(6);
	$option = $parser->menu_list[$chose];
	echo_save($parser,"case $chose: // $option");
	$parser->data['indent'] = $parser->data['indent'] + 1;
}

function PACKET_ZC_NOTIFY_STANDENTRY6($parser){
    $gid = $parser->long(5);
    $parser->npc_list[$gid]['GID'] = $parser->long(5);
    $parser->npc_list[$gid]['job'] = $parser->word(19);
    $parser->npc_list[$gid]['name'] = $parser->string(24,65);
    $parser->npc_list[$gid]['map'] = $parser->data['map'];
    list($x,$y) = explode(",",$parser->xy(55));
    $parser->npc_list[$gid]['x'] = $x;
    $parser->npc_list[$gid]['y'] = $y;
    echo "Seen NPC # ".$parser->npc_list[$gid]['name'] ." \n";
	//print_r($parser->npc_list[$gid]);
}

function PACKET_ZC_ADD_QUEST($parser) {
	echo_save($parser, "setquest ".$parser->long().";");
}

function PACKET_ZC_DEL_QUEST($parser) {
	echo_save($parser,"erasequest ".$parser->long().";");
}

function PACKET_ZC_COMPASS($parser) {
	$naid = $parser->long();
	$action = $parser->long();
	$x = $parser->long();
	$y = $parser->long();
	$id = $parser->byte();
	$color = $parser->long();
	echo_save($parser,"viewpoint $action,$x,$y,$id,$color;");
}

function PACKET_ZC_SHOW_IMAGE2($parser) {
	$imageName = $parser->string(64);
	$type = $parser->byte();
	echo_save($parser,"cutin \"$imageName\",$type;");
}

function PACKET_ZC_NOTIFY_EXP($parser) {
	$AID=$parser->long();
	$amount=$parser->long();
	$varID=$parser->word();
	$expType=$parser->word();
	if($parser->data['talking_to_npc'] == false){
		return;
	}
	if($expType == 1){
		echo_save($parser, "getexp $amount,0;");
	}elseif($expType == 2){
		echo_save($parser, "getexp 0,$amount;");
	}
}

function PACKET_ZC_ITEM_PICKUP_ACK3($parser) {
	$Index=$parser->word();
	$count=$parser->word();
	$ITID=$parser->word();
	if($parser->data['talking_to_npc'] == false){
		return;
	}
	echo_save($parser,"getitem $ITID,$count;");
}

function PACKET_ZC_OPEN_EDITDLGSTR($parser) {
	echo_save($parser,"input .@input1$;");
}

function PACKET_ZC_OPEN_EDITDLG($parser) {
	echo_save($parser,"input .@amount;");
}

function PACKET_ZC_EMOTION($parser) {
	$GID=$parser->long();
	$type=$parser->byte();
	if($parser->data['talking_to_npc'] == $GID){
		echo_save($parser,"emotion $type,0;"); //emotion from npc
	}elseif($parser->$aid == $GID){
		echo_save($parser,"emotion $type,1;"); //emotion from player
	}
}

function PACKET_ZC_LONGPAR_CHANGE($parser) {
	$varID=$parser->word();
	$amount=$parser->long();
	if($varID == 20){ // money
		if($parser->data['money'] !== false){
			if($parser->data['talking_to_npc'] == true){
				$diff = $amount - $parser->data['money'];
				if($diff < 0){
					$diff = abs($diff);
					echo_save($parser,"set zeny,zeny-$diff;");
				} else {
					echo_save($parser,"set zeny,zeny+$diff;");
				}
			}
		}
		$parser->data['money'] = $amount;
	}
}
?>