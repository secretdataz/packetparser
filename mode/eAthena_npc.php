<?php

// class npc_ripper extends parser {
	// public $npc_list = array();
	// public $data = array();
	// public $menu_list = array();
// }

// packet_parser functions
function PP_MODE_INIT($parser) {
	//global $npc_list = array();
	//global $data = array();
	$parser->mode["mode_name"] = "eAthena_npc";	//
	$parser->mode["extra_bytes"] = false;		// warning about extra packet data
	$parser->mode["debug"] = true;				// write packets to file
	$parser->mode["save_npc"] = true;
	
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
	echo $text;
	fwrite($parser->npc_file, $text);
}

function PACKET_HC_NOTIFY_ZONESVR($parser) {
	$parser->data['map'] = $parser->string(16, 6);
	$parser->data['talking_to_npc'] = false;
	$parser->data['money'] = false;
}

function PACKET_ZC_SAY_DIALOG($parser){
    $gid = $parser->long(4);
    if($parser->data['talking_to_npc'] == false){
        $parser->data['talking_to_npc'] = true;
        echo_save($parser,"\n\n".$parser->npc_list[$gid]['map'].",".$parser->npc_list[$gid]['x'].",".$parser->npc_list[$gid]['y'].","."4"."\tscript\t".$parser->npc_list[$gid]['name']."\t".$parser->npc_list[$gid]['job'].",{\n");
        echo_save($parser,"OnClick:\n");
    }
    echo_save($parser,"\tmes \"" .$parser->string($parser->word(2)-8,8) ."\";\n");
}

function PACKET_ZC_WAIT_DIALOG($parser){
    echo_save($parser,"\tnext;\n");
}

function PACKET_ZC_CLOSE_DIALOG($parser){
    echo_save($parser,"\tclose2;\n");
    echo_save($parser,"end;\n");
    $parser->data['talking_to_npc'] = false;
}

function PACKET_ZC_MENU_LIST($parser){
	$select = $parser->string($parser->word(2)-8,8);
	$parser->menu_list = explode(":",":".$select); // begin with : to create a blank entry at begining
	$parser->menu_list[255] = "cancel clicked";
	echo_save($parser,"\tswitch(select(\"$select\") {\n");
}

function PACKET_CZ_CHOOSE_MENU($parser){
	$chose = $parser->byte(6);
	$option = $parser->menu_list[$chose];
	echo_save($parser,"\tcase $chose: // $option\n");
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
	echo_save($parser, "\tsetquest ".$parser->long().";\n");
}

function PACKET_ZC_DEL_QUEST($parser) {
	echo_save($parser,"\terasequest ".$parser->long().";\n");
}

function PACKET_ZC_COMPASS($parser) {
	$naid = $parser->long();
	$action = $parser->long();
	$x = $parser->long();
	$y = $parser->long();
	$id = $parser->byte();
	$color = $parser->long();
	echo_save($parser,"\tviewpoint $action,$x,$y,$id,$color;\n");
}

function PACKET_ZC_SHOW_IMAGE2($parser) {
	$imageName = $parser->string(64);
	$type = $parser->byte();
	echo_save($parser,"\tcutin \"$imageName\",$type;\n");
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
		echo_save($parser, "\tgetexp $amount,0;\n");
	}elseif($expType == 2){
		echo_save($parser, "\tgetexp 0,$amount;\n");
	}
}

function PACKET_ZC_ITEM_PICKUP_ACK3($parser) {
	$Index=$parser->word();
	$count=$parser->word();
	$ITID=$parser->word();
	if($parser->data['talking_to_npc'] == false){
		return;
	}
	echo_save($parser,"\tgetitem $ITID,$count;\n");
}

function PACKET_ZC_OPEN_EDITDLGSTR($parser) {
	echo_save($parser,"\tinput .@input1$;\n");
}

function PACKET_ZC_OPEN_EDITDLG($parser) {
	echo_save($parser,"\tinput .@amount;\n");
}

function PACKET_ZC_EMOTION($parser) {
	$GID=$parser->long();
	$type=$parser->byte();
	if($parser->data['talking_to_npc'] == false){
		return;
	}
	echo_save($parser,"\temotion $type;\n");
}

function PACKET_ZC_LONGPAR_CHANGE($parser) {
	$varID=$parser->word();
	$amount=$parser->long();
	if($varID != 20){ // money
		return;
	}
	if($parser->data['money'] !== false){
		if($parser->data['talking_to_npc'] == true){
			$diff = $amount - $parser->data['money'];
			if($diff < 0){
				$diff = abs($diff);
				echo_save($parser,"\tset zeny,zeny-$diff;\n");
			} else {
				echo_save($parser,"\tset zeny,zeny+$diff;\n");
			}
		}
	}
	$parser->data['money'] = $amount;
	//echo "\n#you have $amount Z\n";
}
?>