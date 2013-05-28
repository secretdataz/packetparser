     _____         _       _      _____
    |  _  |___ ___| |_ ___| |_   |  _  |___ ___ ___ ___ ___
    |   __| .'|  _| '_| -_|  _|  |   __| .'|  _|_ -| -_|  _|
    |__|  |__,|___|_,_|___|_|    |__|  |__,|_| |___|___|_|
       Yommys Amazing Ragnarok Packet Analyzer Framework

This is a REAL-TIME ragnarok packet analyzer -

Packet_Parser requires a correct packet length table (plen_*) to work correctly

TODO:



Packet_Parser
|   parser.bat              -- Run this to start the parser
|   parser.php              -- main script, listens for socket data from ws2_pp.dll OR reads packet_captures, and pushes to extracter
|   parser_cls.php          -- Core Parser file, resposible for extracting packet data
|   readme.txt              -- This file
+---captures
|   +---wpe                 -- WPE *.pac packet captures
|   +---wireshark_k12       -- WireShark k12 packet capture format
|   \---PacketParser        -- PacketParser Captures automatically created when using realtime mode
+---data
|   +---enum
|   |       efst.txt        -- Status Effects
|   |       item.txt        -- Items
|   |       jobtype.txt     -- Jobs / Npc / Mobs / Homunc / Mercenary
|   |       skill.txt       -- Skills
|   |       var.txt         -- Var
|   \---packet
|           func.txt        -- Function list table
|           plen_*.txt      -- Packet length table
+---dev
|   +---plen_extract        -- Extracts packet length table from ro client (and message_id encryption keys)
|   \---structure           -- A script to convert "extracted aegis packet structure defines" into full_mode.php
|   ws2_pp.dll              -- Custom ws2_32.dll, place into RO folder and hexedit client, ws2_32.dll to ws2_pp.dll
|   
+---mode
|       full_info.php       -- prints out all known packet data
|       *.php               -- other modes
\---output                  -- various data output from the parser modes