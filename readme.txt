     _____         _       _      _____
    |  _  |___ ___| |_ ___| |_   |  _  |___ ___ ___ ___ ___
    |   __| .'|  _| '_| -_|  _|  |   __| .'|  _|_ -| -_|  _|
    |__|  |__,|___|_,_|___|_|    |__|  |__,|_| |___|___|_|
       Yommys Amazing Ragnarok Packet Analyzer Framework

This is a REAL-TIME ragnarok packet analyzer -

There is 2 parts to the setup, Packet_forwarder and Packet_Parser -
Packet_Forwarder captures packets from the network interface and sends to the Parser
Packet_Parser receives packet data from the Forwarder, and outputs data from each packet

Alternative to the Forwarder, the ro client can be patched to load wpp.dll

TODO:
* move remaining output into full_info.php
* add a mode selection at startup
* add a packet length file selection at startup
* create a mode specific to capturing npc data, and output into athena script format <3
* update plen_extract to support new clients


Packet_Parser
|   packet_forwarding.exe	-- listens for ragnarok packets on network, and forwards to parser
|   parser.bat			-- Run this to start the parser
|   parser.php			-- main script, listens for socket data from forwarder / wpp.dll, and pushes to extracter
|   parser_cls.php		-- Core Parser file, resposible for extracting packet data
|   readme.txt			-- This file
+---data
|   +---enum
|   |       efst.txt		-- Status Effects
|   |       item.txt		-- Items
|   |       jobtype.txt		-- Jobs / Npc / Mobs / Homunc / Mercenary
|   |       skill.txt		-- Skills
|   |       var.txt		-- Var
|   \---packet
|           func.txt		-- Function list table
|           plen.txt		-- Packet length table
+---dev
|   +---dll_inject		-- wpp.dll and script to make client load this dll
|   +---packet_capture		-- Source of Packet_Forwarder, using libPcap
|   +---plen_extract		-- Extract packet length table from ro client (only vc9 linked)
|   \---structure		-- A script to convert "extracted aegis packet structure defines" into full_mode.php
|   
\---mode
        full_info.php		-- prints out all known packet data