     _____         _       _      _____
    |  _  |___ ___| |_ ___| |_   |  _  |___ ___ ___ ___ ___
    |   __| .'|  _| '_| -_|  _|  |   __| .'|  _|_ -| -_|  _|
    |__|  |__,|___|_,_|___|_|    |__|  |__,|_| |___|___|_|
       Yommys Amazing Ragnarok Packet Analyzer Framework

This is a REAL-TIME ragnarok packet analyzer -
currently does not work with kRO, due to ahnLab catching the dll hook /sadface

First your client needs to be patched to load wpp.dll
in the bin folder is a patcher, just drop your client in there, and run the bat
then copy the patched client and dll back to RO folder
this is the only edit needed in RO folder

The parser is seperate, the dll sends a copy of all packets to the parser using a socket on port 1234
Parser needs to be started and waiting before Ragnarok client is loaded.


/data/packet/plen
Format:
packet_id,length

packet_id = Hex, left padded with 0.
length    = Decimal, variable length should be set to 0, not -1 like some extractors.

