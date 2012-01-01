@echo off
:Parser
cls
@title Welcome to Packet_Parser
php "parser.php"
echo -------------------------------------------------------------------------------
set /p choice=Press enter to restart:
goto Parser
