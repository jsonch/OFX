sudo kill $(ps aux | grep 'python switchAgent.py' | awk '{ print $2 }')
sudo killall genericDpAgent
