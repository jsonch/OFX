# fix a tiny error in the twink library that stops it from parsing experimenter messages.
twinkfile=/usr/local/lib/python2.7/dist-packages/twink/ofp4/parse.py
echo "patching file: $twinkfile"
sudo sed -i "1038i \\\tlength=header.length" $twinkfile