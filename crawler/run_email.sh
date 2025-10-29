#!/bin/sh
if [ ! -f /home/dm/Discord/links_email.txt ]; then
    echo "File not found!"
    exit 1
fi
cd /home/dm/subcrawl/crawler/ || exit 1
mv /home/dm/Discord/links_email.txt /home/dm/subcrawl/crawler/urls/links_email.txt
if [ -f /home/dm/subcrawl/crawler/urls/links_email.txt ]; then
    /home/dm/subcrawl/venv/bin/python /home/dm/subcrawl/crawler/subcrawl.py -s ConsoleStorage,MISPStorage,TeamsStorage -f /home/dm/subcrawl/crawler/urls/links_email.txt
else
    echo "File was not moved correctly!"
    exit 1
fi
