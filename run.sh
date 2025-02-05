#!/bin/bash

sudo ln -s -f /home/ubuntu/nexus/.config/nginx/nexus.conf /etc/nginx/conf.d/nexus.conf
sudo ln -s -f /home/ubuntu/nexus/.config/uwsgi/uwsgi.service /etc/systemd/system/uwsgi.service
sudo systemctl daemon-reload
sudo systemctl enable uwsgi nginx
sudo systemctl restart uwsgi nginx
