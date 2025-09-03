#!/bin/bash
sudo apt update
sudo apt remove gir1.2-appindicator3-0.1
sudo apt install -y libayatana-appindicator3-dev
go build