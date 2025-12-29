#!/bin/bash
echo "[+] Updating EagleRecon..."
git pull
pip install -r requirements.txt
echo "[✓] Update complete"
