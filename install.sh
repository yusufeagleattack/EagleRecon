#!/bin/bash
echo "[+] Installing EagleRecon..."

pip install -r requirements.txt

chmod +x eagle.py
cp eagle.py $PREFIX/bin/eaglerecon 2>/dev/null || sudo cp eagle.py /usr/local/bin/eaglerecon

echo "[✓] Installed! Run: eaglerecon google.com --all"
