#!/bin/bash
cd /root/flowguard
exec /root/flowguard/venv/bin/python3 -m bgp.speaker /root/flowguard/config.yaml
