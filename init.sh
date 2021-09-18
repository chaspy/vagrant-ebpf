#!/bin/bash
set -eu
apt-get update -y
sudo apt-get install -y bpfcc-tools python3-bpfcc linux-headers-$(uname -r)
