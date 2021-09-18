#!/bin/bash
set -eu
apt-get update -y
sudo apt-get install -y bpfcc-tools linux-headers-$(uname -r)
