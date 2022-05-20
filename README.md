# avred

Based on: https://github.com/scrt/avdebugger

Most antivirus engines rely on strings or other bytes sequences, function exports and big integers to recognize malware.
This project helps to automatically recover these signatures.

## Setup

On a VM: 
* e.g.: `1.1.1.1:9001`
* Deploy a avred-server onto a VM with the AV you want to test
* Configured the `config.json` on the avred-server directory
* Test it: TODO
* Start server: `./avred-server.py`

On another VM: 
* checkout avred 
* Configure your servers in config.json (eg `1.1.1.1:9001`)
* Start with: `./avred --server defender`

## Install 

```
pip3 install -r requirements.txt
```

## Architecture
