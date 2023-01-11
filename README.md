# avred

Avred is being used to identify which parts of a file are identified
by a Antivirus, and tries to show as much possible information and context about each match. 

It is mainly used to make it easier for RedTeamers to obfuscate their
tools. 


## Background

Most antivirus engines rely on strings or other bytes sequences to recognize malware.
This project helps to automatically recover these signatures.

The difference to similar projects is: 
* Knowledge of internal file structures. 
  * Can extract vbaProject.bin and modify it 
  * Knows about PE sections and scan each one individually
* Supports any Antivirus (thanks to AMSI server via HTTP)
* Shows detailed information about each match
* Verifies the results


## Inspiration

* Similar to matterpreter/DefenderCheck and rasta-mouse/ThreatCheck
* Based on: https://github.com/scrt/avdebugger


## Supports

* PE (EXE) files
* PE .NET files 
* Word files

This includes: 
* Code decompilation (assembly, .NET IL, and makros)


## Install 

Requires: python 3.8

```
pip3 install -r requirements.txt
```


## Setup

First, we need a windows instance with an antivirus. We use avred-server as interface
to this antivirus.

On VM `1.1.1.1:9001`:
* Deploy a avred-server onto a VM with the AV you want to test
* Configured the `config.json` on the avred-server directory
* Start server: `./avred-server.py`
* Test it: http://1.1.1.1:9001/test

Second, once you have this, you can setup avred.
* checkout avred 
* Configure your servers in `config.json` (eg `1.1.1.1:9001`)
* Scan file with: `./avred.py --file mimikatz.exe --server defender`

Use `--saveMatches` to write all identified matches into file "filename + `.matches.json`". 

Use `--verify` to patch one match after another at the end, until the AV stop detecting it. Used to 
verify if this thing works as intended. 


## Issues when scanning and options

*If all sections get detected*, use `--isolate`. Instead of nulling a section and see if
the AV stops identifying it, the option will do the opposite: null other sections, and see
if the AV still detects it. 

*If there are a lot of matches in `.text`*, use `--ignoreText` to skip analyzing this section.
The findings in the other sections are usually good enough. 


## Tested with: 

* pe/
  * DripLoader.exe
  * lazagne.exe
  * mimikatz.exe
  * PetitPotam.exe
* ps/
  * 
* sharp/
  * Rubeus.exe
  * Seatbelt.exe
  * SharpHound.exe
  * SharpSploit.dll


# Web server

Development:
```
$ export FLASK_DEBUG=1
$ flask run --host=0.0.0.0
```

