# avred

Based on: https://github.com/scrt/avdebugger

Most antivirus engines rely on strings or other bytes sequences, function exports and big integers to recognize malware.
This project helps to automatically recover these signatures.

## Setup

On a VM: 
* Deploy a avred-server onto a VM with the AV you want to test
* Configured the config.json on the avred-server directory
* Test it: TODO

On another VM: 
* checkout avred 
* Configure your servers in config.json
* Start with: `./avred --server defender`

## Architecture


# OLD OLD OLD

# Project status

Able to automatically find and remove the strings that have the most impact on the AV's verdict.

# Setup and usage

Here are the instructions to use this tool.

## Dependencies (Python 3)

* python-tqdm
* python-hexdump
* pytest

```
python3 -m pip install -r requirements.txt
```

## Dependencies (other)

* rabin2 (from radare2)
* loadlibrary: Windows Defender scanner ported to Linux by taviso (3 minutes setup, instructions at https://github.com/taviso/loadlibrary)

## Configuration

Fix all the values in `config.json`.

## Usage

```
python3 antivirus_debugger.py -h                                                          
usage: antivirus_debugger.py [-h] [-s] [-z] [-f FILE] [-e] [-l LENGTH] [-c SECTION] [-g] [-V] [-H HIDE_SECTION] [-S SCANNER]

optional arguments:
  -h, --help            show this help message and exit
  -s, --skip-strings    Skip strings analysis
  -z, --skip-sections   Skip sections analysis
  -f FILE, --file FILE  path to file
  -e, --extensive       search strings in all sections
  -l LENGTH, --length LENGTH
                        minimum length of strings
  -c SECTION, --section SECTION
                        Analyze provided section
  -g, --globals         Analyze global variables in .data section
  -V, --virus           Virus scan
  -H HIDE_SECTION, --hide-section HIDE_SECTION
                        Hide a section
  -S SCANNER, --scanner SCANNER
                        Antivirus engine. Default = DockerWindowsDefender
```
