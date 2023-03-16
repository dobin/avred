# avred

Antivirus reducer. 

Avred is being used to identify which parts of a file are identified
by a Antivirus, and tries to show as much possible information and context about each match. 

This includes: 
* Section names of matches
* Decompilation if match contains code
* Verification of matches

It is mainly used to make it easier for RedTeamers to obfuscate their tools. 


## Background

Most antivirus engines rely on strings or other bytes sequences to recognize malware.
This project helps to automatically recover these signatures (matches).

The difference to similar projects is: 
* Knowledge of internal file structures. 
  * Can extract vbaProject.bin and modify it 
  * Knows about PE sections and scan each one individually
  * Knows .NET streams
* Supports any Antivirus (thanks to AMSI server via HTTP)
* Shows detailed information about each match (disassembly etc.)
* Verifies the matches


## Supported files:

* PE (EXE) files, r2 disassembly
* PE .NET files, dncil disassembly
* Word files, pcodedmp disassembly


## Example


## Screenshots


## Install 

Requires: python 3.8

Install python deps:
```
pip3 install -r requirements.txt
```

If you get the error `ImportError: failed to find libmagic. Check your installation` try: 
```
pip3 install python-magic-bin==0.4.14
```

Install radare2:
* follow [instructions](https://github.com/radareorg/radare2#installation) on radare2 github
* Or download exe from github [releases](https://github.com/radareorg/radare2/releases) and add to your `PATH` (e.g. on windows)


## Setup

First, we need a windows instance with an antivirus. We use [avred-server](https://github.com/dobin/avred-server) as interface to this antivirus on a Windows host.

Lets install and configure avred-server on windows VM `1.1.1.1:9001`. 
Follow install instructions on [avred-server](https://github.com/dobin/avred-server) README. 

Once you have this and its working properly (`use curl 1.1.1.1:9001/test`), you can setup avred:
* Configure your server IP in `config.json` (eg `"amsi": "1.1.1.1:9001"`)
* Test it by scanning a file with: `./avred.py --file test.ps1 --server amsi`

It should look like this:
```
$ r2 -v
radare2 5.7.2 0 @ linux-x86-64 git.
commit: 5.7.2 build: 2022-07-02__14:15:22

$ cat config.json
{
        "server": 
                {
                        "amsi": "http://1.1.1.1:8001/"
                }
}

$ curl http://1.1.1.1:8001/test
{"benign detected":false,"malicous detected":true,"msg":"working as intended"}

$ ./avred.py --file test.ps1 --server amsi
[INFO    ][2023/03/09 18:33][avred.py: 71] main() :: Using file: test.ps1
[INFO    ][2023/03/09 18:33][avred.py: 90] scanFile() :: Handle file: test.ps1
[INFO    ][2023/03/09 18:33][avred.py:115] scanFile() :: Using parser for PLAIN
[ERROR   ][2023/03/09 18:33][avred.py:172] scanFile() :: test.ps1 is not detected by amsi
[INFO    ][2023/03/09 18:33][avred.py:180] scanFile() :: Found 0 matches
[INFO    ][2023/03/09 18:33][avred.py:206] scanFile() :: Wrote results to test.ps1.outcome
```


## How to use

As a web server: 
```sh
$ python3 app.py --listenip 127.0.0.1 --listenport 8080
```

From command line: 
```sh
$ python3 avred.py --server amsi --file malware/evil.exe
```


## File and Directory structure

I am team NO-DB. Only files.

File nomenclature: 
* `file.exe`: The file you want to scan
* `file.exe.log`: All log output of the scanning (with `--logtofile`)
* `file.exe.outcome`: Pickled Outcome data structure with all further information

For the webapp, files are uploaded to `app/uploads`. 


## References

Similar to: 
* https://github.com/matterpreter/DefenderCheck
* https://github.com/rasta-mouse/ThreatCheck
* https://github.com/RythmStick/AMSITrigger

Based on: 
* https://github.com/scrt/avdebugger


## Issues when scanning and options

### EXE PE

*If all sections get detected*, use `--isolate`. Instead of nulling a section and see if
the AV stops identifying it, the option will do the opposite: null other sections, and see
if the AV still detects it. 

*If there are a lot of matches in `.text`*, use `--ignoreText` to skip analyzing this section.
The findings in the other sections are usually good enough. 
