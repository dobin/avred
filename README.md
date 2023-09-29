# avred

AntiVirus REDucer for AntiVirus REDteaming.

Avred is being used to identify which parts of a file are identified
by a Antivirus, and tries to show as much possible information and context about each match. 

This includes: 
* Section names of matches
* Verification of matches
* Augmentation of matches as disassembled code or data references

It is mainly used to make it easier for RedTeamers to obfuscate their tools. 

Check it out: [avred.r00ted.ch](https://avred.r00ted.ch)

Slides: [HITB Slides Cracking The Shield.pdf](https://github.com/dobin/avred/blob/main/doc/HITB%20Slides%20Cracking%20the%20Shield.pdf)


## Comparison to ThreatCheck

Compared to ThreatCheck, avred has multiple features:

* Shows all matches (not just one)
* Verifies the matches to make sure they work
* Shows more information of matches
* Shows relevance of match, so you can target the weakest one

 
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

```
$ ./avred.py --file app/upload/DripLoader.exe 
[...]
DripLoader.exe size: 93184  ident: PE EXE 64
ScannerInfo: zero-sections,section-scan
Matches: 
id:0  offset:12991  len:195
  Section: .text
  Hexdump: 
00012991   48 81 C4 98 13 00 00 C3 CC CC CC CC CC CC CC C3    H...............
000129A1   4D 8B C2 49 C7 C2 01 00 00 00 4D 33 D2 49 C7 C2    M..I......M3.I..
000129B1   0A 00 00 00 4C 8B D1 33 C0 4D 2B C2 83 C0 18 4D    ....L..3.M+....M
000129C1   33 C0 0F 05 C3 48 83 C1 0A 33 C0 4C 8B D1 83 C0    3....H...3.L....
000129D1   3A 49 83 EA 0A 48 83 E9 0A 0F 05 C3 49 83 C2 1C    :I...H......I...
000129E1   33 C0 4C 8B D1 49 83 EA 01 83 C0 50 49 83 C2 01    3.L..I.....PI...
000129F1   0F 05 C3 4C 8B E1 4C 8B EA 4D 8B F0 4D 8B F9 4C    ...L..L..M..M..L
00012A01   8B D1 48 33 C0 05 C1 00 00 00 0F 05 48 83 F8 00    ..H3........H...
00012A11   74 8D 49 8B CC 49 8B D5 4D 8B C6 4D 8B CF 4C 8B    t.I..I..M..M..L.
00012A21   D1 48 33 C0 05 BD 00 00 00 0F 05 48 83 F8 00 0F    .H3........H....
00012A31   84 6A FF FF FF 49 8B CC 49 8B D5 4D 8B C6 4D 8B    .j...I..I..M..M.
00012A41   CF 4C 8B D1 48 33 C0 05 BC 00 00 00 0F 05 48 83    .L..H3........H.
00012A51   F8 00 0F                                           ...
[...]
```


## Upgrades

Note: Data is stored in pickled `.outcome` files. When i change the model, 
weird things gonna happen. 

Usually this will solve it: 
```
$ rm app/upload/*.outcome; rm app/upload/*.log
$ for i in app/upload/*; do ./avred.py --file "$i"; done
```

With hashcache enabled, this should be quick.


## Install 

Requires: python 3.8

Install python deps:
```
pip3 install --upgrade -r requirements.txt
```

If you get the error `ImportError: failed to find libmagic. Check your installation` try: 
```
pip3 install python-magic-bin==0.4.14
```

Install radare2:
* follow [instructions](https://github.com/radareorg/radare2#installation) on radare2 github
* Or download exe from github [releases](https://github.com/radareorg/radare2/releases) and add to your `PATH` (e.g. on windows)

Note: Make sure you have dnfile >= 0.14.1 installed


## Setup

First, we need a windows instance with an antivirus. We use [avred-server](https://github.com/dobin/avred-server) as interface to this antivirus on a Windows host.

Lets install and configure avred-server on windows VM `1.1.1.1:9001`. 
Follow install instructions on [avred-server](https://github.com/dobin/avred-server) README. 

Once you have this and its working properly (`use curl 1.1.1.1:9001/test`), you can setup avred:
* Configure your server IP in `config.yaml` (eg `"amsi": "1.1.1.1:9001"`)
* Test it by scanning a file with: `./avred.py --file test.ps1 --server amsi`

It should look like this:
```
$ r2 -v
radare2 5.7.2 0 @ linux-x86-64 git.
commit: 5.7.2 build: 2022-07-02__14:15:22

$ cat config.yaml
server:
  amsi: "http://1.1.1.1:8001/"

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
$ python3 avredweb.py --listenip 127.0.0.1 --listenport 8080
```

If you dont want that every user is able to see every uploaded file,
set password in `config.yaml` in key `password`, use username `admin`.


From command line: 
```sh
$ python3 avred.py --server amsi --file app/upload/evil.exe
```


## File and Directory structure

I am team NO-DB. Only files.

File nomenclature: 
* `file.exe`: The file you want to scan
* `file.exe.log`: All log output of the scanning (with `--logtofile`)
* `file.exe.outcome`: Pickled Outcome data structure with all further information
* `file.exe.pdb`: If you have debug symbols

For the webapp, files are uploaded to `app/uploads/`. 


## Docker

Build:
```
$ podman build -t avred .
```

run:
```
$ podman run -p 9001:5000 -e "server=http://1.1.1.1:8001" --name avred -d avred
```

run with upload directory mounted:
```
$ podman run -p 9001:5000 -e "server=http://1.1.1.1:8001" -v $HOME/avred-uploads:/opt/avred/app/upload/  --name avred -d avred 
```


## References

Similar to: 
* https://github.com/matterpreter/DefenderCheck
* https://github.com/rasta-mouse/ThreatCheck
* https://github.com/RythmStick/AMSITrigger

Based on: 
* https://github.com/scrt/avdebugger


## Tests

Coverage:
```
python3 -m coverage run -m unittest  -> .coverage
python3 -m coverage report  -> stdout 
python3 -m coverage html  -> ./htmlcov/index.html
```
