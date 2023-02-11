# Source Code Overview 

Main objectes: 
* Make it as easy as possible to identify parts of a binary which can be modified to bypass signature detection
* Add useful information to the matches to make it easy to spot how and what part should be modified
* Support often used file formats in malware attacks


## Phases 

The whole process is separated into three distinct phases: 
1) *Scan* file to get list of `Matches`.
2) *Verify* the matches.
3) *Augment* the matches with file information.

Phase 1) and 2) require avred-server connection. The augmentation can run offline.

1) *Scan* will produce a `.matches` file, which contains a an array of `Interval` with the matches, pickled.
2) *Verify* will create a `.outcome` file, which contains the matches, and its verification. Its of type `Outcome`.
3) *Augment* will update the information in `.outcome` file with more information for each match.


## Data structures

Simplified overview of used data structures.


Interval match: 
```
Interval(start, end, data)
```

Match:
```
class Match:
  - idx: Matches of a file are numbered, starting at 0
  - fileOffset: How many bytes into the file the match starts
  - size: How long the match is

  - data: A copy of the file from `fileOffset` to `fileOffset+size`
  - dataHexdump: A hexdump of `data`
  - info: Where the match is located, e.g. which section
  - detail: Detailed disassembly of `data`, if possible
```

Outcome: 
```
class Outcome: 
  - fileInfo: Some additional information of the file which has been scanned
  - matches: List of `Matches`
  - verification: List of `Verifications` and supplemental conclusion
  - matchesIt: List of matches as `Interval`, basically copy of the `.matches`. Duplicate of `matches`, and not really used
```


## Definition

* `file`: A file to scan. e.g. a .exe, or .docx
* `scanner`: Interface to an `avred-server` running another host. It basically returns detected or not-detected for a given `file`
* `match`: A range in the file which gets detected by Antivirus. Defined in model as `Match`. Basically an file offset and size/length


## Directories 

* app/: Flask Webapp
* doc/: Documentation
* model/: Model 
* plugins/: Plugins for each file type 
* test/: Tests
* tools/: some command line tools

Files: 
* avred.py: Main file
* reducer.py: Finds all `Matches` in a `file` with a `scanner`. The main file reduction logic
* scanner.py: The `scanner` class. Accesses an `avred-server` to scan a `file`
* verifier.py: Logic to verify the `Matches` of a `file` with a `scanner`

