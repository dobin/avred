# Plugins 

Plugins are in `plugins/`: 
* file_xxx.py: Support for a file format
* analyzer_xxx.py: Support to analyze that file format

New plugins need to be linked in `avred.py` at appropriate places.
Ident based on extension, set `FileType`.


## File

The `BaseFile` defines an object which is the view to a file, 
with some helper functions. For example, it does unzipping/zipping for 
Office files. 

Inherit from `BaseFile`, like so: 

```python
class FileXXX(BaseFile):
    def __init__(self):
        super().__init__()
```


## Analyzer

Ananlyzer function will scan a file by getting its content from `BaseFile::getData()`
and send it to the avred-server via HTTP:

```python
def analyzeFileXXX(file: FileXXX, scanner: Scanner, analyzerOptions={}) -> IntervalTree:
```

This will do all the work:
```python
    reducer = Reducer(file, scanner)
    matchesIntervalTree = reducer.scan(0, len(file.getData()))
```


## Augmenter

Augmenter function:

```python
def augmentFileXXX(file: FileXXX, matches: List[Match]) -> str:
```

Iterate through all `matches` and add information to it from `file`, e.g. disassembly of the match.

