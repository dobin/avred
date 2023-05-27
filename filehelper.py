import magic
import pathlib
import hashlib
from typing import List, Set, Dict, Tuple, Optional
from enum import Enum

from model.extensions import PluginFileFormat
from model.model import FileInfo


class FileType(Enum):
    EXE = 1
    OFFICE = 3
    PLAIN = 4


def getFileInfo(file: PluginFileFormat):
    size = pathlib.Path(file.filepath).stat().st_size
    hash = hashlib.md5(file.fileData).digest()
    time = pathlib.Path(file.filepath).stat().st_ctime
    ident = magic.from_file(file.filepath)

    if 'Mono/.Net assembly' in ident: # 'PE32 executable (console) Intel 80386 Mono/.Net assembly, for MS Windows'
        ident = "EXE PE.NET"
    elif 'PE32+ executable' in ident: # 'PE32+ executable (console) x86-64, for MS Windows'
        ident = "EXE PE64"
    elif 'PE32 executable' in ident: # 'PE32 executable (console) Intel 80386, for MS Windows'
        ident = "EXE PE32"
    elif 'PDF document' in ident:
        ident = 'PDF'
    elif 'ASCII text' in ident:
        ident = 'ASCII'
    elif file.filename.endswith('.ps1'):
        ident = "Powershell"
    else:
        # first two words
        ident = ' '.join(ident.split()[:2])

    fileInfo = FileInfo(file.filename, size, hash, time, ident)
    return fileInfo


def getFileScannerTypeFor(filename):
    fileScannerType = FileType.PLAIN

    # detection based on file ending (excplicitly tested)
    if filename.endswith('.ps1'):
        fileScannerType = FileType.PLAIN
    elif filename.endswith('.docm'):  # dotm, xlsm, xltm
        fileScannerType = FileType.OFFICE
    elif filename.endswith('.exe') or filename.endswith('.dll'):
        fileScannerType = FileType.EXE
    elif filename.endswith('.lnk'):
        fileScannerType = FileType.PLAIN
    else:
        # unknown file extension, try to identify it based on type (mostly for .bin files)
        ident = magic.from_file(filename)
        if 'PE32 ' in ident or 'PE32+ ' in ident:
            fileScannerType = FileType.EXE
        elif 'Microsoft Word' in ident:
            fileScannerType = FileType.OFFICE

    return fileScannerType