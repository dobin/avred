import magic
import pathlib
import hashlib
from typing import List, Set, Dict, Tuple, Optional
from enum import Enum

from model.file_model import BaseFile
from model.model_base import FileInfo


class FileType(Enum):
    EXE = 1
    DOTNET = 2
    OFFICE = 3
    PLAIN = 4


def getFileInfo(file: BaseFile):
    """Returns basic file information FileInfo for file (size, hash, ident)"""
    size = pathlib.Path(file.filepath).stat().st_size
    hash = hashlib.md5(file.fileData.getBytes()).digest()
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
    """Identify file type. Used to select the right file scanner."""
    fileScannerType = FileType.PLAIN

    # detection based on file ending (excplicitly tested)
    if filename.endswith('.ps1'):
        fileScannerType = FileType.PLAIN
    elif filename.endswith('.docm'):  # dotm, xlsm, xltm
        fileScannerType = FileType.OFFICE
    elif filename.endswith('.lnk'):
        fileScannerType = FileType.PLAIN
    else:
        # unknown file extension, try to identify it based on type (mostly for .bin files)
        ident = magic.from_file(filename)
        if 'Mono/.Net assembly' in ident:
            fileScannerType = FileType.DOTNET
        elif 'PE32 ' in ident or 'PE32+ ' in ident:
            fileScannerType = FileType.EXE
        elif 'Microsoft Word' in ident:
            fileScannerType = FileType.OFFICE

    return fileScannerType