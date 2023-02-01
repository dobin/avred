import sys
import os

from .dotnetfile import DotNetPE
from .parser import DotNetPEParser, CLRFormatError

sys.path.append(os.path.dirname(__file__))
