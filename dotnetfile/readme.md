# dotnetfile
`dotnetfile` is a Common Language Runtime (CLR) header parser library for Windows .NET files built in Python. The CLR header is present in every Windows .NET assembly beside the Portable Executable (PE) header. It stores a plethora of metadata information for the managed part of the file.

`dotnetfile` is in a way the equivalent of `pefile` but for .NET samples.

The library provides an easy-to-use API, but also try to contribute new methods to improve file detection. This includes the MemberRef hash (experimental) and the original and a modified version of TypeRef hash.

The aim of this project is to give malware analysts and threat hunters a tool to easily pull out information from the CLR header. You don't need to be an expert in the CLR header and get lost in its specification to use this library. By using the API, you'll also learn how the header is structured and hopefully get a better understanding of this file type in general.

## Installation
To install `dotnetfile` as a module, please use the provided `setup.py` file. This can be done with the help of Python:  
```python3 setup.py install```
`dotnetfile` requires Python >= 3.7 .

Now, you're all set to use `dotnetfile`. :raised_hands:

## Usage
To use `dotnetfile`, all you have to do is to import the module and create an instance of the class `DotNetPE` with the .NET assembly path as a parameter. A minimal example that prints out the number of streams of an assembly is shown below:
```python #
# Import class DotNetPE from module dotnetfile
from dotnetfile import DotNetPE

# Define the file path of your assembly
dotnet_file_path = '/Users/<username>/my_dotnet_assembly.exe'

# Create an instance of DotNetPE with the file path as a parameter
dotnet_file = DotNetPE(dotnet_file_path)

# Print out the number of streams of the assembly
print(f'Number of streams: {dotnet_file.get_number_of_streams()}')
```
You are invited to explore the example script ["dotnetfile_dump.py"](https://github.com/pan-unit42/dotnetfile/blob/main/examples/dotnetfile_dump.py)

More about the usage can be found on the [documentation pages](https://pan-unit42.github.io/dotnetfile/get_started/usage/). 

## Documentation
The full and extensive documentation can be found at https://pan-unit42.github.io/dotnetfile/

## Contributors
This project was started in 2016 with the development of the parser library for internal use at Palo Alto Networks. It was improved and extended from 2021-2022 with the interface library and open-sourced in 2022. The following people from the Malware & Countermeasures Unit (MCU) were involved:

- Bob Jung (parser library)
- Yaron Samuel (parser library) :black_small_square: [@yaron_samuel](https://twitter.com/yaron_samuel)
- Dominik Reichel (parser and interface libraries) :black_small_square: [@TheEnergyStory](https://twitter.com/TheEnergyStory)

This project is a work in progress.  If you find any issues or have any suggestions, please report them to the Github project page.

## Credits
`dotnetfile` is heavily based on the [`.NET spec`](https://www.ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf).

`GDATA` team deserves full credit for the `TypeRef Hash` idea.
