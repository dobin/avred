import pickle

filename = "app/upload/0317C1E45CEFD39C.Rubeus.exe.pickle"
fileData = None
with open(filename, "rb") as input_file:
    fileData = pickle.load(input_file)

for match in fileData.matches: 
    print("-> {} {} {}".format(match.idx, match.fileOffset, match.size))
    print(match.dataHexdump)