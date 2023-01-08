
from intervaltree import Interval, IntervalTree


class IlMethod():
    def __init__(self):
        self.name = None
        self.addr = None
        self.size = None
        self.className = None
        self.il = []

    def setName(self, name, className=''):
        self.name = name
        self.className = className

    def setAddr(self, addr):
        self.addr = addr

    def setSize(self, size):
        self.size = size

    def addIl(self, il):
        self.il.append(il)

    def __str__(self):
        s = ''
        s += "Func {}::{} at {} with size {}:\n".format(
            self.className, self.name, self.addr, self.size)
        for il in self.il:
            s += "  {}\n".format(il)
        return s


class IlspyParser():
    def __init__(self):
        self.methods = []
        self.currentMethod = None
        self.currentClassName = ''

        self.methodsIt = IntervalTree()


    def parseFile(self, fileName):
        file = open(fileName, 'r')
        count = 0

        while True:
            line = file.readline()
            if not line:
                break
            line = line.lstrip().rstrip()

            if line.startswith('.class'):
                self.newClass(line)

            if line.startswith('.method'):
                line2 = file.readline()
                line2 = line2.lstrip().rstrip()

                self.newMethod(line + ' ' + line2)

            if line.startswith('//'):
                self.newComment(line)

            if line.startswith('IL_'):
                self.newIl(line)

            if count > 120:
                break
            count += 1

        file.close()

        # convert
        for method in self.methods:
            methodIt = Interval(method.addr, method.addr+method.size, method)
            self.methodsIt.add(methodIt)


    def query(self, addr):
        res = self.methodsIt.at(addr)
        res = list(res)[0].data
        print("BBBB: " + str(res.name))
        return res

    def print(self):
        for method in self.methods:
            print(method)


    def newClass(self, line):
        # .class nested private auto ansi sealed beforefieldinit '<>c__DisplayClass0_0'
		#   extends [mscorlib]System.Object
        l = line.split(' ')
        if len(l) <= 7:
            pass
        else:
            className = l[7]
            self.currentClassName = className


    def newMethod(self, line):
		# .method assembly hidebysig 
		#	instance bool '<SetPinForPrivateKey>b__0' () cil managed         
        self.currentMethod = IlMethod()
        self.methods.append(self.currentMethod)

        l = line.split(' ')
        self.currentMethod.setName(l[5], self.currentClassName)


    def newComment(self, line):
		# // Method begins at RVA 0x2dfa
		# // Header size: 1
		# // Code size: 7 (0x7)
        l = line.split(' ')

        if line.startswith('// Method begins at RVA'):
            addr = l[5]
            addr = int(addr, 16)
            self.currentMethod.setAddr(addr)
        if line.startswith('// Code size: '):
            size = l[3]
            size = int(size)
            self.currentMethod.setSize(size)


    def newIl(self, line):
        # IL_0000: ldarg.0
        l = line.split(': ')
        self.currentMethod.addIl(line)

