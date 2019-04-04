from autocoop.builder.builder import BaseBuilder, Object, Memory, Relocator, Arch, Obj64, Object

class ArrayBuilder(BaseBuilder):
    LABEL_ARRAY = 99

    def __init__(self, arch, baseBuff, mainObj):
        """
        @param baseBuff the base address of the buffer under control
        @param mainObj the main object (loop gadget), will not be contained in the gadget chain
        """
        BaseBuilder.__init__(self, baseBuff, arch)
        self.notInArray = []
        self.addObj(mainObj)

        self.functions = []

    def addFunction(self, addr):
        self.functions.append(addr)

    def _calcSizeFnArray(self):
        return len(self.functions) * self.arch.sizeNativeInt

    def _createArray(self, objReloc=Relocator(0,0), metaReloc=Relocator(0,0)):
        # create buffer
        mem = Memory(self.arch)
        currOffsetFn = 0
        for fn in self.functions:
            mem.addData(currOffsetFn, self.arch.packNativeInt(fn))
            currOffsetFn += self.arch.sizeNativeInt
        # write buffer to array region
        self.regionArray.setData(mem.getBuffer())

    def finalize(self, maxOffset):
        # create object to contain array of object pointers
        objArray = Object(arch=self.arch, noFakeVtable=True)
        self.regionArray = Memory.Region(offset=0, size=self._calcSizeFnArray(), label=self.LABEL_ARRAY)
        objArray.mem.addRegion(self.regionArray)
        self.addObj(objArray)

        # calc offsets
        self._calcOffsets(maxOffset)

        # create array of object pointers
        ## create relocator for array
        offsetsArray = self._getOffsetsObj(objArray)
        assert len(offsetsArray) == 1
        arrayReloc = Relocator(0, self.baseBuff + offsetsArray[0])
        ## create relocator for objects
        objReloc = Relocator(0, self.baseBuff)
        self._createArray(objReloc, arrayReloc)

        # create object buffer
        return self._createObjBuffer(objReloc=objReloc)