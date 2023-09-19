#!/usr/bin/python3
import os
import sys
import struct
import binascii
from os.path import exists

# This is intended for use with other scripts (such as for diffing).

def metaFindListDictWithValue(CmpVal, Val, ValKey):
    Out = None
    for TmpVal in Val:
        if CmpVal == TmpVal[ValKey]:
            Out = TmpVal
            break
    return Out

def metaLoadFac(Fac, path):
    out = {}

    Version = Fac[0]
    Padding = Fac[0x1:0x4]
    FsAccessFlag = struct.unpack('<Q', Fac[0x4:0xC])[0]
    ContentOwnerInfoOffset, ContentOwnerInfoSize, SaveDataOwnerInfoOffset, SaveDataOwnerInfoSize = struct.unpack('<IIII', Fac[0xC:0x1C])

    ContentOwnerInfo = []
    SaveDataOwnerInfo = []

    FacLen = len(Fac)

    if (ContentOwnerInfoOffset>FacLen or ContentOwnerInfoOffset+ContentOwnerInfoSize>FacLen) or (SaveDataOwnerInfoOffset>FacLen or SaveDataOwnerInfoOffset+SaveDataOwnerInfoSize>FacLen):
        print("metaLoadFac('%s'): Offset/size for ContentOwnerInfo/SaveDataOwnerInfo is invalid." % (path))
        return None

    if ContentOwnerInfoOffset!=0 and ContentOwnerInfoSize!=0:
        Offset = ContentOwnerInfoOffset
        CurCount = struct.unpack('<I', Fac[Offset:Offset+0x4])[0]
        Offset=Offset+0x4
        for i in range(CurCount):
            if Offset+0x8 > ContentOwnerInfoSize:
                print("metaLoadFac('%s'): ContentOwnerIdCount (0x%X) is too large for the ContentOwnerInfoSize (0x%X)." % (path, CurCount, ContentOwnerInfoSize))
                return None
            Id = struct.unpack('<Q', Fac[Offset:Offset+0x8])[0]
            Offset=Offset+0x8

            ContentOwnerInfo.append({'Id': Id})

    if SaveDataOwnerInfoOffset!=0 and SaveDataOwnerInfoSize!=0:
        Offset = SaveDataOwnerInfoOffset
        CurCount = struct.unpack('<I', Fac[Offset:Offset+0x4])[0]
        Offset=Offset+0x4
        OffsetId = ((Offset + CurCount) + 0x3) & ~0x3
        for i in range(CurCount):
            if Offset+0x1 - SaveDataOwnerInfoOffset > SaveDataOwnerInfoSize or OffsetId+0x8 - SaveDataOwnerInfoOffset > SaveDataOwnerInfoSize:
                print("metaLoadFac('%s'): SaveDataOwnerIdCount (0x%X) is too large for the SaveDataOwnerInfoSize (0x%X)." % (path, CurCount, SaveDataOwnerInfoSize))
                return None
            Access = struct.unpack('<B', Fac[Offset:Offset+0x1])[0]
            Id = struct.unpack('<Q', Fac[OffsetId:OffsetId+0x8])[0]
            Offset=Offset+0x1
            OffsetId=OffsetId+0x8

            SaveDataOwnerInfo.append({'Id': Id, 'Access': Access})

    out['Version'] = Version
    out['Padding'] = Padding
    out['FsAccessFlag'] = FsAccessFlag
    out['ContentOwnerInfo'] = ContentOwnerInfo
    out['SaveDataOwnerInfo'] = SaveDataOwnerInfo

    return out

def metaLoadSac(Sac): # This uses a dict, so any duplicate entries will overwrite the original entry.
    out = {'Server': {}, 'Client': {}}

    pos=0
    while pos<len(Sac):
        tmp = Sac[pos]
        size = (tmp&0x7)+1
        IsServer = tmp&0x80

        serv = Sac[pos+1:pos+1+size].decode('utf8')
        if IsServer==0x80:
            out['Server'][serv] = tmp
        else:
            out['Client'][serv] = tmp

        pos=pos+size+1

    return out

def CountSetBits(val, in_bitcount):
    bitcount=in_bitcount
    for i in range(in_bitcount):
        if (val & (1<<i)) == 0:
            bitcount = i
            break
    return bitcount

def metaLoadKc(Kc, path):
    out = []
    descriptors = []

    for desc in struct.iter_unpack('<I', Kc):
        descriptors.append(desc[0])

    EnableSystemCalls = {'Mask': 0, 'Descriptors': []}
    EnableInterrupts = {'Interrupts': [], 'Descriptors': []}

    pos=0
    num_descriptors = len(descriptors)
    while pos<num_descriptors:
        desc = descriptors[pos]
        if desc==0xFFFFFFFF:
            pos=pos+1
            continue

        bitcount=CountSetBits(desc, 32)

        next_desc = None
        next_bitcount = None
        if pos<num_descriptors-1:
            next_desc = descriptors[pos+1]
            next_bitcount=CountSetBits(next_desc, 32)

        if bitcount==3: # ThreadInfo
            LowestPriority = (desc>>4) & 0x3F
            HighestPriority = (desc>>10) & 0x3F
            MinCoreNumber = (desc>>16) & 0xFF
            MaxCoreNumber = (desc>>24) & 0xFF
            out.append({'ThreadInfo': {'Value': desc, 'LowestPriority': LowestPriority, 'HighestPriority': HighestPriority, 'MinCoreNumber': MinCoreNumber, 'MaxCoreNumber': MaxCoreNumber}})
        elif bitcount==4: # EnableSystemCalls
            SystemCallId = (desc>>5) & 0xFFFFFF
            Index = (desc>>29) & 0x7
            EnableSystemCalls['Mask'] |= SystemCallId << (0x18*Index)
            EnableSystemCalls['Descriptors'].append({'Value': desc, 'SystemCallId': SystemCallId, 'Index': Index})
        elif bitcount==6: # MemoryMap
            if next_desc is not None and next_bitcount!=6:
                print("metaLoadKc('%s'): MemoryMap descriptor is missing a matching descriptor, ignoring." % (path))
                continue

            BeginAddress = (desc & ~(1<<31)) >> 7
            PermissionType = (desc>>31) & 0x1
            Size = (next_desc>>7) & 0xFFFFF
            Reserved = (next_desc>>27) & 0xF
            MappingType = (next_desc>>31) & 0x1

            BeginAddress<<=12
            Size<<=12

            if PermissionType==0:
                PermissionType = 'RW'
            else:
                PermissionType = 'R-'

            if MappingType==0:
                MappingType = 'Io'
            else:
                MappingType = 'Static'

            out.append({'MemoryMap': {'Value0': desc, 'Value1': next_desc, 'BeginAddress': BeginAddress, 'PermissionType': PermissionType, 'Size': Size, 'Reserved': Reserved, 'MappingType': MappingType}})

            pos=pos+1
        elif bitcount==7: # IoMemoryMap
            BeginAddress = desc>>8
            BeginAddress<<=12

            out.append({'IoMemoryMap': {'Value': desc, 'BeginAddress': BeginAddress}})
        elif bitcount==10: # MemoryRegionMap
            RegionType0 = (desc>>11) & 0x3F
            RegionType1 = (desc>>18) & 0x3F
            RegionType2 = (desc>>25) & 0x3F
            RegionIsReadOnly0 = (desc>>17) & 0x1
            RegionIsReadOnly1 = (desc>>24) & 0x1
            RegionIsReadOnly2 = (desc>>31) & 0x1

            out.append({'MemoryRegionMap': {'Value': desc, 'RegionsType': [RegionType0, RegionType1, RegionType2], 'RegionsIsReadOnly': [RegionIsReadOnly0, RegionIsReadOnly1, RegionIsReadOnly2]}})
        elif bitcount==11: # EnableInterrupts
            InterruptNumber0 = (desc>>12) & 0x3FF
            InterruptNumber1 = (desc>>22) & 0x3FF

            if InterruptNumber0!=0x3FF:
                EnableInterrupts['Interrupts'].append(InterruptNumber0)
            if InterruptNumber1!=0x3FF:
                EnableInterrupts['Interrupts'].append(InterruptNumber1)
            EnableInterrupts['Descriptors'].append({'Value': desc, 'InterruptNumber0': InterruptNumber0, 'InterruptNumber1': InterruptNumber1})
        elif bitcount==13: # MiscParams
            ProgramType = (desc>>14) & 0x7
            Reserved = desc>>17

            out.append({'MiscParams': {'Value': desc, 'ProgramType': ProgramType, 'Reserved': Reserved}})
        elif bitcount==14: # KernelVersion
            MinorVersion = (desc>>15) & 0xF
            MajorVersion = (desc>>19) & 0x1FFF

            out.append({'KernelVersion': {'Value': desc, 'Version': {'Major': MajorVersion, 'Minor': MinorVersion}}})
        elif bitcount==15: # HandleTableSize
            HandleTableSize = (desc>>16) & 0x3FF
            Reserved = desc>>26

            out.append({'HandleTableSize': {'Value': desc, 'HandleTableSize': HandleTableSize, 'Reserved': Reserved}})
        elif bitcount==16: # MiscFlags
            EnableDebug = (desc>>17) & 0x1
            ForceDebug = (desc>>18) & 0x1
            Reserved = desc>>19

            out.append({'MiscFlags': {'Value': desc, 'EnableDebug': EnableDebug, 'ForceDebug': ForceDebug, 'Reserved': Reserved}})
        else:
            print("metaLoadKc('%s'): Unknown descriptor with bitcount %d, adding it to output." % (path, bitcount))
            out.append({'Descriptor': {'Value': desc}})

        pos=pos+1

    out.append({'EnableSystemCalls': EnableSystemCalls})
    out.append({'EnableInterrupts': EnableInterrupts})

    return out

def metaGetNameLen(data):
    NameLen = len(data)
    DataLen = NameLen
    for i in range(DataLen):
        if data[i]==0x0:
            NameLen = i
            break
    return NameLen

def metaLoad(path):
    out = {}
    if os.path.exists(path) is False:
        print("metaLoad(): File doesn't exist: %s" % (path))
        out = None
    else:
        with open(path, 'rb') as tmpf:
            data = tmpf.read()
            magicnum = struct.unpack('<I', data[0x0:0x4])[0]
            if magicnum!=0x4154454d:
                if magicnum==0x31494e49: # INI1
                    return metaIni1Load(path, data)
                else:
                    print("Bad META magicnum (0x%x) for metaLoad('%s')." % (magicnum, path))
                    out = None
            else:
                SignatureKeyGeneration, Reserved_x8, Flags, Reserved_xD, MainThreadPriority, MainThreadCoreNumber, Reserved_x10, SystemResourceSize, Version, MainThreadStackSize = struct.unpack('<IIBBBBIIII', data[0x4:0x20])
                Name = data[0x20:0x20+0x10]
                ProductCode = data[0x30:0x30+0x10]
                Reserved_x40 = data[0x40:0x40+0x30]
                AciOffset, AciSize, AcidOffset, AcidSize = struct.unpack('<IIII', data[0x70:0x80])

                out['SignatureKeyGeneration'] = SignatureKeyGeneration
                out['Reserved_x8'] = Reserved_x8
                out['Flags'] = Flags
                out['Reserved_xD'] = Reserved_xD
                out['MainThreadPriority'] = MainThreadPriority
                out['MainThreadCoreNumber'] = MainThreadCoreNumber
                out['Reserved_x10'] = Reserved_x10
                out['SystemResourceSize'] = SystemResourceSize
                out['Version'] = Version
                out['MainThreadStackSize'] = MainThreadStackSize

                namelen = metaGetNameLen(Name)
                out['Name'] = Name[:namelen].decode('utf8')
                out['ProductCode'] = ProductCode
                out['Reserved_x40'] = Reserved_x40

                metasize = len(data)
                if (AciOffset>=metasize or AciOffset+AciSize>metasize) or (AcidOffset>=metasize or AcidOffset+AcidSize>metasize):
                    print("Invalid Aci/Acid offset/size for metaLoad('%s')." % (path))
                    out = None
                else:
                    Aci = data[AciOffset:AciOffset+AciSize]
                    Acid = data[AcidOffset:AcidOffset+AcidSize]

                    magicnum, Size, Version, Unk_x209, Reserved_x20A, Reserved_x20B, Flags, ProgramIdMin, ProgramIdMax = struct.unpack('<IIBBBBIQQ', Acid[0x200:0x220])
                    Reserved_x238, Reserved_x23C = struct.unpack('<II', Acid[0x238:0x240])

                    if magicnum!=0x44494341:
                        print("Bad ACID magicnum (0x%x) for metaLoad('%s')." % (magicnum, path))
                        out = None
                    else:
                        out['Acid'] = {'Version': Version, 'Unk_x209': Unk_x209, 'Reserved_x20A': Reserved_x20A, 'Reserved_x20B': Reserved_x20B, 'Flags': Flags, 'ProgramIdMin': ProgramIdMin, 'ProgramIdMax': ProgramIdMax}

                        magicnum, Reserved_x4, Reserved_x8, Reserved_xC, ProgramId, Reserved_x18, Reserved_x1C = struct.unpack('<IIIIQII', Aci[0x0:0x20])
                        FacOffset, FacSize, SacOffset, SacSize, KcOffset, KcSize = struct.unpack('<IIIIII', Aci[0x20:0x38])
                        Reserved_x38, Reserved_x3C = struct.unpack('<II', Aci[0x38:0x40])

                        if magicnum!=0x30494341:
                            print("Bad ACI0 magicnum (0x%x) for metaLoad('%s')." % (magicnum, path))
                            out = None
                        else:
                            out['Aci'] = {'Reserved_x4': Reserved_x4, 'Reserved_x8': Reserved_x8, 'Reserved_xC': Reserved_xC, 'ProgramId': ProgramId, 'Reserved_x18': Reserved_x18, 'Reserved_x1C': Reserved_x1C, 'Reserved_x38': Reserved_x38, 'Reserved_x3C': Reserved_x3C}

                            if (FacOffset>=AciSize or FacOffset+FacSize>AciSize) or (SacOffset>=AciSize or SacOffset+SacSize>AciSize) or (KcOffset>=AciSize or KcOffset+KcSize>AciSize) or (KcSize&0x3):
                                print("Invalid data offset/size within ACID for metaLoad('%s')." % (path))
                                out = None
                            else:
                                Fac = Aci[FacOffset:FacOffset+FacSize]
                                Sac = Aci[SacOffset:SacOffset+SacSize]
                                Kc = Aci[KcOffset:KcOffset+KcSize]

                                Fac = metaLoadFac(Fac, path)
                                if Fac is None:
                                    out = None
                                else:
                                    Sac = metaLoadSac(Sac)
                                    Kc = metaLoadKc(Kc, path)

                                    out['Aci']['Fac'] = Fac
                                    out['Aci']['Sac'] = Sac
                                    out['Aci']['Kc'] = Kc

    if out is not None:
        out = {'Meta': out}
    return out

def metaIni1Load(path, data):
    out = {}
    datalen = len(data)

    magicnum = struct.unpack('<I', data[0x0:0x4])[0]

    if magicnum!=0x31494e49:
        print("Bad INI1 magicnum (0x%x) for metaIni1Load('%s')." % (magicnum, path))
        out = None
    else:
        Size, KipsCount, Reserved_xC = struct.unpack('<III', data[0x4:0x10])

        out = {'Size': Size, 'Reserved_xC': Reserved_xC, 'Kips': []}

        pos=0x10
        for KipIndex in range(KipsCount):
            if datalen < pos+0x100:
                print("Input file data is too small for metaIni1Load('%s'), KipIndex=%d." % (KipIndex))
                out = None
                break

            magicnum = struct.unpack('<I', data[pos:pos+0x4])[0]
            if magicnum!=0x3150494b:
                print("Bad KIP1 magicnum (0x%x) for metaIni1Load('%s')." % (magicnum, path))
                out = None
                break

            Kip = {}

            Name = data[pos+0x4:pos+0x10]

            ProgramId, Version, MainThreadPriority, MainThreadCoreNumber, Reserved_x1E, Flags = struct.unpack('<QIBBBB', data[pos+0x10:pos+0x20])

            TextOffset, TextSize, TextBinSize = struct.unpack('<III', data[pos+0x20:pos+0x20+0xC])
            RoOffset, RoSize, RoBinSize = struct.unpack('<III', data[pos+0x30:pos+0x30+0xC])
            DataOffset, DataSize, DataBinSize = struct.unpack('<III', data[pos+0x40:pos+0x40+0xC])

            MainThreadAffinityMask = struct.unpack('<I', data[pos+0x2C:pos+0x2C+0x4])[0]
            MainThreadStackSize = struct.unpack('<I', data[pos+0x3C:pos+0x3C+0x4])[0]
            Reserved_x4C = struct.unpack('<I', data[pos+0x4C:pos+0x4C+0x4])[0]

            Reserved_x5C, Reserved_x60, Reserved_x64 = struct.unpack('<III', data[pos+0x5C:pos+0x5C+0xC])
            Reserved_x68, Reserved_x6C, Reserved_x70 = struct.unpack('<III', data[pos+0x68:pos+0x68+0xC])
            Reserved_x74, Reserved_x78, Reserved_x7C = struct.unpack('<III', data[pos+0x74:pos+0x74+0xC])

            Kc = data[pos+0x80:pos+0x80+0x80]

            Kc = metaLoadKc(Kc, path)

            NameLen = metaGetNameLen(Name)
            Kip['Name'] = Name[:NameLen].decode('utf8')

            Kip['ProgramId'] = ProgramId
            Kip['Version'] = Version
            Kip['MainThreadPriority'] = MainThreadPriority
            Kip['MainThreadCoreNumber'] = MainThreadCoreNumber
            Kip['Reserved_x1E'] = Reserved_x1E
            Kip['Flags'] = Flags
            Kip['MainThreadAffinityMask'] = MainThreadAffinityMask
            Kip['MainThreadStackSize'] = MainThreadStackSize
            Kip['Reserved_x4C'] = Reserved_x4C

            Kip['Reserved_x5C'] = Reserved_x5C
            Kip['Reserved_x60'] = Reserved_x60
            Kip['Reserved_x64'] = Reserved_x64
            Kip['Reserved_x68'] = Reserved_x68
            Kip['Reserved_x6C'] = Reserved_x6C
            Kip['Reserved_x70'] = Reserved_x70
            Kip['Reserved_x74'] = Reserved_x74
            Kip['Reserved_x78'] = Reserved_x78
            Kip['Reserved_x7C'] = Reserved_x7C

            Kip['Kc'] = Kc

            out['Kips'].append(Kip)
            pos=pos+0x100+TextBinSize+RoBinSize+DataBinSize

    if out is not None:
        out = {'Ini1': out}
    return out

def metaDiffSac(Out, Prev, Cur, SacKey):
    for TmpKey, TmpValue in Cur['Aci']['Sac'][SacKey].items():
        if TmpKey in Prev['Aci']['Sac'][SacKey]:
            if Prev['Aci']['Sac'][SacKey][TmpKey] != TmpValue:
                if 'Aci' not in Out:
                    Out['Aci'] = {}
                if 'Sac' not in Out['Aci']:
                    Out['Aci']['Sac'] = {}
                if SacKey not in Out['Aci']['Sac']:
                    Out['Aci']['Sac'][SacKey] = {}
                if TmpKey not in Out['Aci']['Sac'][SacKey]:
                    Out['Aci']['Sac'][SacKey][TmpKey] = {}
                Out['Aci']['Sac'][SacKey][TmpKey]['Updated'] = (Prev['Aci'][SacKey][TmpKey], TmpValue)
        else:
            if 'Aci' not in Out:
                Out['Aci'] = {}
            if 'Sac' not in Out['Aci']:
                Out['Aci']['Sac'] = {}
            if SacKey not in Out['Aci']['Sac']:
                Out['Aci']['Sac'][SacKey] = {}
            if TmpKey not in Out['Aci']['Sac'][SacKey]:
                Out['Aci']['Sac'][SacKey][TmpKey] = {}
            Out['Aci']['Sac'][SacKey][TmpKey]['Added'] = TmpValue

    for TmpKey, TmpValue in Prev['Aci']['Sac'][SacKey].items():
        if TmpKey not in Cur['Aci']['Sac'][SacKey]:
            if 'Aci' not in Out:
                Out['Aci'] = {}
            if 'Sac' not in Out['Aci']:
                Out['Aci']['Sac'] = {}
            if SacKey not in Out['Aci']['Sac']:
                Out['Aci']['Sac'][SacKey] = {}
            if TmpKey not in Out['Aci']['Sac'][SacKey]:
                Out['Aci']['Sac'][SacKey][TmpKey] = {}
            Out['Aci']['Sac'][SacKey][TmpKey]['Removed'] = TmpValue

def metaMaskToList(Mask):
    pos=0
    Out = []

    while Mask!=0:
        if Mask & 0x1:
            Out.append(pos)
        pos=pos+1
        Mask>>=1

    return Out

def metaKcToDict(Kc):
    Values = {}

    for KcEntry in Kc:
        for KcKey, KcValue in KcEntry.items():
            if KcKey not in Values:
                Values[KcKey] = []
            Values[KcKey].append(KcValue)
    return Values

def metaDiffKc(Prev, Cur):
    Out = {}

    if Prev==Cur:
        return Out

    MemoryMapUpdated = {'Descriptors': []}
    MemoryMapAdded = {'Descriptors': []}
    MemoryMapRemoved = {'Descriptors': []}

    IoMemoryMapAdded = {'Descriptors': []}
    IoMemoryMapRemoved = {'Descriptors': []}

    DescriptorAdded = {'Descriptors': []}
    DescriptorRemoved = {'Descriptors': []}

    ValuesPrev = metaKcToDict(Prev)
    ValuesCur = metaKcToDict(Cur)

    for KcKey, KcEntry in ValuesCur.items():
        ValuePrev = []
        if KcKey in ValuesPrev:
            ValuePrev = ValuesPrev[KcKey]
        ValuePrevLen = len(ValuePrev)

        for KcValue in KcEntry:
            if KcKey == 'EnableSystemCalls':
                Mask = KcValue['Mask']
                if ValuePrevLen>0:
                    MaskPrev = ValuePrev[-1]['Mask']
                else:
                    MaskPrev = 0

                if Mask != MaskPrev:
                    MaskAdded = Mask & ~MaskPrev
                    MaskRemoved = MaskPrev & ~Mask

                    if KcKey not in Out:
                        Out[KcKey] = {}
                    if MaskAdded!=0:
                        Out[KcKey]['Added'] = metaMaskToList(MaskAdded)
                    if MaskRemoved!=0:
                        Out[KcKey]['Removed'] = metaMaskToList(MaskRemoved)
            elif KcKey == 'EnableInterrupts':
                Interrupts = KcValue['Interrupts']
                if ValuePrevLen>0:
                    InterruptsPrev = ValuePrev[-1]['Interrupts']
                else:
                    InterruptsPrev = []

                if Interrupts != InterruptsPrev:
                    InterruptsAdded = sorted([InterruptNum for InterruptNum in Interrupts if InterruptNum not in InterruptsPrev])
                    InterruptsRemoved = sorted([InterruptNum for InterruptNum in InterruptsPrev if InterruptNum not in Interrupts])
                    InterruptsAddedLen = len(InterruptsAdded)
                    InterruptsRemovedLen = len(InterruptsRemoved)

                    if InterruptsAddedLen>0 or InterruptsRemovedLen>0:
                        if KcKey not in Out:
                            Out[KcKey] = {}
                        if InterruptsAddedLen>0:
                            Out[KcKey]['Added'] = InterruptsAdded
                        if InterruptsRemovedLen>0:
                            Out[KcKey]['Removed'] = InterruptsRemoved
            elif KcKey == 'MemoryMap':
                MemoryMapPrev = None
                for Val in ValuePrev:
                    if KcValue['BeginAddress'] == Val['BeginAddress']:
                        MemoryMapPrev = Val
                        break
                if MemoryMapPrev is None:
                    MemoryMapAdded['Descriptors'].append(KcValue)
                    continue

                if KcValue == MemoryMapPrev:
                    continue

                Desc = {'BeginAddress': Val['BeginAddress']}
                for TmpKey, TmpValue in KcValue.items():
                    if TmpKey!='BeginAddress' and TmpValue != MemoryMapPrev[TmpKey]:
                        Desc[TmpKey] = (MemoryMapPrev[TmpKey], TmpValue)

                if len(Desc)>0:
                    MemoryMapUpdated['Descriptors'].append(Desc)

            elif KcKey == 'IoMemoryMap':
                IoMemoryMapPrev = metaFindListDictWithValue(KcValue['BeginAddress'], ValuePrev, 'BeginAddress')
                if IoMemoryMapPrev is None:
                    IoMemoryMapAdded['Descriptors'].append(KcValue)
            elif KcKey == 'Descriptor':
                TmpDesc = metaFindListDictWithValue(KcValue['Value'], Val, 'Value')
                if TmpDesc is not None:
                    continue
                DescriptorAdded['Descriptors'].append(KcValue)
            else:
                if ValuePrevLen==0:
                    if KcKey not in Out:
                        Out[KcKey] = {}
                    Out[KcKey]['Added'] = KcValue
                    continue
                DescPrev = ValuePrev[-1]

                if KcValue == DescPrev:
                    continue

                Desc = {}
                for TmpKey, TmpValue in KcValue.items():
                    if TmpValue != DescPrev[TmpKey]:
                        Desc[TmpKey] = (DescPrev[TmpKey], TmpValue)

                if len(Desc)>0:
                    if KcKey not in Out:
                        Out[KcKey] = {}
                    Out[KcKey]['Updated'] = Desc

    for KcKey, KcEntry in ValuesPrev.items():
        ValueCur = []
        if KcKey in ValuesCur:
            ValueCur = ValuesCur[KcKey]
        ValueCurLen = len(ValueCur)

        for KcValue in KcEntry:
            if KcKey == 'EnableSystemCalls' or KcKey == 'EnableInterrupts':
                continue
            elif KcKey == 'MemoryMap':
                MemoryMapCur = metaFindListDictWithValue(KcValue['BeginAddress'], ValueCur, 'BeginAddress')
                if MemoryMapCur is None:
                    MemoryMapRemoved['Descriptors'].append(KcValue)
            elif KcKey == 'IoMemoryMap':
                IoMemoryMapCur = metaFindListDictWithValue(KcValue['BeginAddress'], ValueCur, 'BeginAddress')
                if IoMemoryMapCur is None:
                    IoMemoryMapRemoved['Descriptors'].append(KcValue)
            elif KcKey == 'Descriptor':
                TmpDesc = metaFindListDictWithValue(KcValue['Value'], ValueCur, 'Value')
                if TmpDesc is not None:
                    continue
                DescriptorRemoved['Descriptors'].append(KcValue)
            else:
                if ValueCurLen==0:
                    if KcKey not in Out:
                        Out[KcKey] = {}
                    Out[KcKey]['Removed'] = KcValue

    MemoryMapUpdatedLen = len(MemoryMapUpdated['Descriptors'])
    MemoryMapAddedLen = len(MemoryMapAdded['Descriptors'])
    MemoryMapRemovedLen = len(MemoryMapRemoved['Descriptors'])

    IoMemoryMapAddedLen = len(IoMemoryMapAdded['Descriptors'])
    IoMemoryMapRemovedLen = len(IoMemoryMapRemoved['Descriptors'])

    DescriptorAddedLen = len(DescriptorAdded['Descriptors'])
    DescriptorRemovedLen = len(DescriptorRemoved['Descriptors'])

    if MemoryMapUpdatedLen>0 or MemoryMapUpdatedLen>0 or MemoryMapRemovedLen>0:
        if 'MemoryMap' not in Out:
            Out['MemoryMap'] = {}
        if MemoryMapUpdatedLen>0:
            Out['MemoryMap']['Updated'] = MemoryMapUpdated
        if MemoryMapAddedLen>0:
            Out['MemoryMap']['Added'] = MemoryMapAdded
        if MemoryMapRemovedLen>0:
            Out['MemoryMap']['Removed'] = MemoryMapRemoved

    if IoMemoryMapAddedLen>0 or IoMemoryMapRemovedLen>0:
        if 'IoMemoryMap' not in Out:
            Out['IoMemoryMap'] = {}
        if IoMemoryMapAddedLen>0:
            Out['IoMemoryMap']['Added'] = IoMemoryMapAdded
        if IoMemoryMapRemovedLen>0:
            Out['IoMemoryMap']['Removed'] = IoMemoryMapRemoved

    if DescriptorAddedLen>0 or DescriptorRemovedLen>0:
        if 'Descriptor' not in Out:
            Out['Descriptor'] = {}
        if DescriptorAddedLen>0:
            Out['Descriptor']['Added'] = DescriptorAdded
        if DescriptorRemovedLen>0:
            Out['Descriptor']['Removed'] = DescriptorRemoved

    return Out

def metaDiff(Prev, Cur):
    Out = {}

    for Key, Value in Cur.items():
        if Key in Prev:
            if Key == 'Acid':
                for AcidKey, AcidValue in Cur[Key].items():
                    if Prev[Key][AcidKey] != AcidValue:
                        if Key not in Out:
                            Out[Key] = {}
                        if AcidKey not in Out[Key]:
                            Out[Key][AcidKey] = {}
                        Out[Key][AcidKey]['Updated'] = (Prev[Key][AcidKey], AcidValue)
            elif Key != 'Aci':
                if Prev[Key] != Cur[Key]:
                    if Key not in Out:
                        Out[Key] = {}
                    Out[Key]['Updated'] = (Prev[Key], Value)
            elif 'Aci' in Prev:
                for AciKey, AciValue in Cur[Key].items():
                    if AciKey!='Fac' and AciKey!='Sac' and AciKey!='Kc':
                        if Prev[Key][AciKey] != AciValue:
                            if Key not in Out:
                                Out[Key] = {}
                            if AciKey not in Out[Key]:
                                Out[Key][AciKey] = {}
                            Out[Key][AciKey]['Updated'] = (Prev[Key][AciKey], AciValue)
                    elif AciKey=='Fac' and 'Fac' in Prev[Key]:
                        for FacKey, FacValue in Cur[Key][AciKey].items():
                            FacValuePrev = Prev[Key][AciKey][FacKey]
                            if FacValuePrev != FacValue:
                                if FacKey != 'ContentOwnerInfo' and FacKey != 'SaveDataOwnerInfo':
                                    if Key not in Out:
                                        Out[Key] = {}
                                    if AciKey not in Out[Key]:
                                        Out[Key][AciKey] = {}
                                    if FacKey not in Out[Key][AciKey]:
                                        Out[Key][AciKey][FacKey] = {}
                                    Out[Key][AciKey][FacKey]['Updated'] = (FacValuePrev, FacValue)
                                else:
                                    InfoUpdated = []
                                    InfoAdded = []
                                    InfoRemoved = []

                                    for Info in FacValue:
                                        TmpPrev = None
                                        for InfoPrev in FacValuePrev:
                                            if InfoPrev['Id']==Info['Id']:
                                                TmpPrev = InfoPrev
                                                break
                                        if TmpPrev is None:
                                            InfoAdded.append(Info)
                                        elif FacKey=='SaveDataOwnerInfo':
                                            if TmpPrev['Access']!=Info['Access']:
                                                InfoUpdated.append((TmpPrev, Info))

                                    for InfoPrev in FacValuePrev:
                                        TmpCur = None
                                        for Info in FacValue:
                                            if Info['Id']==InfoPrev['Id']:
                                                TmpCur = Info
                                                break
                                        if TmpCur is None:
                                            InfoRemoved.append(InfoPrev)

                                    InfoUpdatedLen = len(InfoUpdated)
                                    InfoAddedLen = len(InfoAdded)
                                    InfoRemovedLen = len(InfoRemoved)

                                    if InfoUpdatedLen>0 or InfoAddedLen>0 or InfoRemovedLen>0:
                                        if Key not in Out:
                                            Out[Key] = {}
                                        if AciKey not in Out[Key]:
                                            Out[Key][AciKey] = {}
                                        if FacKey not in Out[Key][AciKey]:
                                            Out[Key][AciKey][FacKey] = {}
                                        if InfoUpdatedLen>0:
                                            Out[Key][AciKey][FacKey]['Updated'] = InfoUpdated
                                        if InfoAddedLen>0:
                                            Out[Key][AciKey][FacKey]['Added'] = InfoAdded
                                        if InfoRemovedLen>0:
                                            Out[Key][AciKey][FacKey]['Removed'] = InfoRemoved
                    elif AciKey=='Sac' and 'Sac' in Prev['Aci']:
                        metaDiffSac(Out, Prev, Cur, 'Server')
                        metaDiffSac(Out, Prev, Cur, 'Client')
                    elif AciKey=='Kc' and 'Kc' in Prev['Aci']:
                        KcDiff = metaDiffKc(Prev['Aci'][AciKey], AciValue)
                        if len(KcDiff)>0:
                            if 'Aci' not in Out:
                                Out['Aci'] = {}
                            Out['Aci']['Kc'] = KcDiff

    return {'Meta': Out}

def metaDiffIni1(Prev, Cur):
    Out = {}

    Updated = {}
    Added = {}
    Removed = {}

    for Key, Value in Cur.items():
        if Key in Prev:
            if Key != 'Kips':
                if Prev[Key] != Cur[Key]:
                    Updated[Key] = (Prev[Key], Value)
            else:
                for Kip in Cur[Key]:
                    KipKeyId = "%016X_%s" % (Kip['ProgramId'], Kip['Name'])
                    PrevKip = None
                    for CurKip in Prev[Key]:
                        if CurKip['ProgramId'] == Kip['ProgramId'] or CurKip['Name'] == Kip['Name']:
                            PrevKip = CurKip
                            break
                    if PrevKip is None:
                        if Key not in Added:
                            Added[Key] = []
                        Added[Key].append(Kip)
                        continue

                    for KipKey, KipValue in Kip.items():
                        if KipKey != 'Kc':
                            if PrevKip[KipKey] != KipValue:
                                if Key not in Updated:
                                    Updated[Key] = {}
                                if KipKeyId not in Updated[Key]:
                                    Updated[Key][KipKeyId] = {}
                                Updated[Key][KipKeyId][KipKey] = (PrevKip[KipKey], KipValue)
                        else:
                            KcDiff = metaDiffKc(PrevKip[KipKey], KipValue)
                            if len(KcDiff)>0:
                                if Key not in Updated:
                                    Updated[Key] = {}
                                if KipKeyId not in Updated[Key]:
                                    Updated[Key][KipKeyId] = {}
                                Updated[Key][KipKeyId][KipKey] = KcDiff

                for PrevKip in Prev[Key]:
                    found = False
                    for Kip in Cur[Key]:
                        if PrevKip['ProgramId'] == Kip['ProgramId'] or PrevKip['Name'] == Kip['Name']:
                            found = True
                            break
                    if found is False:
                        if Key not in Removed:
                            Removed[Key] = []
                        Removed[Key].append(Kip)

    if len(Updated)>0:
        Out['Updated'] = Updated

    if len(Added)>0:
        Out['Added'] = Added

    if len(Removed)>0:
        Out['Removed'] = Removed

    return {'Ini1': Out}

def metaDiffPathArray(InPaths):
    out = {}

    for Id, Paths in InPaths.items():
        Prev = metaLoad(Paths['Prev'])
        Cur = metaLoad(Paths['Cur'])

        if Prev is None or Cur is None:
            print("metaDiffPathArray(): Skipping diff for %s since loading Prev/Cur failed." % (Id))
        else:
            if 'Meta' in Prev and 'Meta' in Cur:
                tmp = metaDiff(Prev['Meta'], Cur['Meta'])
            elif 'Ini1' in Prev and 'Ini1' in Cur:
                tmp = metaDiffIni1(Prev['Ini1'], Cur['Ini1'])
            else:
                print("metaDiffPathArray(): Skipping diff for %s since the required data was not specified." % (Id))
                continue
            out[Id] = tmp

    return out

if __name__ == "__main__":
    if len(sys.argv)>1:
        out = metaLoad(sys.argv[1])
        print(out)

