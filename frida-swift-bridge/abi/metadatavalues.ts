export const NumWords_ValueBuffer = 3;

const MetadataKindIsNonHeap = 0x200;

enum TargetValueWitnessFlags_Values {
    AlignmentMask = 0x000000ff,
    IsNonPOD = 0x00010000,
    IsNonInline = 0x00020000,
    HasSpareBits = 0x00080000,
    IsNonBitwiseTakable = 0x00100000,
    HasEnumWitnesses = 0x00200000,
    Incomplete = 0x00400000,
}

export class TargetValueWitnessFlags {
    constructor(public data: number) {}

    get isInlineStorage(): boolean {
        return !(this.data & TargetValueWitnessFlags_Values.IsNonInline);
    }

    get isPOD(): boolean {
        return !(this.data & TargetValueWitnessFlags_Values.IsNonPOD);
    }

    get isBitwiseTakable(): boolean {
        return !(
            this.data & TargetValueWitnessFlags_Values.IsNonBitwiseTakable
        );
    }

    getAlignmentMask(): number {
        return this.data & TargetValueWitnessFlags_Values.AlignmentMask;
    }
}

export enum MetadataKind {
    Class = 0,
    Struct = 0 | MetadataKindIsNonHeap,
    Enum = 1 | MetadataKindIsNonHeap,
    LastEnumerated = 0x7ff,
}

export function getEnumeratedMetadataKind(kind: MetadataKind): MetadataKind {
    if (kind > MetadataKind.LastEnumerated) {
        return MetadataKind.Class;
    }
    return kind;
}

export enum ContextDescriptorKind {
    Module = 0,
    Extension = 1,
    Anonymous = 2,
    Protocol = 3,
    OpaqueType = 4,
    TypeFirst = 16,
    Class = TypeFirst,
    Struct = TypeFirst + 1,
    Enum = TypeFirst + 2,
}

enum TypeContextDescriptorFlags_Values {
    MetadataInitialization = 0,
    MetadataInitialization_width = 2,
    Class_ResilientSuperclassReferenceKind = 9,
    Class_HasResilientSuperclass = 13,
    Class_HasOverrideTable = 14,
    Class_HasVTable = 15,
}

enum MetadataInitializationKind {
    NoMetadataInitialization = 0,
    SingletonMetadataInitialization = 1,
    ForeignMetadataInitialization = 2,
}

export class TypeContextDescriptorFlags {
    constructor(private value: TypeContextDescriptorFlags_Values) {}

    class_hasVTable(): boolean {
        return !!(
            this.value &
            (1 << TypeContextDescriptorFlags_Values.Class_HasVTable)
        );
    }

    class_hasResilientSuperClass(): boolean {
        return !!(
            this.value &
            (1 <<
                TypeContextDescriptorFlags_Values.Class_HasResilientSuperclass)
        );
    }

    class_hasOverrideTable(): boolean {
        return !!(
            this.value &
            (1 << TypeContextDescriptorFlags_Values.Class_HasOverrideTable)
        );
    }

    getMetadataInitialization(): MetadataInitializationKind {
        return getField(
            this.value,
            TypeContextDescriptorFlags_Values.MetadataInitialization,
            TypeContextDescriptorFlags_Values.MetadataInitialization_width
        );
    }

    hasSingletonMetadataInitialization(): boolean {
        return (
            this.getMetadataInitialization() ===
            MetadataInitializationKind.SingletonMetadataInitialization
        );
    }

    hasForeignMetadataInitialization(): boolean {
        return (
            this.getMetadataInitialization() ===
            MetadataInitializationKind.ForeignMetadataInitialization
        );
    }
}

function getField(bits: number, firstBit: number, width: number) {
    return (bits >>> firstBit) & ~(~0 << width);
}

export enum MethodDescriptorKind {
    Method,
    Init,
    Getter,
    Setter,
    ModifyCoroutine,
    ReadCoroutine,
}

export class MethodDescriptorFlags {
    private static readonly KindMask = 0x0f;

    constructor(readonly value: number) {}

    getKind(): MethodDescriptorKind {
        return this.value & MethodDescriptorFlags.KindMask;
    }
}

export enum TypeReferenceKind {
    DirectTypeDescriptor = 0x00,
    IndirectTypeDescriptor = 0x01,
    DirectObjCClassName = 0x02,
    IndirectObjCClass = 0x03,
}

enum ConformanceFlags_Value {
    TypeMetadataKindMask = 0x7 << 3,
    TypeMetadataKindShift = 3,
}

export class ConformanceFlags {
    constructor(private value: number) {}

    getTypeReferenceKind(): TypeReferenceKind {
        return (
            (this.value & ConformanceFlags_Value.TypeMetadataKindMask) >>
            ConformanceFlags_Value.TypeMetadataKindShift
        );
    }
}

export class ProtocolClassConstraint {
    static readonly Class = false;
    static readonly Any = true;
}

enum ProtocolContextDescriptorFlags_Values {
    HasClassConstratint = 0,
    HasClassConstratint_width = 1,
}

export class ProtocolContextDescriptorFlags {
    constructor(private bits: number) {}

    getClassConstraint(): ProtocolClassConstraint {
        return !!(
            this.bits &
            (1 << ProtocolContextDescriptorFlags_Values.HasClassConstratint)
        );
    }
}
