import * as vue from 'vue';
import { ComponentPropsOptions, ExtractPropTypes, VNodeChild, VNode, ComponentInternalInstance, Ref, ComputedRef } from 'vue';

type SlotsToProps<U extends RawSlots, T = MakeInternalSlots<U>> = {
    $children?: (VNodeChild | (T extends {
        default: infer V;
    } ? V : {}) | {
        [K in keyof T]?: T[K];
    });
    'v-slots'?: {
        [K in keyof T]?: T[K] | false;
    };
} & {
    [K in keyof T as `v-slot:${K & string}`]?: T[K] | false;
};
type RawSlots = Record<string, unknown>;
type Slot<T> = [T] extends [never] ? () => VNodeChild : (arg: T) => VNodeChild;
type VueSlot<T> = [T] extends [never] ? () => VNode[] : (arg: T) => VNode[];
type MakeInternalSlots<T extends RawSlots> = {
    [K in keyof T]: Slot<T[K]>;
};
type MakeSlots<T extends RawSlots> = {
    [K in keyof T]: VueSlot<T[K]>;
};
type GenericProps<Props, Slots extends Record<string, unknown>> = {
    $props: Props & SlotsToProps<Slots>;
    $slots: MakeSlots<Slots>;
};
interface FilterPropsOptions<PropsOptions extends Readonly<ComponentPropsOptions>, Props = ExtractPropTypes<PropsOptions>> {
    filterProps<T extends Partial<Props>, U extends Exclude<keyof Props, Exclude<keyof Props, keyof T>>>(props: T): Partial<Pick<T, U>>;
}

type Density = null | 'default' | 'comfortable' | 'compact';

interface GroupItem {
    id: number;
    value: Ref<unknown>;
    disabled: Ref<boolean | undefined>;
    useIndexAsValue?: boolean;
}
interface GroupProvide {
    register: (item: GroupItem, cmp: ComponentInternalInstance) => void;
    unregister: (id: number) => void;
    select: (id: number, value: boolean) => void;
    selected: Ref<Readonly<number[]>>;
    isSelected: (id: number) => boolean;
    prev: () => void;
    next: () => void;
    selectedClass: Ref<string | undefined>;
    items: ComputedRef<{
        id: number;
        value: unknown;
        disabled: boolean | undefined;
    }[]>;
    disabled: Ref<boolean | undefined>;
    getItemIndex: (value: unknown) => number;
}

type BtnToggleSlotProps = 'isSelected' | 'select' | 'selected' | 'next' | 'prev';
interface DefaultBtnToggleSlot extends Pick<GroupProvide, BtnToggleSlotProps> {
}
type VBtnToggleSlots = {
    default: DefaultBtnToggleSlot;
};
declare const VBtnToggle: {
    new (...args: any[]): vue.CreateComponentPublicInstance<{
        style: vue.StyleValue;
        disabled: boolean;
        tag: string;
        variant: "flat" | "text" | "elevated" | "tonal" | "outlined" | "plain";
        multiple: boolean;
        tile: boolean;
        density: Density;
        divided: boolean;
    } & {
        class?: any;
        theme?: string | undefined;
        color?: string | undefined;
        border?: string | number | boolean | undefined;
        rounded?: string | number | boolean | undefined;
        mandatory?: boolean | "force" | undefined;
        elevation?: string | number | undefined;
        baseColor?: string | undefined;
        max?: number | undefined;
        selectedClass?: string | undefined;
    } & {}, {
        next: () => void;
        prev: () => void;
        select: (id: number, value: boolean) => void;
    }, unknown, {}, {}, vue.ComponentOptionsMixin, vue.ComponentOptionsMixin, Omit<{
        'update:modelValue': (value: any) => boolean;
    }, "v-slot:default" | "$children" | "v-slots" | "modelValue" | "update:modelValue">, vue.VNodeProps & vue.AllowedComponentProps & vue.ComponentCustomProps & {
        style: vue.StyleValue;
        disabled: boolean;
        tag: string;
        variant: "flat" | "text" | "elevated" | "tonal" | "outlined" | "plain";
        multiple: boolean;
        tile: boolean;
        density: Density;
        divided: boolean;
    } & {
        class?: any;
        theme?: string | undefined;
        color?: string | undefined;
        border?: string | number | boolean | undefined;
        rounded?: string | number | boolean | undefined;
        mandatory?: boolean | "force" | undefined;
        elevation?: string | number | undefined;
        baseColor?: string | undefined;
        max?: number | undefined;
        selectedClass?: string | undefined;
    } & {}, {
        style: vue.StyleValue;
        disabled: boolean;
        tag: string;
        rounded: string | number | boolean;
        variant: "flat" | "text" | "elevated" | "tonal" | "outlined" | "plain";
        multiple: boolean;
        tile: boolean;
        density: Density;
        divided: boolean;
    }, true, {}, vue.SlotsType<Partial<{
        default: (arg: DefaultBtnToggleSlot) => vue.VNode<vue.RendererNode, vue.RendererElement, {
            [key: string]: any;
        }>[];
    }>>, {
        P: {};
        B: {};
        D: {};
        C: {};
        M: {};
        Defaults: {};
    }, {
        style: vue.StyleValue;
        disabled: boolean;
        tag: string;
        variant: "flat" | "text" | "elevated" | "tonal" | "outlined" | "plain";
        multiple: boolean;
        tile: boolean;
        density: Density;
        divided: boolean;
    } & {
        class?: any;
        theme?: string | undefined;
        color?: string | undefined;
        border?: string | number | boolean | undefined;
        rounded?: string | number | boolean | undefined;
        mandatory?: boolean | "force" | undefined;
        elevation?: string | number | undefined;
        baseColor?: string | undefined;
        max?: number | undefined;
        selectedClass?: string | undefined;
    } & {}, {
        next: () => void;
        prev: () => void;
        select: (id: number, value: boolean) => void;
    }, {}, {}, {}, {
        style: vue.StyleValue;
        disabled: boolean;
        tag: string;
        rounded: string | number | boolean;
        variant: "flat" | "text" | "elevated" | "tonal" | "outlined" | "plain";
        multiple: boolean;
        tile: boolean;
        density: Density;
        divided: boolean;
    }>;
    __isFragment?: undefined;
    __isTeleport?: undefined;
    __isSuspense?: undefined;
} & vue.ComponentOptionsBase<{
    style: vue.StyleValue;
    disabled: boolean;
    tag: string;
    variant: "flat" | "text" | "elevated" | "tonal" | "outlined" | "plain";
    multiple: boolean;
    tile: boolean;
    density: Density;
    divided: boolean;
} & {
    class?: any;
    theme?: string | undefined;
    color?: string | undefined;
    border?: string | number | boolean | undefined;
    rounded?: string | number | boolean | undefined;
    mandatory?: boolean | "force" | undefined;
    elevation?: string | number | undefined;
    baseColor?: string | undefined;
    max?: number | undefined;
    selectedClass?: string | undefined;
} & {}, {
    next: () => void;
    prev: () => void;
    select: (id: number, value: boolean) => void;
}, unknown, {}, {}, vue.ComponentOptionsMixin, vue.ComponentOptionsMixin, Omit<{
    'update:modelValue': (value: any) => boolean;
}, "v-slot:default" | "$children" | "v-slots" | "modelValue" | "update:modelValue">, string, {
    style: vue.StyleValue;
    disabled: boolean;
    tag: string;
    rounded: string | number | boolean;
    variant: "flat" | "text" | "elevated" | "tonal" | "outlined" | "plain";
    multiple: boolean;
    tile: boolean;
    density: Density;
    divided: boolean;
}, {}, string, vue.SlotsType<Partial<{
    default: (arg: DefaultBtnToggleSlot) => vue.VNode<vue.RendererNode, vue.RendererElement, {
        [key: string]: any;
    }>[];
}>>> & vue.VNodeProps & vue.AllowedComponentProps & vue.ComponentCustomProps & (new <T>(props: {
    modelValue?: T | undefined;
    'onUpdate:modelValue'?: ((value: T) => void) | undefined;
}, slots: VBtnToggleSlots) => GenericProps<{
    modelValue?: T | undefined;
    'onUpdate:modelValue'?: ((value: T) => void) | undefined;
}, VBtnToggleSlots>) & FilterPropsOptions<{
    modelValue: {
        type: null;
        default: undefined;
    };
    multiple: BooleanConstructor;
    mandatory: vue.PropType<boolean | "force">;
    max: NumberConstructor;
    selectedClass: StringConstructor;
    disabled: BooleanConstructor;
    color: StringConstructor;
    variant: {
        type: vue.PropType<"flat" | "text" | "elevated" | "tonal" | "outlined" | "plain">;
        default: string;
        validator: (v: any) => boolean;
    };
    theme: StringConstructor;
    tag: {
        type: StringConstructor;
        default: string;
    };
    rounded: {
        type: (StringConstructor | NumberConstructor | BooleanConstructor)[];
        default: undefined;
    };
    tile: BooleanConstructor;
    elevation: {
        type: (StringConstructor | NumberConstructor)[];
        validator(v: any): boolean;
    };
    density: {
        type: vue.PropType<Density>;
        default: string;
        validator: (v: any) => boolean;
    };
    class: vue.PropType<any>;
    style: {
        type: vue.PropType<vue.StyleValue>;
        default: null;
    };
    border: (StringConstructor | NumberConstructor | BooleanConstructor)[];
    baseColor: StringConstructor;
    divided: BooleanConstructor;
}, vue.ExtractPropTypes<{
    modelValue: {
        type: null;
        default: undefined;
    };
    multiple: BooleanConstructor;
    mandatory: vue.PropType<boolean | "force">;
    max: NumberConstructor;
    selectedClass: StringConstructor;
    disabled: BooleanConstructor;
    color: StringConstructor;
    variant: {
        type: vue.PropType<"flat" | "text" | "elevated" | "tonal" | "outlined" | "plain">;
        default: string;
        validator: (v: any) => boolean;
    };
    theme: StringConstructor;
    tag: {
        type: StringConstructor;
        default: string;
    };
    rounded: {
        type: (StringConstructor | NumberConstructor | BooleanConstructor)[];
        default: undefined;
    };
    tile: BooleanConstructor;
    elevation: {
        type: (StringConstructor | NumberConstructor)[];
        validator(v: any): boolean;
    };
    density: {
        type: vue.PropType<Density>;
        default: string;
        validator: (v: any) => boolean;
    };
    class: vue.PropType<any>;
    style: {
        type: vue.PropType<vue.StyleValue>;
        default: null;
    };
    border: (StringConstructor | NumberConstructor | BooleanConstructor)[];
    baseColor: StringConstructor;
    divided: BooleanConstructor;
}>>;
type VBtnToggle = InstanceType<typeof VBtnToggle>;

export { VBtnToggle };
