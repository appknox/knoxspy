import * as vue from 'vue';
import { ComponentPropsOptions, ExtractPropTypes, VNodeChild, VNode } from 'vue';

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

declare const VBottomNavigation: {
    new (...args: any[]): vue.CreateComponentPublicInstance<{
        style: vue.StyleValue;
        height: string | number;
        active: boolean;
        name: string;
        disabled: boolean;
        tag: string;
        order: string | number;
        absolute: boolean;
        multiple: boolean;
        tile: boolean;
        density: Density;
        selectedClass: string;
        grow: boolean;
    } & {
        class?: any;
        mode?: string | undefined;
        theme?: string | undefined;
        color?: string | undefined;
        border?: string | number | boolean | undefined;
        rounded?: string | number | boolean | undefined;
        mandatory?: boolean | "force" | undefined;
        elevation?: string | number | undefined;
        baseColor?: string | undefined;
        max?: number | undefined;
        bgColor?: string | undefined;
    } & {
        "onUpdate:active"?: ((value: any) => any) | undefined;
    }, void, unknown, {}, {}, vue.ComponentOptionsMixin, vue.ComponentOptionsMixin, Omit<{
        'update:active': (value: any) => boolean;
        'update:modelValue': (value: any) => boolean;
    }, "v-slot:default" | "$children" | "v-slots" | "modelValue" | "update:modelValue">, vue.VNodeProps & vue.AllowedComponentProps & vue.ComponentCustomProps & {
        style: vue.StyleValue;
        height: string | number;
        active: boolean;
        name: string;
        disabled: boolean;
        tag: string;
        order: string | number;
        absolute: boolean;
        multiple: boolean;
        tile: boolean;
        density: Density;
        selectedClass: string;
        grow: boolean;
    } & {
        class?: any;
        mode?: string | undefined;
        theme?: string | undefined;
        color?: string | undefined;
        border?: string | number | boolean | undefined;
        rounded?: string | number | boolean | undefined;
        mandatory?: boolean | "force" | undefined;
        elevation?: string | number | undefined;
        baseColor?: string | undefined;
        max?: number | undefined;
        bgColor?: string | undefined;
    } & {
        "onUpdate:active"?: ((value: any) => any) | undefined;
    }, {
        style: vue.StyleValue;
        height: string | number;
        active: boolean;
        name: string;
        disabled: boolean;
        tag: string;
        order: string | number;
        absolute: boolean;
        rounded: string | number | boolean;
        multiple: boolean;
        tile: boolean;
        density: Density;
        selectedClass: string;
        grow: boolean;
    }, true, {}, vue.SlotsType<Partial<{
        default: () => vue.VNode<vue.RendererNode, vue.RendererElement, {
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
        height: string | number;
        active: boolean;
        name: string;
        disabled: boolean;
        tag: string;
        order: string | number;
        absolute: boolean;
        multiple: boolean;
        tile: boolean;
        density: Density;
        selectedClass: string;
        grow: boolean;
    } & {
        class?: any;
        mode?: string | undefined;
        theme?: string | undefined;
        color?: string | undefined;
        border?: string | number | boolean | undefined;
        rounded?: string | number | boolean | undefined;
        mandatory?: boolean | "force" | undefined;
        elevation?: string | number | undefined;
        baseColor?: string | undefined;
        max?: number | undefined;
        bgColor?: string | undefined;
    } & {
        "onUpdate:active"?: ((value: any) => any) | undefined;
    }, {}, {}, {}, {}, {
        style: vue.StyleValue;
        height: string | number;
        active: boolean;
        name: string;
        disabled: boolean;
        tag: string;
        order: string | number;
        absolute: boolean;
        rounded: string | number | boolean;
        multiple: boolean;
        tile: boolean;
        density: Density;
        selectedClass: string;
        grow: boolean;
    }>;
    __isFragment?: undefined;
    __isTeleport?: undefined;
    __isSuspense?: undefined;
} & vue.ComponentOptionsBase<{
    style: vue.StyleValue;
    height: string | number;
    active: boolean;
    name: string;
    disabled: boolean;
    tag: string;
    order: string | number;
    absolute: boolean;
    multiple: boolean;
    tile: boolean;
    density: Density;
    selectedClass: string;
    grow: boolean;
} & {
    class?: any;
    mode?: string | undefined;
    theme?: string | undefined;
    color?: string | undefined;
    border?: string | number | boolean | undefined;
    rounded?: string | number | boolean | undefined;
    mandatory?: boolean | "force" | undefined;
    elevation?: string | number | undefined;
    baseColor?: string | undefined;
    max?: number | undefined;
    bgColor?: string | undefined;
} & {
    "onUpdate:active"?: ((value: any) => any) | undefined;
}, void, unknown, {}, {}, vue.ComponentOptionsMixin, vue.ComponentOptionsMixin, Omit<{
    'update:active': (value: any) => boolean;
    'update:modelValue': (value: any) => boolean;
}, "v-slot:default" | "$children" | "v-slots" | "modelValue" | "update:modelValue">, string, {
    style: vue.StyleValue;
    height: string | number;
    active: boolean;
    name: string;
    disabled: boolean;
    tag: string;
    order: string | number;
    absolute: boolean;
    rounded: string | number | boolean;
    multiple: boolean;
    tile: boolean;
    density: Density;
    selectedClass: string;
    grow: boolean;
}, {}, string, vue.SlotsType<Partial<{
    default: () => vue.VNode<vue.RendererNode, vue.RendererElement, {
        [key: string]: any;
    }>[];
}>>> & vue.VNodeProps & vue.AllowedComponentProps & vue.ComponentCustomProps & (new <T>(props: {
    modelValue?: T | undefined;
    'onUpdate:modelValue'?: ((value: T) => void) | undefined;
}, slots: {
    default: never;
}) => GenericProps<{
    modelValue?: T | undefined;
    'onUpdate:modelValue'?: ((value: T) => void) | undefined;
}, {
    default: never;
}>) & FilterPropsOptions<{
    theme: StringConstructor;
    modelValue: {
        type: null;
        default: undefined;
    };
    multiple: BooleanConstructor;
    mandatory: vue.PropType<boolean | "force">;
    max: NumberConstructor;
    selectedClass: {
        type: vue.PropType<string>;
        default: string;
    };
    disabled: BooleanConstructor;
    tag: Omit<{
        type: StringConstructor;
        default: string;
    }, "default" | "type"> & {
        type: vue.PropType<string>;
        default: string;
    };
    name: Omit<{
        type: StringConstructor;
    }, "default" | "type"> & {
        type: vue.PropType<string>;
        default: string;
    };
    order: {
        type: (StringConstructor | NumberConstructor)[];
        default: number;
    };
    absolute: BooleanConstructor;
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
    bgColor: StringConstructor;
    color: StringConstructor;
    grow: BooleanConstructor;
    mode: {
        type: StringConstructor;
        validator: (v: any) => boolean;
    };
    height: {
        type: (StringConstructor | NumberConstructor)[];
        default: number;
    };
    active: {
        type: BooleanConstructor;
        default: boolean;
    };
}, vue.ExtractPropTypes<{
    theme: StringConstructor;
    modelValue: {
        type: null;
        default: undefined;
    };
    multiple: BooleanConstructor;
    mandatory: vue.PropType<boolean | "force">;
    max: NumberConstructor;
    selectedClass: {
        type: vue.PropType<string>;
        default: string;
    };
    disabled: BooleanConstructor;
    tag: Omit<{
        type: StringConstructor;
        default: string;
    }, "default" | "type"> & {
        type: vue.PropType<string>;
        default: string;
    };
    name: Omit<{
        type: StringConstructor;
    }, "default" | "type"> & {
        type: vue.PropType<string>;
        default: string;
    };
    order: {
        type: (StringConstructor | NumberConstructor)[];
        default: number;
    };
    absolute: BooleanConstructor;
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
    bgColor: StringConstructor;
    color: StringConstructor;
    grow: BooleanConstructor;
    mode: {
        type: StringConstructor;
        validator: (v: any) => boolean;
    };
    height: {
        type: (StringConstructor | NumberConstructor)[];
        default: number;
    };
    active: {
        type: BooleanConstructor;
        default: boolean;
    };
}>>;
type VBottomNavigation = InstanceType<typeof VBottomNavigation>;

export { VBottomNavigation };
