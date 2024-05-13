import * as vue from 'vue';
import { ComponentPropsOptions, ExtractPropTypes, JSXComponent, PropType, WritableComputedRef, Ref, CSSProperties, VNode } from 'vue';

interface FilterPropsOptions<PropsOptions extends Readonly<ComponentPropsOptions>, Props = ExtractPropTypes<PropsOptions>> {
    filterProps<T extends Partial<Props>, U extends Exclude<keyof Props, Exclude<keyof Props, keyof T>>>(props: T): Partial<Pick<T, U>>;
}

declare function deepEqual(a: any, b: any): boolean;

type Density = null | 'default' | 'comfortable' | 'compact';

type IconValue = string | (string | [path: string, opacity: number])[] | JSXComponent;
declare const IconValue: PropType<IconValue>;

type SelectionControlSlot = {
    model: WritableComputedRef<boolean>;
    textColorClasses: Ref<string[]>;
    textColorStyles: Ref<CSSProperties>;
    backgroundColorClasses: Ref<string[]>;
    backgroundColorStyles: Ref<CSSProperties>;
    inputNode: VNode;
    icon: IconValue | undefined;
    props: {
        onBlur: (e: Event) => void;
        onFocus: (e: FocusEvent) => void;
        id: string;
    };
};

declare const VRadio: {
    new (...args: any[]): vue.CreateComponentPublicInstance<{
        style: vue.StyleValue;
        error: boolean;
        disabled: boolean | null;
        readonly: boolean | null;
        inline: boolean;
        multiple: boolean | null;
        density: Density;
        ripple: boolean | {
            class: string;
        } | undefined;
        falseIcon: NonNullable<IconValue>;
        trueIcon: NonNullable<IconValue>;
        valueComparator: typeof deepEqual;
    } & {
        class?: any;
        id?: string | undefined;
        label?: string | undefined;
        type?: string | undefined;
        value?: any;
        theme?: string | undefined;
        color?: string | undefined;
        name?: string | undefined;
        modelValue?: any;
        baseColor?: string | undefined;
        defaultsTarget?: string | undefined;
        trueValue?: any;
        falseValue?: any;
    } & {
        $children?: vue.VNodeChild | ((arg: {
            backgroundColorClasses: vue.Ref<string[]>;
            backgroundColorStyles: vue.Ref<vue.CSSProperties>;
        }) => vue.VNodeChild) | {
            default?: ((arg: {
                backgroundColorClasses: vue.Ref<string[]>;
                backgroundColorStyles: vue.Ref<vue.CSSProperties>;
            }) => vue.VNodeChild) | undefined;
            label?: ((arg: {
                label: string | undefined;
                props: Record<string, unknown>;
            }) => vue.VNodeChild) | undefined;
            input?: ((arg: SelectionControlSlot) => vue.VNodeChild) | undefined;
        };
        'v-slots'?: {
            default?: false | ((arg: {
                backgroundColorClasses: vue.Ref<string[]>;
                backgroundColorStyles: vue.Ref<vue.CSSProperties>;
            }) => vue.VNodeChild) | undefined;
            label?: false | ((arg: {
                label: string | undefined;
                props: Record<string, unknown>;
            }) => vue.VNodeChild) | undefined;
            input?: false | ((arg: SelectionControlSlot) => vue.VNodeChild) | undefined;
        } | undefined;
    } & {
        "v-slot:default"?: false | ((arg: {
            backgroundColorClasses: vue.Ref<string[]>;
            backgroundColorStyles: vue.Ref<vue.CSSProperties>;
        }) => vue.VNodeChild) | undefined;
        "v-slot:label"?: false | ((arg: {
            label: string | undefined;
            props: Record<string, unknown>;
        }) => vue.VNodeChild) | undefined;
        "v-slot:input"?: false | ((arg: SelectionControlSlot) => vue.VNodeChild) | undefined;
    }, {}, unknown, {}, {}, vue.ComponentOptionsMixin, vue.ComponentOptionsMixin, Record<string, any>, vue.VNodeProps & vue.AllowedComponentProps & vue.ComponentCustomProps & {
        style: vue.StyleValue;
        error: boolean;
        disabled: boolean | null;
        readonly: boolean | null;
        inline: boolean;
        multiple: boolean | null;
        density: Density;
        ripple: boolean | {
            class: string;
        } | undefined;
        falseIcon: NonNullable<IconValue>;
        trueIcon: NonNullable<IconValue>;
        valueComparator: typeof deepEqual;
    } & {
        class?: any;
        id?: string | undefined;
        label?: string | undefined;
        type?: string | undefined;
        value?: any;
        theme?: string | undefined;
        color?: string | undefined;
        name?: string | undefined;
        modelValue?: any;
        baseColor?: string | undefined;
        defaultsTarget?: string | undefined;
        trueValue?: any;
        falseValue?: any;
    } & {
        $children?: vue.VNodeChild | ((arg: {
            backgroundColorClasses: vue.Ref<string[]>;
            backgroundColorStyles: vue.Ref<vue.CSSProperties>;
        }) => vue.VNodeChild) | {
            default?: ((arg: {
                backgroundColorClasses: vue.Ref<string[]>;
                backgroundColorStyles: vue.Ref<vue.CSSProperties>;
            }) => vue.VNodeChild) | undefined;
            label?: ((arg: {
                label: string | undefined;
                props: Record<string, unknown>;
            }) => vue.VNodeChild) | undefined;
            input?: ((arg: SelectionControlSlot) => vue.VNodeChild) | undefined;
        };
        'v-slots'?: {
            default?: false | ((arg: {
                backgroundColorClasses: vue.Ref<string[]>;
                backgroundColorStyles: vue.Ref<vue.CSSProperties>;
            }) => vue.VNodeChild) | undefined;
            label?: false | ((arg: {
                label: string | undefined;
                props: Record<string, unknown>;
            }) => vue.VNodeChild) | undefined;
            input?: false | ((arg: SelectionControlSlot) => vue.VNodeChild) | undefined;
        } | undefined;
    } & {
        "v-slot:default"?: false | ((arg: {
            backgroundColorClasses: vue.Ref<string[]>;
            backgroundColorStyles: vue.Ref<vue.CSSProperties>;
        }) => vue.VNodeChild) | undefined;
        "v-slot:label"?: false | ((arg: {
            label: string | undefined;
            props: Record<string, unknown>;
        }) => vue.VNodeChild) | undefined;
        "v-slot:input"?: false | ((arg: SelectionControlSlot) => vue.VNodeChild) | undefined;
    }, {
        style: vue.StyleValue;
        error: boolean;
        disabled: boolean | null;
        readonly: boolean | null;
        inline: boolean;
        multiple: boolean | null;
        density: Density;
        ripple: boolean | {
            class: string;
        } | undefined;
        falseIcon: NonNullable<IconValue>;
        trueIcon: NonNullable<IconValue>;
        valueComparator: typeof deepEqual;
    }, true, {}, vue.SlotsType<Partial<{
        default: (arg: {
            backgroundColorClasses: vue.Ref<string[]>;
            backgroundColorStyles: vue.Ref<vue.CSSProperties>;
        }) => vue.VNode<vue.RendererNode, vue.RendererElement, {
            [key: string]: any;
        }>[];
        label: (arg: {
            label: string | undefined;
            props: Record<string, unknown>;
        }) => vue.VNode<vue.RendererNode, vue.RendererElement, {
            [key: string]: any;
        }>[];
        input: (arg: SelectionControlSlot) => vue.VNode<vue.RendererNode, vue.RendererElement, {
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
        error: boolean;
        disabled: boolean | null;
        readonly: boolean | null;
        inline: boolean;
        multiple: boolean | null;
        density: Density;
        ripple: boolean | {
            class: string;
        } | undefined;
        falseIcon: NonNullable<IconValue>;
        trueIcon: NonNullable<IconValue>;
        valueComparator: typeof deepEqual;
    } & {
        class?: any;
        id?: string | undefined;
        label?: string | undefined;
        type?: string | undefined;
        value?: any;
        theme?: string | undefined;
        color?: string | undefined;
        name?: string | undefined;
        modelValue?: any;
        baseColor?: string | undefined;
        defaultsTarget?: string | undefined;
        trueValue?: any;
        falseValue?: any;
    } & {
        $children?: vue.VNodeChild | ((arg: {
            backgroundColorClasses: vue.Ref<string[]>;
            backgroundColorStyles: vue.Ref<vue.CSSProperties>;
        }) => vue.VNodeChild) | {
            default?: ((arg: {
                backgroundColorClasses: vue.Ref<string[]>;
                backgroundColorStyles: vue.Ref<vue.CSSProperties>;
            }) => vue.VNodeChild) | undefined;
            label?: ((arg: {
                label: string | undefined;
                props: Record<string, unknown>;
            }) => vue.VNodeChild) | undefined;
            input?: ((arg: SelectionControlSlot) => vue.VNodeChild) | undefined;
        };
        'v-slots'?: {
            default?: false | ((arg: {
                backgroundColorClasses: vue.Ref<string[]>;
                backgroundColorStyles: vue.Ref<vue.CSSProperties>;
            }) => vue.VNodeChild) | undefined;
            label?: false | ((arg: {
                label: string | undefined;
                props: Record<string, unknown>;
            }) => vue.VNodeChild) | undefined;
            input?: false | ((arg: SelectionControlSlot) => vue.VNodeChild) | undefined;
        } | undefined;
    } & {
        "v-slot:default"?: false | ((arg: {
            backgroundColorClasses: vue.Ref<string[]>;
            backgroundColorStyles: vue.Ref<vue.CSSProperties>;
        }) => vue.VNodeChild) | undefined;
        "v-slot:label"?: false | ((arg: {
            label: string | undefined;
            props: Record<string, unknown>;
        }) => vue.VNodeChild) | undefined;
        "v-slot:input"?: false | ((arg: SelectionControlSlot) => vue.VNodeChild) | undefined;
    }, {}, {}, {}, {}, {
        style: vue.StyleValue;
        error: boolean;
        disabled: boolean | null;
        readonly: boolean | null;
        inline: boolean;
        multiple: boolean | null;
        density: Density;
        ripple: boolean | {
            class: string;
        } | undefined;
        falseIcon: NonNullable<IconValue>;
        trueIcon: NonNullable<IconValue>;
        valueComparator: typeof deepEqual;
    }>;
    __isFragment?: undefined;
    __isTeleport?: undefined;
    __isSuspense?: undefined;
} & vue.ComponentOptionsBase<{
    style: vue.StyleValue;
    error: boolean;
    disabled: boolean | null;
    readonly: boolean | null;
    inline: boolean;
    multiple: boolean | null;
    density: Density;
    ripple: boolean | {
        class: string;
    } | undefined;
    falseIcon: NonNullable<IconValue>;
    trueIcon: NonNullable<IconValue>;
    valueComparator: typeof deepEqual;
} & {
    class?: any;
    id?: string | undefined;
    label?: string | undefined;
    type?: string | undefined;
    value?: any;
    theme?: string | undefined;
    color?: string | undefined;
    name?: string | undefined;
    modelValue?: any;
    baseColor?: string | undefined;
    defaultsTarget?: string | undefined;
    trueValue?: any;
    falseValue?: any;
} & {
    $children?: vue.VNodeChild | ((arg: {
        backgroundColorClasses: vue.Ref<string[]>;
        backgroundColorStyles: vue.Ref<vue.CSSProperties>;
    }) => vue.VNodeChild) | {
        default?: ((arg: {
            backgroundColorClasses: vue.Ref<string[]>;
            backgroundColorStyles: vue.Ref<vue.CSSProperties>;
        }) => vue.VNodeChild) | undefined;
        label?: ((arg: {
            label: string | undefined;
            props: Record<string, unknown>;
        }) => vue.VNodeChild) | undefined;
        input?: ((arg: SelectionControlSlot) => vue.VNodeChild) | undefined;
    };
    'v-slots'?: {
        default?: false | ((arg: {
            backgroundColorClasses: vue.Ref<string[]>;
            backgroundColorStyles: vue.Ref<vue.CSSProperties>;
        }) => vue.VNodeChild) | undefined;
        label?: false | ((arg: {
            label: string | undefined;
            props: Record<string, unknown>;
        }) => vue.VNodeChild) | undefined;
        input?: false | ((arg: SelectionControlSlot) => vue.VNodeChild) | undefined;
    } | undefined;
} & {
    "v-slot:default"?: false | ((arg: {
        backgroundColorClasses: vue.Ref<string[]>;
        backgroundColorStyles: vue.Ref<vue.CSSProperties>;
    }) => vue.VNodeChild) | undefined;
    "v-slot:label"?: false | ((arg: {
        label: string | undefined;
        props: Record<string, unknown>;
    }) => vue.VNodeChild) | undefined;
    "v-slot:input"?: false | ((arg: SelectionControlSlot) => vue.VNodeChild) | undefined;
}, {}, unknown, {}, {}, vue.ComponentOptionsMixin, vue.ComponentOptionsMixin, Record<string, any>, string, {
    style: vue.StyleValue;
    error: boolean;
    disabled: boolean | null;
    readonly: boolean | null;
    inline: boolean;
    multiple: boolean | null;
    density: Density;
    ripple: boolean | {
        class: string;
    } | undefined;
    falseIcon: NonNullable<IconValue>;
    trueIcon: NonNullable<IconValue>;
    valueComparator: typeof deepEqual;
}, {}, string, vue.SlotsType<Partial<{
    default: (arg: {
        backgroundColorClasses: vue.Ref<string[]>;
        backgroundColorStyles: vue.Ref<vue.CSSProperties>;
    }) => vue.VNode<vue.RendererNode, vue.RendererElement, {
        [key: string]: any;
    }>[];
    label: (arg: {
        label: string | undefined;
        props: Record<string, unknown>;
    }) => vue.VNode<vue.RendererNode, vue.RendererElement, {
        [key: string]: any;
    }>[];
    input: (arg: SelectionControlSlot) => vue.VNode<vue.RendererNode, vue.RendererElement, {
        [key: string]: any;
    }>[];
}>>> & vue.VNodeProps & vue.AllowedComponentProps & vue.ComponentCustomProps & FilterPropsOptions<{
    theme: StringConstructor;
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
    color: StringConstructor;
    disabled: {
        type: vue.PropType<boolean | null>;
        default: null;
    };
    defaultsTarget: StringConstructor;
    error: BooleanConstructor;
    id: StringConstructor;
    inline: BooleanConstructor;
    falseIcon: {
        type: vue.PropType<NonNullable<IconValue>>;
        default: NonNullable<IconValue>;
    };
    trueIcon: {
        type: vue.PropType<NonNullable<IconValue>>;
        default: NonNullable<IconValue>;
    };
    ripple: {
        type: vue.PropType<boolean | {
            class: string;
        } | undefined>;
        default: boolean;
    };
    multiple: {
        type: vue.PropType<boolean | null>;
        default: null;
    };
    name: StringConstructor;
    readonly: {
        type: vue.PropType<boolean | null>;
        default: null;
    };
    modelValue: null;
    type: StringConstructor;
    valueComparator: {
        type: vue.PropType<typeof deepEqual>;
        default: typeof deepEqual;
    };
    label: StringConstructor;
    baseColor: StringConstructor;
    trueValue: null;
    falseValue: null;
    value: null;
}, vue.ExtractPropTypes<{
    theme: StringConstructor;
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
    color: StringConstructor;
    disabled: {
        type: vue.PropType<boolean | null>;
        default: null;
    };
    defaultsTarget: StringConstructor;
    error: BooleanConstructor;
    id: StringConstructor;
    inline: BooleanConstructor;
    falseIcon: {
        type: vue.PropType<NonNullable<IconValue>>;
        default: NonNullable<IconValue>;
    };
    trueIcon: {
        type: vue.PropType<NonNullable<IconValue>>;
        default: NonNullable<IconValue>;
    };
    ripple: {
        type: vue.PropType<boolean | {
            class: string;
        } | undefined>;
        default: boolean;
    };
    multiple: {
        type: vue.PropType<boolean | null>;
        default: null;
    };
    name: StringConstructor;
    readonly: {
        type: vue.PropType<boolean | null>;
        default: null;
    };
    modelValue: null;
    type: StringConstructor;
    valueComparator: {
        type: vue.PropType<typeof deepEqual>;
        default: typeof deepEqual;
    };
    label: StringConstructor;
    baseColor: StringConstructor;
    trueValue: null;
    falseValue: null;
    value: null;
}>>;
type VRadio = InstanceType<typeof VRadio>;

export { VRadio };
