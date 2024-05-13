import * as vue from 'vue';
import { ComponentPropsOptions, ExtractPropTypes, PropType } from 'vue';

interface FilterPropsOptions<PropsOptions extends Readonly<ComponentPropsOptions>, Props = ExtractPropTypes<PropsOptions>> {
    filterProps<T extends Partial<Props>, U extends Exclude<keyof Props, Exclude<keyof Props, keyof T>>>(props: T): Partial<Pick<T, U>>;
}

declare const VProgressCircular: {
    new (...args: any[]): vue.CreateComponentPublicInstance<{
        style: vue.StyleValue;
        size: string | number;
        width: string | number;
        tag: string;
        modelValue: string | number;
        rotate: string | number;
    } & {
        class?: any;
        theme?: string | undefined;
        color?: string | undefined;
        bgColor?: string | undefined;
        indeterminate?: boolean | "disable-shrink" | undefined;
    } & {
        $children?: vue.VNodeChild | {
            default?: ((arg: {
                value: number;
            }) => vue.VNodeChild) | undefined;
        } | ((arg: {
            value: number;
        }) => vue.VNodeChild);
        'v-slots'?: {
            default?: false | ((arg: {
                value: number;
            }) => vue.VNodeChild) | undefined;
        } | undefined;
    } & {
        "v-slot:default"?: false | ((arg: {
            value: number;
        }) => vue.VNodeChild) | undefined;
    }, {}, unknown, {}, {}, vue.ComponentOptionsMixin, vue.ComponentOptionsMixin, Record<string, any>, vue.VNodeProps & vue.AllowedComponentProps & vue.ComponentCustomProps & {
        style: vue.StyleValue;
        size: string | number;
        width: string | number;
        tag: string;
        modelValue: string | number;
        rotate: string | number;
    } & {
        class?: any;
        theme?: string | undefined;
        color?: string | undefined;
        bgColor?: string | undefined;
        indeterminate?: boolean | "disable-shrink" | undefined;
    } & {
        $children?: vue.VNodeChild | {
            default?: ((arg: {
                value: number;
            }) => vue.VNodeChild) | undefined;
        } | ((arg: {
            value: number;
        }) => vue.VNodeChild);
        'v-slots'?: {
            default?: false | ((arg: {
                value: number;
            }) => vue.VNodeChild) | undefined;
        } | undefined;
    } & {
        "v-slot:default"?: false | ((arg: {
            value: number;
        }) => vue.VNodeChild) | undefined;
    }, {
        style: vue.StyleValue;
        size: string | number;
        width: string | number;
        tag: string;
        modelValue: string | number;
        rotate: string | number;
    }, true, {}, vue.SlotsType<Partial<{
        default: (arg: {
            value: number;
        }) => vue.VNode<vue.RendererNode, vue.RendererElement, {
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
        size: string | number;
        width: string | number;
        tag: string;
        modelValue: string | number;
        rotate: string | number;
    } & {
        class?: any;
        theme?: string | undefined;
        color?: string | undefined;
        bgColor?: string | undefined;
        indeterminate?: boolean | "disable-shrink" | undefined;
    } & {
        $children?: vue.VNodeChild | {
            default?: ((arg: {
                value: number;
            }) => vue.VNodeChild) | undefined;
        } | ((arg: {
            value: number;
        }) => vue.VNodeChild);
        'v-slots'?: {
            default?: false | ((arg: {
                value: number;
            }) => vue.VNodeChild) | undefined;
        } | undefined;
    } & {
        "v-slot:default"?: false | ((arg: {
            value: number;
        }) => vue.VNodeChild) | undefined;
    }, {}, {}, {}, {}, {
        style: vue.StyleValue;
        size: string | number;
        width: string | number;
        tag: string;
        modelValue: string | number;
        rotate: string | number;
    }>;
    __isFragment?: undefined;
    __isTeleport?: undefined;
    __isSuspense?: undefined;
} & vue.ComponentOptionsBase<{
    style: vue.StyleValue;
    size: string | number;
    width: string | number;
    tag: string;
    modelValue: string | number;
    rotate: string | number;
} & {
    class?: any;
    theme?: string | undefined;
    color?: string | undefined;
    bgColor?: string | undefined;
    indeterminate?: boolean | "disable-shrink" | undefined;
} & {
    $children?: vue.VNodeChild | {
        default?: ((arg: {
            value: number;
        }) => vue.VNodeChild) | undefined;
    } | ((arg: {
        value: number;
    }) => vue.VNodeChild);
    'v-slots'?: {
        default?: false | ((arg: {
            value: number;
        }) => vue.VNodeChild) | undefined;
    } | undefined;
} & {
    "v-slot:default"?: false | ((arg: {
        value: number;
    }) => vue.VNodeChild) | undefined;
}, {}, unknown, {}, {}, vue.ComponentOptionsMixin, vue.ComponentOptionsMixin, Record<string, any>, string, {
    style: vue.StyleValue;
    size: string | number;
    width: string | number;
    tag: string;
    modelValue: string | number;
    rotate: string | number;
}, {}, string, vue.SlotsType<Partial<{
    default: (arg: {
        value: number;
    }) => vue.VNode<vue.RendererNode, vue.RendererElement, {
        [key: string]: any;
    }>[];
}>>> & vue.VNodeProps & vue.AllowedComponentProps & vue.ComponentCustomProps & FilterPropsOptions<{
    theme: StringConstructor;
    tag: Omit<{
        type: StringConstructor;
        default: string;
    }, "default" | "type"> & {
        type: PropType<string>;
        default: string;
    };
    size: {
        type: (StringConstructor | NumberConstructor)[];
        default: string;
    };
    class: PropType<any>;
    style: {
        type: PropType<vue.StyleValue>;
        default: null;
    };
    bgColor: StringConstructor;
    color: StringConstructor;
    indeterminate: PropType<boolean | "disable-shrink">;
    modelValue: {
        type: (StringConstructor | NumberConstructor)[];
        default: number;
    };
    rotate: {
        type: (StringConstructor | NumberConstructor)[];
        default: number;
    };
    width: {
        type: (StringConstructor | NumberConstructor)[];
        default: number;
    };
}, vue.ExtractPropTypes<{
    theme: StringConstructor;
    tag: Omit<{
        type: StringConstructor;
        default: string;
    }, "default" | "type"> & {
        type: PropType<string>;
        default: string;
    };
    size: {
        type: (StringConstructor | NumberConstructor)[];
        default: string;
    };
    class: PropType<any>;
    style: {
        type: PropType<vue.StyleValue>;
        default: null;
    };
    bgColor: StringConstructor;
    color: StringConstructor;
    indeterminate: PropType<boolean | "disable-shrink">;
    modelValue: {
        type: (StringConstructor | NumberConstructor)[];
        default: number;
    };
    rotate: {
        type: (StringConstructor | NumberConstructor)[];
        default: number;
    };
    width: {
        type: (StringConstructor | NumberConstructor)[];
        default: number;
    };
}>>;
type VProgressCircular = InstanceType<typeof VProgressCircular>;

export { VProgressCircular };
