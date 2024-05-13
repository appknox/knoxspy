import * as vue from 'vue';
import { ComponentPropsOptions, ExtractPropTypes, PropType } from 'vue';

interface FilterPropsOptions<PropsOptions extends Readonly<ComponentPropsOptions>, Props = ExtractPropTypes<PropsOptions>> {
    filterProps<T extends Partial<Props>, U extends Exclude<keyof Props, Exclude<keyof Props, keyof T>>>(props: T): Partial<Pick<T, U>>;
}

declare const VOtpInput: {
    new (...args: any[]): vue.CreateComponentPublicInstance<{
        length: string | number;
        style: vue.StyleValue;
        label: string;
        type: "number" | "text" | "password";
        error: boolean;
        disabled: boolean;
        focused: boolean;
        variant: NonNullable<"underlined" | "filled" | "outlined" | "plain" | "solo" | "solo-inverted" | "solo-filled">;
        autofocus: boolean;
        focusAll: boolean;
    } & {
        class?: any;
        width?: string | number | undefined;
        height?: string | number | undefined;
        theme?: string | undefined;
        color?: string | undefined;
        loading?: string | boolean | undefined;
        divider?: string | undefined;
        placeholder?: string | undefined;
        'onUpdate:focused'?: ((args_0: boolean) => void) | undefined;
        modelValue?: string | number | undefined;
        rounded?: string | number | boolean | undefined;
        maxHeight?: string | number | undefined;
        maxWidth?: string | number | undefined;
        minHeight?: string | number | undefined;
        minWidth?: string | number | undefined;
        baseColor?: string | undefined;
        bgColor?: string | undefined;
    } & {
        $children?: vue.VNodeChild | (() => vue.VNodeChild) | {
            default?: (() => vue.VNodeChild) | undefined;
            loader?: (() => vue.VNodeChild) | undefined;
        };
        'v-slots'?: {
            default?: false | (() => vue.VNodeChild) | undefined;
            loader?: false | (() => vue.VNodeChild) | undefined;
        } | undefined;
    } & {
        "v-slot:default"?: false | (() => vue.VNodeChild) | undefined;
        "v-slot:loader"?: false | (() => vue.VNodeChild) | undefined;
    } & {
        "onUpdate:focused"?: ((val: boolean) => any) | undefined;
        "onUpdate:modelValue"?: ((val: string) => any) | undefined;
        onFinish?: ((val: string) => any) | undefined;
    }, {
        blur: () => void;
        focus: () => void;
        reset: () => void;
        isFocused: vue.Ref<boolean> & {
            readonly externalValue: boolean;
        };
    }, unknown, {}, {}, vue.ComponentOptionsMixin, vue.ComponentOptionsMixin, {
        finish: (val: string) => true;
        'update:focused': (val: boolean) => true;
        'update:modelValue': (val: string) => true;
    }, vue.VNodeProps & vue.AllowedComponentProps & vue.ComponentCustomProps & {
        length: string | number;
        style: vue.StyleValue;
        label: string;
        type: "number" | "text" | "password";
        error: boolean;
        disabled: boolean;
        focused: boolean;
        variant: NonNullable<"underlined" | "filled" | "outlined" | "plain" | "solo" | "solo-inverted" | "solo-filled">;
        autofocus: boolean;
        focusAll: boolean;
    } & {
        class?: any;
        width?: string | number | undefined;
        height?: string | number | undefined;
        theme?: string | undefined;
        color?: string | undefined;
        loading?: string | boolean | undefined;
        divider?: string | undefined;
        placeholder?: string | undefined;
        'onUpdate:focused'?: ((args_0: boolean) => void) | undefined;
        modelValue?: string | number | undefined;
        rounded?: string | number | boolean | undefined;
        maxHeight?: string | number | undefined;
        maxWidth?: string | number | undefined;
        minHeight?: string | number | undefined;
        minWidth?: string | number | undefined;
        baseColor?: string | undefined;
        bgColor?: string | undefined;
    } & {
        $children?: vue.VNodeChild | (() => vue.VNodeChild) | {
            default?: (() => vue.VNodeChild) | undefined;
            loader?: (() => vue.VNodeChild) | undefined;
        };
        'v-slots'?: {
            default?: false | (() => vue.VNodeChild) | undefined;
            loader?: false | (() => vue.VNodeChild) | undefined;
        } | undefined;
    } & {
        "v-slot:default"?: false | (() => vue.VNodeChild) | undefined;
        "v-slot:loader"?: false | (() => vue.VNodeChild) | undefined;
    } & {
        "onUpdate:focused"?: ((val: boolean) => any) | undefined;
        "onUpdate:modelValue"?: ((val: string) => any) | undefined;
        onFinish?: ((val: string) => any) | undefined;
    }, {
        length: string | number;
        style: vue.StyleValue;
        label: string;
        type: "number" | "text" | "password";
        error: boolean;
        disabled: boolean;
        focused: boolean;
        modelValue: string | number;
        rounded: string | number | boolean;
        variant: NonNullable<"underlined" | "filled" | "outlined" | "plain" | "solo" | "solo-inverted" | "solo-filled">;
        autofocus: boolean;
        focusAll: boolean;
    }, true, {}, vue.SlotsType<Partial<{
        default: () => vue.VNode<vue.RendererNode, vue.RendererElement, {
            [key: string]: any;
        }>[];
        loader: () => vue.VNode<vue.RendererNode, vue.RendererElement, {
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
        length: string | number;
        style: vue.StyleValue;
        label: string;
        type: "number" | "text" | "password";
        error: boolean;
        disabled: boolean;
        focused: boolean;
        variant: NonNullable<"underlined" | "filled" | "outlined" | "plain" | "solo" | "solo-inverted" | "solo-filled">;
        autofocus: boolean;
        focusAll: boolean;
    } & {
        class?: any;
        width?: string | number | undefined;
        height?: string | number | undefined;
        theme?: string | undefined;
        color?: string | undefined;
        loading?: string | boolean | undefined;
        divider?: string | undefined;
        placeholder?: string | undefined;
        'onUpdate:focused'?: ((args_0: boolean) => void) | undefined;
        modelValue?: string | number | undefined;
        rounded?: string | number | boolean | undefined;
        maxHeight?: string | number | undefined;
        maxWidth?: string | number | undefined;
        minHeight?: string | number | undefined;
        minWidth?: string | number | undefined;
        baseColor?: string | undefined;
        bgColor?: string | undefined;
    } & {
        $children?: vue.VNodeChild | (() => vue.VNodeChild) | {
            default?: (() => vue.VNodeChild) | undefined;
            loader?: (() => vue.VNodeChild) | undefined;
        };
        'v-slots'?: {
            default?: false | (() => vue.VNodeChild) | undefined;
            loader?: false | (() => vue.VNodeChild) | undefined;
        } | undefined;
    } & {
        "v-slot:default"?: false | (() => vue.VNodeChild) | undefined;
        "v-slot:loader"?: false | (() => vue.VNodeChild) | undefined;
    } & {
        "onUpdate:focused"?: ((val: boolean) => any) | undefined;
        "onUpdate:modelValue"?: ((val: string) => any) | undefined;
        onFinish?: ((val: string) => any) | undefined;
    }, {
        blur: () => void;
        focus: () => void;
        reset: () => void;
        isFocused: vue.Ref<boolean> & {
            readonly externalValue: boolean;
        };
    }, {}, {}, {}, {
        length: string | number;
        style: vue.StyleValue;
        label: string;
        type: "number" | "text" | "password";
        error: boolean;
        disabled: boolean;
        focused: boolean;
        modelValue: string | number;
        rounded: string | number | boolean;
        variant: NonNullable<"underlined" | "filled" | "outlined" | "plain" | "solo" | "solo-inverted" | "solo-filled">;
        autofocus: boolean;
        focusAll: boolean;
    }>;
    __isFragment?: undefined;
    __isTeleport?: undefined;
    __isSuspense?: undefined;
} & vue.ComponentOptionsBase<{
    length: string | number;
    style: vue.StyleValue;
    label: string;
    type: "number" | "text" | "password";
    error: boolean;
    disabled: boolean;
    focused: boolean;
    variant: NonNullable<"underlined" | "filled" | "outlined" | "plain" | "solo" | "solo-inverted" | "solo-filled">;
    autofocus: boolean;
    focusAll: boolean;
} & {
    class?: any;
    width?: string | number | undefined;
    height?: string | number | undefined;
    theme?: string | undefined;
    color?: string | undefined;
    loading?: string | boolean | undefined;
    divider?: string | undefined;
    placeholder?: string | undefined;
    'onUpdate:focused'?: ((args_0: boolean) => void) | undefined;
    modelValue?: string | number | undefined;
    rounded?: string | number | boolean | undefined;
    maxHeight?: string | number | undefined;
    maxWidth?: string | number | undefined;
    minHeight?: string | number | undefined;
    minWidth?: string | number | undefined;
    baseColor?: string | undefined;
    bgColor?: string | undefined;
} & {
    $children?: vue.VNodeChild | (() => vue.VNodeChild) | {
        default?: (() => vue.VNodeChild) | undefined;
        loader?: (() => vue.VNodeChild) | undefined;
    };
    'v-slots'?: {
        default?: false | (() => vue.VNodeChild) | undefined;
        loader?: false | (() => vue.VNodeChild) | undefined;
    } | undefined;
} & {
    "v-slot:default"?: false | (() => vue.VNodeChild) | undefined;
    "v-slot:loader"?: false | (() => vue.VNodeChild) | undefined;
} & {
    "onUpdate:focused"?: ((val: boolean) => any) | undefined;
    "onUpdate:modelValue"?: ((val: string) => any) | undefined;
    onFinish?: ((val: string) => any) | undefined;
}, {
    blur: () => void;
    focus: () => void;
    reset: () => void;
    isFocused: vue.Ref<boolean> & {
        readonly externalValue: boolean;
    };
}, unknown, {}, {}, vue.ComponentOptionsMixin, vue.ComponentOptionsMixin, {
    finish: (val: string) => true;
    'update:focused': (val: boolean) => true;
    'update:modelValue': (val: string) => true;
}, string, {
    length: string | number;
    style: vue.StyleValue;
    label: string;
    type: "number" | "text" | "password";
    error: boolean;
    disabled: boolean;
    focused: boolean;
    modelValue: string | number;
    rounded: string | number | boolean;
    variant: NonNullable<"underlined" | "filled" | "outlined" | "plain" | "solo" | "solo-inverted" | "solo-filled">;
    autofocus: boolean;
    focusAll: boolean;
}, {}, string, vue.SlotsType<Partial<{
    default: () => vue.VNode<vue.RendererNode, vue.RendererElement, {
        [key: string]: any;
    }>[];
    loader: () => vue.VNode<vue.RendererNode, vue.RendererElement, {
        [key: string]: any;
    }>[];
}>>> & vue.VNodeProps & vue.AllowedComponentProps & vue.ComponentCustomProps & FilterPropsOptions<{
    class: PropType<any>;
    style: {
        type: PropType<vue.StyleValue>;
        default: null;
    };
    error: BooleanConstructor;
    theme: StringConstructor;
    color: StringConstructor;
    disabled: {
        type: BooleanConstructor;
        default: null;
    };
    loading: (StringConstructor | BooleanConstructor)[];
    rounded: {
        type: (StringConstructor | NumberConstructor | BooleanConstructor)[];
        default: undefined;
    };
    variant: Omit<{
        type: PropType<"underlined" | "filled" | "outlined" | "plain" | "solo" | "solo-inverted" | "solo-filled">;
        default: string;
        validator: (v: any) => boolean;
    }, "default" | "type"> & {
        type: PropType<NonNullable<"underlined" | "filled" | "outlined" | "plain" | "solo" | "solo-inverted" | "solo-filled">>;
        default: NonNullable<"underlined" | "filled" | "outlined" | "plain" | "solo" | "solo-inverted" | "solo-filled">;
    };
    baseColor: StringConstructor;
    bgColor: StringConstructor;
    focused: BooleanConstructor;
    'onUpdate:focused': PropType<(args_0: boolean) => void>;
    height: (StringConstructor | NumberConstructor)[];
    maxHeight: (StringConstructor | NumberConstructor)[];
    maxWidth: (StringConstructor | NumberConstructor)[];
    minHeight: (StringConstructor | NumberConstructor)[];
    minWidth: (StringConstructor | NumberConstructor)[];
    width: (StringConstructor | NumberConstructor)[];
    autofocus: BooleanConstructor;
    divider: StringConstructor;
    focusAll: BooleanConstructor;
    label: {
        type: StringConstructor;
        default: string;
    };
    length: {
        type: (StringConstructor | NumberConstructor)[];
        default: number;
    };
    modelValue: {
        type: (StringConstructor | NumberConstructor)[];
        default: undefined;
    };
    placeholder: StringConstructor;
    type: {
        type: PropType<"number" | "text" | "password">;
        default: string;
    };
}, vue.ExtractPropTypes<{
    class: PropType<any>;
    style: {
        type: PropType<vue.StyleValue>;
        default: null;
    };
    error: BooleanConstructor;
    theme: StringConstructor;
    color: StringConstructor;
    disabled: {
        type: BooleanConstructor;
        default: null;
    };
    loading: (StringConstructor | BooleanConstructor)[];
    rounded: {
        type: (StringConstructor | NumberConstructor | BooleanConstructor)[];
        default: undefined;
    };
    variant: Omit<{
        type: PropType<"underlined" | "filled" | "outlined" | "plain" | "solo" | "solo-inverted" | "solo-filled">;
        default: string;
        validator: (v: any) => boolean;
    }, "default" | "type"> & {
        type: PropType<NonNullable<"underlined" | "filled" | "outlined" | "plain" | "solo" | "solo-inverted" | "solo-filled">>;
        default: NonNullable<"underlined" | "filled" | "outlined" | "plain" | "solo" | "solo-inverted" | "solo-filled">;
    };
    baseColor: StringConstructor;
    bgColor: StringConstructor;
    focused: BooleanConstructor;
    'onUpdate:focused': PropType<(args_0: boolean) => void>;
    height: (StringConstructor | NumberConstructor)[];
    maxHeight: (StringConstructor | NumberConstructor)[];
    maxWidth: (StringConstructor | NumberConstructor)[];
    minHeight: (StringConstructor | NumberConstructor)[];
    minWidth: (StringConstructor | NumberConstructor)[];
    width: (StringConstructor | NumberConstructor)[];
    autofocus: BooleanConstructor;
    divider: StringConstructor;
    focusAll: BooleanConstructor;
    label: {
        type: StringConstructor;
        default: string;
    };
    length: {
        type: (StringConstructor | NumberConstructor)[];
        default: number;
    };
    modelValue: {
        type: (StringConstructor | NumberConstructor)[];
        default: undefined;
    };
    placeholder: StringConstructor;
    type: {
        type: PropType<"number" | "text" | "password">;
        default: string;
    };
}>>;
type VOtpInput = InstanceType<typeof VOtpInput>;

export { VOtpInput };
