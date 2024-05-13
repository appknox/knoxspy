import * as vue from 'vue';
import { ComponentPropsOptions, ExtractPropTypes, PropType } from 'vue';

declare const block: readonly ["top", "bottom"];
declare const inline: readonly ["start", "end", "left", "right"];
type Tblock = typeof block[number];
type Tinline = typeof inline[number];
type Anchor = Tblock | Tinline | 'center' | 'center center' | `${Tblock} ${Tinline | 'center'}` | `${Tinline} ${Tblock | 'center'}`;

interface FilterPropsOptions<PropsOptions extends Readonly<ComponentPropsOptions>, Props = ExtractPropTypes<PropsOptions>> {
    filterProps<T extends Partial<Props>, U extends Exclude<keyof Props, Exclude<keyof Props, keyof T>>>(props: T): Partial<Pick<T, U>>;
}

type Period$1 = 'am' | 'pm';
type AllowFunction = (val: number) => boolean;

declare const VTimePicker: {
    new (...args: any[]): vue.CreateComponentPublicInstance<{
        style: vue.StyleValue;
        title: string;
        disabled: boolean;
        tag: string;
        format: "ampm" | "24hr";
        readonly: boolean;
        tile: boolean;
        scrollable: boolean;
        hideHeader: boolean;
        useSeconds: boolean;
        ampmInTitle: boolean;
    } & {
        class?: any;
        width?: string | number | undefined;
        height?: string | number | undefined;
        theme?: string | undefined;
        color?: string | undefined;
        border?: string | number | boolean | undefined;
        position?: "fixed" | "absolute" | "relative" | "static" | "sticky" | undefined;
        modelValue?: any;
        rounded?: string | number | boolean | undefined;
        maxHeight?: string | number | undefined;
        maxWidth?: string | number | undefined;
        minHeight?: string | number | undefined;
        minWidth?: string | number | undefined;
        elevation?: string | number | undefined;
        location?: Anchor | undefined;
        max?: string | undefined;
        bgColor?: string | undefined;
        min?: string | undefined;
        allowedHours?: number[] | AllowFunction | undefined;
        allowedMinutes?: number[] | AllowFunction | undefined;
        allowedSeconds?: number[] | AllowFunction | undefined;
    } & {
        $children?: vue.VNodeChild | (() => vue.VNodeChild) | {
            default?: (() => vue.VNodeChild) | undefined;
            title?: (() => vue.VNodeChild) | undefined;
            actions?: (() => vue.VNodeChild) | undefined;
        };
        'v-slots'?: {
            default?: false | (() => vue.VNodeChild) | undefined;
            title?: false | (() => vue.VNodeChild) | undefined;
            actions?: false | (() => vue.VNodeChild) | undefined;
        } | undefined;
    } & {
        "v-slot:default"?: false | (() => vue.VNodeChild) | undefined;
        "v-slot:title"?: false | (() => vue.VNodeChild) | undefined;
        "v-slot:actions"?: false | (() => vue.VNodeChild) | undefined;
    } & {
        "onUpdate:modelValue"?: ((val: string) => any) | undefined;
        "onUpdate:period"?: ((val: Period$1) => any) | undefined;
        "onUpdate:hour"?: ((val: number) => any) | undefined;
        "onUpdate:minute"?: ((val: number) => any) | undefined;
        "onUpdate:second"?: ((val: number) => any) | undefined;
    }, void, unknown, {}, {}, vue.ComponentOptionsMixin, vue.ComponentOptionsMixin, {
        'update:hour': (val: number) => number;
        'update:minute': (val: number) => number;
        'update:period': (val: Period$1) => Period$1;
        'update:second': (val: number) => number;
        'update:modelValue': (val: string) => string;
    }, vue.VNodeProps & vue.AllowedComponentProps & vue.ComponentCustomProps & {
        style: vue.StyleValue;
        title: string;
        disabled: boolean;
        tag: string;
        format: "ampm" | "24hr";
        readonly: boolean;
        tile: boolean;
        scrollable: boolean;
        hideHeader: boolean;
        useSeconds: boolean;
        ampmInTitle: boolean;
    } & {
        class?: any;
        width?: string | number | undefined;
        height?: string | number | undefined;
        theme?: string | undefined;
        color?: string | undefined;
        border?: string | number | boolean | undefined;
        position?: "fixed" | "absolute" | "relative" | "static" | "sticky" | undefined;
        modelValue?: any;
        rounded?: string | number | boolean | undefined;
        maxHeight?: string | number | undefined;
        maxWidth?: string | number | undefined;
        minHeight?: string | number | undefined;
        minWidth?: string | number | undefined;
        elevation?: string | number | undefined;
        location?: Anchor | undefined;
        max?: string | undefined;
        bgColor?: string | undefined;
        min?: string | undefined;
        allowedHours?: number[] | AllowFunction | undefined;
        allowedMinutes?: number[] | AllowFunction | undefined;
        allowedSeconds?: number[] | AllowFunction | undefined;
    } & {
        $children?: vue.VNodeChild | (() => vue.VNodeChild) | {
            default?: (() => vue.VNodeChild) | undefined;
            title?: (() => vue.VNodeChild) | undefined;
            actions?: (() => vue.VNodeChild) | undefined;
        };
        'v-slots'?: {
            default?: false | (() => vue.VNodeChild) | undefined;
            title?: false | (() => vue.VNodeChild) | undefined;
            actions?: false | (() => vue.VNodeChild) | undefined;
        } | undefined;
    } & {
        "v-slot:default"?: false | (() => vue.VNodeChild) | undefined;
        "v-slot:title"?: false | (() => vue.VNodeChild) | undefined;
        "v-slot:actions"?: false | (() => vue.VNodeChild) | undefined;
    } & {
        "onUpdate:modelValue"?: ((val: string) => any) | undefined;
        "onUpdate:period"?: ((val: Period$1) => any) | undefined;
        "onUpdate:hour"?: ((val: number) => any) | undefined;
        "onUpdate:minute"?: ((val: number) => any) | undefined;
        "onUpdate:second"?: ((val: number) => any) | undefined;
    }, {
        style: vue.StyleValue;
        title: string;
        disabled: boolean;
        tag: string;
        format: "ampm" | "24hr";
        readonly: boolean;
        rounded: string | number | boolean;
        tile: boolean;
        scrollable: boolean;
        hideHeader: boolean;
        useSeconds: boolean;
        ampmInTitle: boolean;
    }, true, {}, vue.SlotsType<Partial<{
        default: () => vue.VNode<vue.RendererNode, vue.RendererElement, {
            [key: string]: any;
        }>[];
        title: () => vue.VNode<vue.RendererNode, vue.RendererElement, {
            [key: string]: any;
        }>[];
        actions: () => vue.VNode<vue.RendererNode, vue.RendererElement, {
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
        title: string;
        disabled: boolean;
        tag: string;
        format: "ampm" | "24hr";
        readonly: boolean;
        tile: boolean;
        scrollable: boolean;
        hideHeader: boolean;
        useSeconds: boolean;
        ampmInTitle: boolean;
    } & {
        class?: any;
        width?: string | number | undefined;
        height?: string | number | undefined;
        theme?: string | undefined;
        color?: string | undefined;
        border?: string | number | boolean | undefined;
        position?: "fixed" | "absolute" | "relative" | "static" | "sticky" | undefined;
        modelValue?: any;
        rounded?: string | number | boolean | undefined;
        maxHeight?: string | number | undefined;
        maxWidth?: string | number | undefined;
        minHeight?: string | number | undefined;
        minWidth?: string | number | undefined;
        elevation?: string | number | undefined;
        location?: Anchor | undefined;
        max?: string | undefined;
        bgColor?: string | undefined;
        min?: string | undefined;
        allowedHours?: number[] | AllowFunction | undefined;
        allowedMinutes?: number[] | AllowFunction | undefined;
        allowedSeconds?: number[] | AllowFunction | undefined;
    } & {
        $children?: vue.VNodeChild | (() => vue.VNodeChild) | {
            default?: (() => vue.VNodeChild) | undefined;
            title?: (() => vue.VNodeChild) | undefined;
            actions?: (() => vue.VNodeChild) | undefined;
        };
        'v-slots'?: {
            default?: false | (() => vue.VNodeChild) | undefined;
            title?: false | (() => vue.VNodeChild) | undefined;
            actions?: false | (() => vue.VNodeChild) | undefined;
        } | undefined;
    } & {
        "v-slot:default"?: false | (() => vue.VNodeChild) | undefined;
        "v-slot:title"?: false | (() => vue.VNodeChild) | undefined;
        "v-slot:actions"?: false | (() => vue.VNodeChild) | undefined;
    } & {
        "onUpdate:modelValue"?: ((val: string) => any) | undefined;
        "onUpdate:period"?: ((val: Period$1) => any) | undefined;
        "onUpdate:hour"?: ((val: number) => any) | undefined;
        "onUpdate:minute"?: ((val: number) => any) | undefined;
        "onUpdate:second"?: ((val: number) => any) | undefined;
    }, {}, {}, {}, {}, {
        style: vue.StyleValue;
        title: string;
        disabled: boolean;
        tag: string;
        format: "ampm" | "24hr";
        readonly: boolean;
        rounded: string | number | boolean;
        tile: boolean;
        scrollable: boolean;
        hideHeader: boolean;
        useSeconds: boolean;
        ampmInTitle: boolean;
    }>;
    __isFragment?: undefined;
    __isTeleport?: undefined;
    __isSuspense?: undefined;
} & vue.ComponentOptionsBase<{
    style: vue.StyleValue;
    title: string;
    disabled: boolean;
    tag: string;
    format: "ampm" | "24hr";
    readonly: boolean;
    tile: boolean;
    scrollable: boolean;
    hideHeader: boolean;
    useSeconds: boolean;
    ampmInTitle: boolean;
} & {
    class?: any;
    width?: string | number | undefined;
    height?: string | number | undefined;
    theme?: string | undefined;
    color?: string | undefined;
    border?: string | number | boolean | undefined;
    position?: "fixed" | "absolute" | "relative" | "static" | "sticky" | undefined;
    modelValue?: any;
    rounded?: string | number | boolean | undefined;
    maxHeight?: string | number | undefined;
    maxWidth?: string | number | undefined;
    minHeight?: string | number | undefined;
    minWidth?: string | number | undefined;
    elevation?: string | number | undefined;
    location?: Anchor | undefined;
    max?: string | undefined;
    bgColor?: string | undefined;
    min?: string | undefined;
    allowedHours?: number[] | AllowFunction | undefined;
    allowedMinutes?: number[] | AllowFunction | undefined;
    allowedSeconds?: number[] | AllowFunction | undefined;
} & {
    $children?: vue.VNodeChild | (() => vue.VNodeChild) | {
        default?: (() => vue.VNodeChild) | undefined;
        title?: (() => vue.VNodeChild) | undefined;
        actions?: (() => vue.VNodeChild) | undefined;
    };
    'v-slots'?: {
        default?: false | (() => vue.VNodeChild) | undefined;
        title?: false | (() => vue.VNodeChild) | undefined;
        actions?: false | (() => vue.VNodeChild) | undefined;
    } | undefined;
} & {
    "v-slot:default"?: false | (() => vue.VNodeChild) | undefined;
    "v-slot:title"?: false | (() => vue.VNodeChild) | undefined;
    "v-slot:actions"?: false | (() => vue.VNodeChild) | undefined;
} & {
    "onUpdate:modelValue"?: ((val: string) => any) | undefined;
    "onUpdate:period"?: ((val: Period$1) => any) | undefined;
    "onUpdate:hour"?: ((val: number) => any) | undefined;
    "onUpdate:minute"?: ((val: number) => any) | undefined;
    "onUpdate:second"?: ((val: number) => any) | undefined;
}, void, unknown, {}, {}, vue.ComponentOptionsMixin, vue.ComponentOptionsMixin, {
    'update:hour': (val: number) => number;
    'update:minute': (val: number) => number;
    'update:period': (val: Period$1) => Period$1;
    'update:second': (val: number) => number;
    'update:modelValue': (val: string) => string;
}, string, {
    style: vue.StyleValue;
    title: string;
    disabled: boolean;
    tag: string;
    format: "ampm" | "24hr";
    readonly: boolean;
    rounded: string | number | boolean;
    tile: boolean;
    scrollable: boolean;
    hideHeader: boolean;
    useSeconds: boolean;
    ampmInTitle: boolean;
}, {}, string, vue.SlotsType<Partial<{
    default: () => vue.VNode<vue.RendererNode, vue.RendererElement, {
        [key: string]: any;
    }>[];
    title: () => vue.VNode<vue.RendererNode, vue.RendererElement, {
        [key: string]: any;
    }>[];
    actions: () => vue.VNode<vue.RendererNode, vue.RendererElement, {
        [key: string]: any;
    }>[];
}>>> & vue.VNodeProps & vue.AllowedComponentProps & vue.ComponentCustomProps & FilterPropsOptions<{
    class: PropType<any>;
    style: {
        type: PropType<vue.StyleValue>;
        default: null;
    };
    title: {
        type: PropType<string>;
        default: string;
    };
    width: (StringConstructor | NumberConstructor)[];
    height: (StringConstructor | NumberConstructor)[];
    theme: StringConstructor;
    color: StringConstructor;
    tag: {
        type: StringConstructor;
        default: string;
    };
    border: (StringConstructor | NumberConstructor | BooleanConstructor)[];
    position: {
        type: PropType<"fixed" | "absolute" | "relative" | "static" | "sticky">;
        validator: (v: any) => boolean;
    };
    rounded: {
        type: (StringConstructor | NumberConstructor | BooleanConstructor)[];
        default: undefined;
    };
    maxHeight: (StringConstructor | NumberConstructor)[];
    maxWidth: (StringConstructor | NumberConstructor)[];
    minHeight: (StringConstructor | NumberConstructor)[];
    minWidth: (StringConstructor | NumberConstructor)[];
    tile: BooleanConstructor;
    elevation: {
        type: (StringConstructor | NumberConstructor)[];
        validator(v: any): boolean;
    };
    location: PropType<Anchor>;
    bgColor: StringConstructor;
    hideHeader: BooleanConstructor;
    allowedHours: PropType<number[] | AllowFunction>;
    allowedMinutes: PropType<number[] | AllowFunction>;
    allowedSeconds: PropType<number[] | AllowFunction>;
    ampmInTitle: BooleanConstructor;
    disabled: BooleanConstructor;
    format: {
        type: PropType<"ampm" | "24hr">;
        default: string;
    };
    max: StringConstructor;
    min: StringConstructor;
    modelValue: PropType<any>;
    readonly: BooleanConstructor;
    scrollable: BooleanConstructor;
    useSeconds: BooleanConstructor;
}, vue.ExtractPropTypes<{
    class: PropType<any>;
    style: {
        type: PropType<vue.StyleValue>;
        default: null;
    };
    title: {
        type: PropType<string>;
        default: string;
    };
    width: (StringConstructor | NumberConstructor)[];
    height: (StringConstructor | NumberConstructor)[];
    theme: StringConstructor;
    color: StringConstructor;
    tag: {
        type: StringConstructor;
        default: string;
    };
    border: (StringConstructor | NumberConstructor | BooleanConstructor)[];
    position: {
        type: PropType<"fixed" | "absolute" | "relative" | "static" | "sticky">;
        validator: (v: any) => boolean;
    };
    rounded: {
        type: (StringConstructor | NumberConstructor | BooleanConstructor)[];
        default: undefined;
    };
    maxHeight: (StringConstructor | NumberConstructor)[];
    maxWidth: (StringConstructor | NumberConstructor)[];
    minHeight: (StringConstructor | NumberConstructor)[];
    minWidth: (StringConstructor | NumberConstructor)[];
    tile: BooleanConstructor;
    elevation: {
        type: (StringConstructor | NumberConstructor)[];
        validator(v: any): boolean;
    };
    location: PropType<Anchor>;
    bgColor: StringConstructor;
    hideHeader: BooleanConstructor;
    allowedHours: PropType<number[] | AllowFunction>;
    allowedMinutes: PropType<number[] | AllowFunction>;
    allowedSeconds: PropType<number[] | AllowFunction>;
    ampmInTitle: BooleanConstructor;
    disabled: BooleanConstructor;
    format: {
        type: PropType<"ampm" | "24hr">;
        default: string;
    };
    max: StringConstructor;
    min: StringConstructor;
    modelValue: PropType<any>;
    readonly: BooleanConstructor;
    scrollable: BooleanConstructor;
    useSeconds: BooleanConstructor;
}>>;
type VTimePicker = InstanceType<typeof VTimePicker>;

declare const VTimePickerClock: {
    new (...args: any[]): vue.CreateComponentPublicInstance<{
        disabled: boolean;
        format: Function;
        readonly: boolean;
        double: boolean;
        rotate: number;
        max: number;
        min: number;
        step: number;
        scrollable: boolean;
        ampm: boolean;
    } & {
        color?: string | undefined;
        modelValue?: number | undefined;
        displayedValue?: any;
        allowedValues?: ((value: number) => boolean) | undefined;
    } & {
        $children?: vue.VNodeChild | {
            default?: (() => vue.VNodeChild) | undefined;
        } | (() => vue.VNodeChild);
        'v-slots'?: {
            default?: false | (() => vue.VNodeChild) | undefined;
        } | undefined;
    } & {
        "v-slot:default"?: false | (() => vue.VNodeChild) | undefined;
    } & {
        onChange?: ((val: number) => any) | undefined;
        onInput?: ((val: number) => any) | undefined;
    }, void, unknown, {}, {}, vue.ComponentOptionsMixin, vue.ComponentOptionsMixin, {
        change: (val: number) => number;
        input: (val: number) => number;
    }, vue.VNodeProps & vue.AllowedComponentProps & vue.ComponentCustomProps & {
        disabled: boolean;
        format: Function;
        readonly: boolean;
        double: boolean;
        rotate: number;
        max: number;
        min: number;
        step: number;
        scrollable: boolean;
        ampm: boolean;
    } & {
        color?: string | undefined;
        modelValue?: number | undefined;
        displayedValue?: any;
        allowedValues?: ((value: number) => boolean) | undefined;
    } & {
        $children?: vue.VNodeChild | {
            default?: (() => vue.VNodeChild) | undefined;
        } | (() => vue.VNodeChild);
        'v-slots'?: {
            default?: false | (() => vue.VNodeChild) | undefined;
        } | undefined;
    } & {
        "v-slot:default"?: false | (() => vue.VNodeChild) | undefined;
    } & {
        onChange?: ((val: number) => any) | undefined;
        onInput?: ((val: number) => any) | undefined;
    }, {
        disabled: boolean;
        format: Function;
        readonly: boolean;
        double: boolean;
        rotate: number;
        step: number;
        scrollable: boolean;
        ampm: boolean;
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
        disabled: boolean;
        format: Function;
        readonly: boolean;
        double: boolean;
        rotate: number;
        max: number;
        min: number;
        step: number;
        scrollable: boolean;
        ampm: boolean;
    } & {
        color?: string | undefined;
        modelValue?: number | undefined;
        displayedValue?: any;
        allowedValues?: ((value: number) => boolean) | undefined;
    } & {
        $children?: vue.VNodeChild | {
            default?: (() => vue.VNodeChild) | undefined;
        } | (() => vue.VNodeChild);
        'v-slots'?: {
            default?: false | (() => vue.VNodeChild) | undefined;
        } | undefined;
    } & {
        "v-slot:default"?: false | (() => vue.VNodeChild) | undefined;
    } & {
        onChange?: ((val: number) => any) | undefined;
        onInput?: ((val: number) => any) | undefined;
    }, {}, {}, {}, {}, {
        disabled: boolean;
        format: Function;
        readonly: boolean;
        double: boolean;
        rotate: number;
        step: number;
        scrollable: boolean;
        ampm: boolean;
    }>;
    __isFragment?: undefined;
    __isTeleport?: undefined;
    __isSuspense?: undefined;
} & vue.ComponentOptionsBase<{
    disabled: boolean;
    format: Function;
    readonly: boolean;
    double: boolean;
    rotate: number;
    max: number;
    min: number;
    step: number;
    scrollable: boolean;
    ampm: boolean;
} & {
    color?: string | undefined;
    modelValue?: number | undefined;
    displayedValue?: any;
    allowedValues?: ((value: number) => boolean) | undefined;
} & {
    $children?: vue.VNodeChild | {
        default?: (() => vue.VNodeChild) | undefined;
    } | (() => vue.VNodeChild);
    'v-slots'?: {
        default?: false | (() => vue.VNodeChild) | undefined;
    } | undefined;
} & {
    "v-slot:default"?: false | (() => vue.VNodeChild) | undefined;
} & {
    onChange?: ((val: number) => any) | undefined;
    onInput?: ((val: number) => any) | undefined;
}, void, unknown, {}, {}, vue.ComponentOptionsMixin, vue.ComponentOptionsMixin, {
    change: (val: number) => number;
    input: (val: number) => number;
}, string, {
    disabled: boolean;
    format: Function;
    readonly: boolean;
    double: boolean;
    rotate: number;
    step: number;
    scrollable: boolean;
    ampm: boolean;
}, {}, string, vue.SlotsType<Partial<{
    default: () => vue.VNode<vue.RendererNode, vue.RendererElement, {
        [key: string]: any;
    }>[];
}>>> & vue.VNodeProps & vue.AllowedComponentProps & vue.ComponentCustomProps & FilterPropsOptions<{
    allowedValues: PropType<(value: number) => boolean>;
    ampm: BooleanConstructor;
    color: StringConstructor;
    disabled: BooleanConstructor;
    displayedValue: null;
    double: BooleanConstructor;
    format: {
        type: FunctionConstructor;
        default: (val: string | number) => string | number;
    };
    max: {
        type: NumberConstructor;
        required: true;
    };
    min: {
        type: NumberConstructor;
        required: true;
    };
    scrollable: BooleanConstructor;
    readonly: BooleanConstructor;
    rotate: {
        type: NumberConstructor;
        default: number;
    };
    step: {
        type: NumberConstructor;
        default: number;
    };
    modelValue: {
        type: NumberConstructor;
    };
}, vue.ExtractPropTypes<{
    allowedValues: PropType<(value: number) => boolean>;
    ampm: BooleanConstructor;
    color: StringConstructor;
    disabled: BooleanConstructor;
    displayedValue: null;
    double: BooleanConstructor;
    format: {
        type: FunctionConstructor;
        default: (val: string | number) => string | number;
    };
    max: {
        type: NumberConstructor;
        required: true;
    };
    min: {
        type: NumberConstructor;
        required: true;
    };
    scrollable: BooleanConstructor;
    readonly: BooleanConstructor;
    rotate: {
        type: NumberConstructor;
        default: number;
    };
    step: {
        type: NumberConstructor;
        default: number;
    };
    modelValue: {
        type: NumberConstructor;
    };
}>>;
type VTimePickerClock = InstanceType<typeof VTimePickerClock>;

type Period = 'am' | 'pm';
declare const VTimePickerControls: {
    new (...args: any[]): vue.CreateComponentPublicInstance<{
        disabled: boolean;
        readonly: boolean;
        ampm: boolean;
        ampmReadonly: boolean;
        useSeconds: boolean;
    } & {
        value?: number | undefined;
        color?: string | undefined;
        hour?: number | undefined;
        minute?: number | undefined;
        second?: number | undefined;
        period?: string | undefined;
        selecting?: number | undefined;
    } & {
        $children?: vue.VNodeChild | {
            default?: (() => vue.VNodeChild) | undefined;
        } | (() => vue.VNodeChild);
        'v-slots'?: {
            default?: false | (() => vue.VNodeChild) | undefined;
        } | undefined;
    } & {
        "v-slot:default"?: false | (() => vue.VNodeChild) | undefined;
    } & {
        "onUpdate:period"?: ((data: Period) => any) | undefined;
        "onUpdate:selecting"?: ((data: 1 | 3 | 2) => any) | undefined;
    }, {}, unknown, {}, {}, vue.ComponentOptionsMixin, vue.ComponentOptionsMixin, {
        'update:period': (data: Period) => Period;
        'update:selecting': (data: 1 | 2 | 3) => 1 | 3 | 2;
    }, vue.VNodeProps & vue.AllowedComponentProps & vue.ComponentCustomProps & {
        disabled: boolean;
        readonly: boolean;
        ampm: boolean;
        ampmReadonly: boolean;
        useSeconds: boolean;
    } & {
        value?: number | undefined;
        color?: string | undefined;
        hour?: number | undefined;
        minute?: number | undefined;
        second?: number | undefined;
        period?: string | undefined;
        selecting?: number | undefined;
    } & {
        $children?: vue.VNodeChild | {
            default?: (() => vue.VNodeChild) | undefined;
        } | (() => vue.VNodeChild);
        'v-slots'?: {
            default?: false | (() => vue.VNodeChild) | undefined;
        } | undefined;
    } & {
        "v-slot:default"?: false | (() => vue.VNodeChild) | undefined;
    } & {
        "onUpdate:period"?: ((data: Period) => any) | undefined;
        "onUpdate:selecting"?: ((data: 1 | 3 | 2) => any) | undefined;
    }, {
        disabled: boolean;
        readonly: boolean;
        ampm: boolean;
        ampmReadonly: boolean;
        useSeconds: boolean;
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
        disabled: boolean;
        readonly: boolean;
        ampm: boolean;
        ampmReadonly: boolean;
        useSeconds: boolean;
    } & {
        value?: number | undefined;
        color?: string | undefined;
        hour?: number | undefined;
        minute?: number | undefined;
        second?: number | undefined;
        period?: string | undefined;
        selecting?: number | undefined;
    } & {
        $children?: vue.VNodeChild | {
            default?: (() => vue.VNodeChild) | undefined;
        } | (() => vue.VNodeChild);
        'v-slots'?: {
            default?: false | (() => vue.VNodeChild) | undefined;
        } | undefined;
    } & {
        "v-slot:default"?: false | (() => vue.VNodeChild) | undefined;
    } & {
        "onUpdate:period"?: ((data: Period) => any) | undefined;
        "onUpdate:selecting"?: ((data: 1 | 3 | 2) => any) | undefined;
    }, {}, {}, {}, {}, {
        disabled: boolean;
        readonly: boolean;
        ampm: boolean;
        ampmReadonly: boolean;
        useSeconds: boolean;
    }>;
    __isFragment?: undefined;
    __isTeleport?: undefined;
    __isSuspense?: undefined;
} & vue.ComponentOptionsBase<{
    disabled: boolean;
    readonly: boolean;
    ampm: boolean;
    ampmReadonly: boolean;
    useSeconds: boolean;
} & {
    value?: number | undefined;
    color?: string | undefined;
    hour?: number | undefined;
    minute?: number | undefined;
    second?: number | undefined;
    period?: string | undefined;
    selecting?: number | undefined;
} & {
    $children?: vue.VNodeChild | {
        default?: (() => vue.VNodeChild) | undefined;
    } | (() => vue.VNodeChild);
    'v-slots'?: {
        default?: false | (() => vue.VNodeChild) | undefined;
    } | undefined;
} & {
    "v-slot:default"?: false | (() => vue.VNodeChild) | undefined;
} & {
    "onUpdate:period"?: ((data: Period) => any) | undefined;
    "onUpdate:selecting"?: ((data: 1 | 3 | 2) => any) | undefined;
}, {}, unknown, {}, {}, vue.ComponentOptionsMixin, vue.ComponentOptionsMixin, {
    'update:period': (data: Period) => Period;
    'update:selecting': (data: 1 | 2 | 3) => 1 | 3 | 2;
}, string, {
    disabled: boolean;
    readonly: boolean;
    ampm: boolean;
    ampmReadonly: boolean;
    useSeconds: boolean;
}, {}, string, vue.SlotsType<Partial<{
    default: () => vue.VNode<vue.RendererNode, vue.RendererElement, {
        [key: string]: any;
    }>[];
}>>> & vue.VNodeProps & vue.AllowedComponentProps & vue.ComponentCustomProps & FilterPropsOptions<{
    ampm: BooleanConstructor;
    ampmReadonly: BooleanConstructor;
    color: StringConstructor;
    disabled: BooleanConstructor;
    hour: NumberConstructor;
    minute: NumberConstructor;
    second: NumberConstructor;
    period: StringConstructor;
    readonly: BooleanConstructor;
    useSeconds: BooleanConstructor;
    selecting: NumberConstructor;
    value: NumberConstructor;
}, vue.ExtractPropTypes<{
    ampm: BooleanConstructor;
    ampmReadonly: BooleanConstructor;
    color: StringConstructor;
    disabled: BooleanConstructor;
    hour: NumberConstructor;
    minute: NumberConstructor;
    second: NumberConstructor;
    period: StringConstructor;
    readonly: BooleanConstructor;
    useSeconds: BooleanConstructor;
    selecting: NumberConstructor;
    value: NumberConstructor;
}>>;
type VTimePickerControls = InstanceType<typeof VTimePickerControls>;

export { VTimePicker, VTimePickerClock, VTimePickerControls };
