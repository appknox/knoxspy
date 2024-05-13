import * as vue from 'vue';
import { ComponentPropsOptions, ExtractPropTypes, JSXComponent, PropType } from 'vue';

declare const block: readonly ["top", "bottom"];
declare const inline: readonly ["start", "end", "left", "right"];
type Tblock = typeof block[number];
type Tinline = typeof inline[number];
type Anchor = Tblock | Tinline | 'center' | 'center center' | `${Tblock} ${Tinline | 'center'}` | `${Tinline} ${Tblock | 'center'}`;

interface FilterPropsOptions<PropsOptions extends Readonly<ComponentPropsOptions>, Props = ExtractPropTypes<PropsOptions>> {
    filterProps<T extends Partial<Props>, U extends Exclude<keyof Props, Exclude<keyof Props, keyof T>>>(props: T): Partial<Pick<T, U>>;
}

type IconValue = string | (string | [path: string, opacity: number])[] | JSXComponent;
declare const IconValue: PropType<IconValue>;

declare const VBadge: {
    new (...args: any[]): vue.CreateComponentPublicInstance<{
        style: vue.StyleValue;
        label: string;
        tag: string;
        transition: NonNullable<string | boolean | (vue.TransitionProps & {
            component?: vue.Component | undefined;
        })>;
        modelValue: boolean;
        inline: boolean;
        dot: boolean;
        tile: boolean;
        floating: boolean;
        location: NonNullable<Anchor>;
        bordered: boolean;
    } & {
        class?: any;
        theme?: string | undefined;
        color?: string | undefined;
        content?: string | number | undefined;
        icon?: IconValue | undefined;
        rounded?: string | number | boolean | undefined;
        max?: string | number | undefined;
        offsetX?: string | number | undefined;
        offsetY?: string | number | undefined;
        textColor?: string | undefined;
    } & {
        $children?: vue.VNodeChild | (() => vue.VNodeChild) | {
            default?: (() => vue.VNodeChild) | undefined;
            badge?: (() => vue.VNodeChild) | undefined;
        };
        'v-slots'?: {
            default?: false | (() => vue.VNodeChild) | undefined;
            badge?: false | (() => vue.VNodeChild) | undefined;
        } | undefined;
    } & {
        "v-slot:default"?: false | (() => vue.VNodeChild) | undefined;
        "v-slot:badge"?: false | (() => vue.VNodeChild) | undefined;
    }, {}, unknown, {}, {}, vue.ComponentOptionsMixin, vue.ComponentOptionsMixin, Record<string, any>, vue.VNodeProps & vue.AllowedComponentProps & vue.ComponentCustomProps & {
        style: vue.StyleValue;
        label: string;
        tag: string;
        transition: NonNullable<string | boolean | (vue.TransitionProps & {
            component?: vue.Component | undefined;
        })>;
        modelValue: boolean;
        inline: boolean;
        dot: boolean;
        tile: boolean;
        floating: boolean;
        location: NonNullable<Anchor>;
        bordered: boolean;
    } & {
        class?: any;
        theme?: string | undefined;
        color?: string | undefined;
        content?: string | number | undefined;
        icon?: IconValue | undefined;
        rounded?: string | number | boolean | undefined;
        max?: string | number | undefined;
        offsetX?: string | number | undefined;
        offsetY?: string | number | undefined;
        textColor?: string | undefined;
    } & {
        $children?: vue.VNodeChild | (() => vue.VNodeChild) | {
            default?: (() => vue.VNodeChild) | undefined;
            badge?: (() => vue.VNodeChild) | undefined;
        };
        'v-slots'?: {
            default?: false | (() => vue.VNodeChild) | undefined;
            badge?: false | (() => vue.VNodeChild) | undefined;
        } | undefined;
    } & {
        "v-slot:default"?: false | (() => vue.VNodeChild) | undefined;
        "v-slot:badge"?: false | (() => vue.VNodeChild) | undefined;
    }, {
        style: vue.StyleValue;
        label: string;
        tag: string;
        transition: NonNullable<string | boolean | (vue.TransitionProps & {
            component?: vue.Component | undefined;
        })>;
        modelValue: boolean;
        rounded: string | number | boolean;
        inline: boolean;
        dot: boolean;
        tile: boolean;
        floating: boolean;
        location: NonNullable<Anchor>;
        bordered: boolean;
    }, true, {}, vue.SlotsType<Partial<{
        default: () => vue.VNode<vue.RendererNode, vue.RendererElement, {
            [key: string]: any;
        }>[];
        badge: () => vue.VNode<vue.RendererNode, vue.RendererElement, {
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
        label: string;
        tag: string;
        transition: NonNullable<string | boolean | (vue.TransitionProps & {
            component?: vue.Component | undefined;
        })>;
        modelValue: boolean;
        inline: boolean;
        dot: boolean;
        tile: boolean;
        floating: boolean;
        location: NonNullable<Anchor>;
        bordered: boolean;
    } & {
        class?: any;
        theme?: string | undefined;
        color?: string | undefined;
        content?: string | number | undefined;
        icon?: IconValue | undefined;
        rounded?: string | number | boolean | undefined;
        max?: string | number | undefined;
        offsetX?: string | number | undefined;
        offsetY?: string | number | undefined;
        textColor?: string | undefined;
    } & {
        $children?: vue.VNodeChild | (() => vue.VNodeChild) | {
            default?: (() => vue.VNodeChild) | undefined;
            badge?: (() => vue.VNodeChild) | undefined;
        };
        'v-slots'?: {
            default?: false | (() => vue.VNodeChild) | undefined;
            badge?: false | (() => vue.VNodeChild) | undefined;
        } | undefined;
    } & {
        "v-slot:default"?: false | (() => vue.VNodeChild) | undefined;
        "v-slot:badge"?: false | (() => vue.VNodeChild) | undefined;
    }, {}, {}, {}, {}, {
        style: vue.StyleValue;
        label: string;
        tag: string;
        transition: NonNullable<string | boolean | (vue.TransitionProps & {
            component?: vue.Component | undefined;
        })>;
        modelValue: boolean;
        rounded: string | number | boolean;
        inline: boolean;
        dot: boolean;
        tile: boolean;
        floating: boolean;
        location: NonNullable<Anchor>;
        bordered: boolean;
    }>;
    __isFragment?: undefined;
    __isTeleport?: undefined;
    __isSuspense?: undefined;
} & vue.ComponentOptionsBase<{
    style: vue.StyleValue;
    label: string;
    tag: string;
    transition: NonNullable<string | boolean | (vue.TransitionProps & {
        component?: vue.Component | undefined;
    })>;
    modelValue: boolean;
    inline: boolean;
    dot: boolean;
    tile: boolean;
    floating: boolean;
    location: NonNullable<Anchor>;
    bordered: boolean;
} & {
    class?: any;
    theme?: string | undefined;
    color?: string | undefined;
    content?: string | number | undefined;
    icon?: IconValue | undefined;
    rounded?: string | number | boolean | undefined;
    max?: string | number | undefined;
    offsetX?: string | number | undefined;
    offsetY?: string | number | undefined;
    textColor?: string | undefined;
} & {
    $children?: vue.VNodeChild | (() => vue.VNodeChild) | {
        default?: (() => vue.VNodeChild) | undefined;
        badge?: (() => vue.VNodeChild) | undefined;
    };
    'v-slots'?: {
        default?: false | (() => vue.VNodeChild) | undefined;
        badge?: false | (() => vue.VNodeChild) | undefined;
    } | undefined;
} & {
    "v-slot:default"?: false | (() => vue.VNodeChild) | undefined;
    "v-slot:badge"?: false | (() => vue.VNodeChild) | undefined;
}, {}, unknown, {}, {}, vue.ComponentOptionsMixin, vue.ComponentOptionsMixin, Record<string, any>, string, {
    style: vue.StyleValue;
    label: string;
    tag: string;
    transition: NonNullable<string | boolean | (vue.TransitionProps & {
        component?: vue.Component | undefined;
    })>;
    modelValue: boolean;
    rounded: string | number | boolean;
    inline: boolean;
    dot: boolean;
    tile: boolean;
    floating: boolean;
    location: NonNullable<Anchor>;
    bordered: boolean;
}, {}, string, vue.SlotsType<Partial<{
    default: () => vue.VNode<vue.RendererNode, vue.RendererElement, {
        [key: string]: any;
    }>[];
    badge: () => vue.VNode<vue.RendererNode, vue.RendererElement, {
        [key: string]: any;
    }>[];
}>>> & vue.VNodeProps & vue.AllowedComponentProps & vue.ComponentCustomProps & FilterPropsOptions<{
    transition: Omit<{
        type: vue.PropType<string | boolean | (vue.TransitionProps & {
            component?: vue.Component | undefined;
        })>;
        default: string;
        validator: (val: unknown) => boolean;
    }, "default" | "type"> & {
        type: vue.PropType<NonNullable<string | boolean | (vue.TransitionProps & {
            component?: vue.Component | undefined;
        })>>;
        default: NonNullable<string | boolean | (vue.TransitionProps & {
            component?: vue.Component | undefined;
        })>;
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
    location: {
        type: vue.PropType<NonNullable<Anchor>>;
        default: NonNullable<Anchor>;
    };
    class: vue.PropType<any>;
    style: {
        type: vue.PropType<vue.StyleValue>;
        default: null;
    };
    bordered: BooleanConstructor;
    color: StringConstructor;
    content: (StringConstructor | NumberConstructor)[];
    dot: BooleanConstructor;
    floating: BooleanConstructor;
    icon: vue.PropType<IconValue>;
    inline: BooleanConstructor;
    label: {
        type: StringConstructor;
        default: string;
    };
    max: (StringConstructor | NumberConstructor)[];
    modelValue: {
        type: BooleanConstructor;
        default: boolean;
    };
    offsetX: (StringConstructor | NumberConstructor)[];
    offsetY: (StringConstructor | NumberConstructor)[];
    textColor: StringConstructor;
}, vue.ExtractPropTypes<{
    transition: Omit<{
        type: vue.PropType<string | boolean | (vue.TransitionProps & {
            component?: vue.Component | undefined;
        })>;
        default: string;
        validator: (val: unknown) => boolean;
    }, "default" | "type"> & {
        type: vue.PropType<NonNullable<string | boolean | (vue.TransitionProps & {
            component?: vue.Component | undefined;
        })>>;
        default: NonNullable<string | boolean | (vue.TransitionProps & {
            component?: vue.Component | undefined;
        })>;
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
    location: {
        type: vue.PropType<NonNullable<Anchor>>;
        default: NonNullable<Anchor>;
    };
    class: vue.PropType<any>;
    style: {
        type: vue.PropType<vue.StyleValue>;
        default: null;
    };
    bordered: BooleanConstructor;
    color: StringConstructor;
    content: (StringConstructor | NumberConstructor)[];
    dot: BooleanConstructor;
    floating: BooleanConstructor;
    icon: vue.PropType<IconValue>;
    inline: BooleanConstructor;
    label: {
        type: StringConstructor;
        default: string;
    };
    max: (StringConstructor | NumberConstructor)[];
    modelValue: {
        type: BooleanConstructor;
        default: boolean;
    };
    offsetX: (StringConstructor | NumberConstructor)[];
    offsetY: (StringConstructor | NumberConstructor)[];
    textColor: StringConstructor;
}>>;
type VBadge = InstanceType<typeof VBadge>;

export { VBadge };
