import * as vue from 'vue';
import { ComponentPropsOptions, ExtractPropTypes, PropType, JSXComponent, ComponentInternalInstance, Ref, ComputedRef } from 'vue';
// @ts-ignore
import * as vue_router from 'vue-router';

declare const block: readonly ["top", "bottom"];
declare const inline: readonly ["start", "end", "left", "right"];
type Tblock = typeof block[number];
type Tinline = typeof inline[number];
type Anchor = Tblock | Tinline | 'center' | 'center center' | `${Tblock} ${Tinline | 'center'}` | `${Tinline} ${Tblock | 'center'}`;

interface FilterPropsOptions<PropsOptions extends Readonly<ComponentPropsOptions>, Props = ExtractPropTypes<PropsOptions>> {
    filterProps<T extends Partial<Props>, U extends Exclude<keyof Props, Exclude<keyof Props, keyof T>>>(props: T): Partial<Pick<T, U>>;
}

type Density$1 = null | 'prominent' | 'default' | 'comfortable' | 'compact';

declare const VAppBar: {
    new (...args: any[]): vue.CreateComponentPublicInstance<{
        flat: boolean;
        style: vue.StyleValue;
        height: string | number;
        tag: string;
        collapse: boolean;
        order: string | number;
        absolute: boolean;
        modelValue: boolean;
        tile: boolean;
        density: Density$1;
        extended: boolean;
        extensionHeight: string | number;
        floating: boolean;
        scrollThreshold: string | number;
        location: "top" | "bottom";
    } & {
        class?: any;
        title?: string | undefined;
        image?: string | undefined;
        theme?: string | undefined;
        color?: string | undefined;
        name?: string | undefined;
        border?: string | number | boolean | undefined;
        rounded?: string | number | boolean | undefined;
        elevation?: string | number | undefined;
        scrollTarget?: string | undefined;
        scrollBehavior?: (string & {}) | "collapse" | "hide" | "inverted" | "elevate" | "fade-image" | undefined;
    } & {
        $children?: vue.VNodeChild | (() => vue.VNodeChild) | {
            default?: (() => vue.VNodeChild) | undefined;
            image?: (() => vue.VNodeChild) | undefined;
            prepend?: (() => vue.VNodeChild) | undefined;
            append?: (() => vue.VNodeChild) | undefined;
            title?: (() => vue.VNodeChild) | undefined;
            extension?: (() => vue.VNodeChild) | undefined;
        };
        'v-slots'?: {
            default?: false | (() => vue.VNodeChild) | undefined;
            image?: false | (() => vue.VNodeChild) | undefined;
            prepend?: false | (() => vue.VNodeChild) | undefined;
            append?: false | (() => vue.VNodeChild) | undefined;
            title?: false | (() => vue.VNodeChild) | undefined;
            extension?: false | (() => vue.VNodeChild) | undefined;
        } | undefined;
    } & {
        "v-slot:default"?: false | (() => vue.VNodeChild) | undefined;
        "v-slot:image"?: false | (() => vue.VNodeChild) | undefined;
        "v-slot:prepend"?: false | (() => vue.VNodeChild) | undefined;
        "v-slot:append"?: false | (() => vue.VNodeChild) | undefined;
        "v-slot:title"?: false | (() => vue.VNodeChild) | undefined;
        "v-slot:extension"?: false | (() => vue.VNodeChild) | undefined;
    } & {
        "onUpdate:modelValue"?: ((value: boolean) => any) | undefined;
    }, void, unknown, {}, {}, vue.ComponentOptionsMixin, vue.ComponentOptionsMixin, {
        'update:modelValue': (value: boolean) => boolean;
    }, vue.VNodeProps & vue.AllowedComponentProps & vue.ComponentCustomProps & {
        flat: boolean;
        style: vue.StyleValue;
        height: string | number;
        tag: string;
        collapse: boolean;
        order: string | number;
        absolute: boolean;
        modelValue: boolean;
        tile: boolean;
        density: Density$1;
        extended: boolean;
        extensionHeight: string | number;
        floating: boolean;
        scrollThreshold: string | number;
        location: "top" | "bottom";
    } & {
        class?: any;
        title?: string | undefined;
        image?: string | undefined;
        theme?: string | undefined;
        color?: string | undefined;
        name?: string | undefined;
        border?: string | number | boolean | undefined;
        rounded?: string | number | boolean | undefined;
        elevation?: string | number | undefined;
        scrollTarget?: string | undefined;
        scrollBehavior?: (string & {}) | "collapse" | "hide" | "inverted" | "elevate" | "fade-image" | undefined;
    } & {
        $children?: vue.VNodeChild | (() => vue.VNodeChild) | {
            default?: (() => vue.VNodeChild) | undefined;
            image?: (() => vue.VNodeChild) | undefined;
            prepend?: (() => vue.VNodeChild) | undefined;
            append?: (() => vue.VNodeChild) | undefined;
            title?: (() => vue.VNodeChild) | undefined;
            extension?: (() => vue.VNodeChild) | undefined;
        };
        'v-slots'?: {
            default?: false | (() => vue.VNodeChild) | undefined;
            image?: false | (() => vue.VNodeChild) | undefined;
            prepend?: false | (() => vue.VNodeChild) | undefined;
            append?: false | (() => vue.VNodeChild) | undefined;
            title?: false | (() => vue.VNodeChild) | undefined;
            extension?: false | (() => vue.VNodeChild) | undefined;
        } | undefined;
    } & {
        "v-slot:default"?: false | (() => vue.VNodeChild) | undefined;
        "v-slot:image"?: false | (() => vue.VNodeChild) | undefined;
        "v-slot:prepend"?: false | (() => vue.VNodeChild) | undefined;
        "v-slot:append"?: false | (() => vue.VNodeChild) | undefined;
        "v-slot:title"?: false | (() => vue.VNodeChild) | undefined;
        "v-slot:extension"?: false | (() => vue.VNodeChild) | undefined;
    } & {
        "onUpdate:modelValue"?: ((value: boolean) => any) | undefined;
    }, {
        flat: boolean;
        style: vue.StyleValue;
        height: string | number;
        tag: string;
        collapse: boolean;
        order: string | number;
        absolute: boolean;
        modelValue: boolean;
        rounded: string | number | boolean;
        tile: boolean;
        density: Density$1;
        extended: boolean;
        extensionHeight: string | number;
        floating: boolean;
        scrollThreshold: string | number;
        location: "top" | "bottom";
    }, true, {}, vue.SlotsType<Partial<{
        default: () => vue.VNode<vue.RendererNode, vue.RendererElement, {
            [key: string]: any;
        }>[];
        image: () => vue.VNode<vue.RendererNode, vue.RendererElement, {
            [key: string]: any;
        }>[];
        prepend: () => vue.VNode<vue.RendererNode, vue.RendererElement, {
            [key: string]: any;
        }>[];
        append: () => vue.VNode<vue.RendererNode, vue.RendererElement, {
            [key: string]: any;
        }>[];
        title: () => vue.VNode<vue.RendererNode, vue.RendererElement, {
            [key: string]: any;
        }>[];
        extension: () => vue.VNode<vue.RendererNode, vue.RendererElement, {
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
        flat: boolean;
        style: vue.StyleValue;
        height: string | number;
        tag: string;
        collapse: boolean;
        order: string | number;
        absolute: boolean;
        modelValue: boolean;
        tile: boolean;
        density: Density$1;
        extended: boolean;
        extensionHeight: string | number;
        floating: boolean;
        scrollThreshold: string | number;
        location: "top" | "bottom";
    } & {
        class?: any;
        title?: string | undefined;
        image?: string | undefined;
        theme?: string | undefined;
        color?: string | undefined;
        name?: string | undefined;
        border?: string | number | boolean | undefined;
        rounded?: string | number | boolean | undefined;
        elevation?: string | number | undefined;
        scrollTarget?: string | undefined;
        scrollBehavior?: (string & {}) | "collapse" | "hide" | "inverted" | "elevate" | "fade-image" | undefined;
    } & {
        $children?: vue.VNodeChild | (() => vue.VNodeChild) | {
            default?: (() => vue.VNodeChild) | undefined;
            image?: (() => vue.VNodeChild) | undefined;
            prepend?: (() => vue.VNodeChild) | undefined;
            append?: (() => vue.VNodeChild) | undefined;
            title?: (() => vue.VNodeChild) | undefined;
            extension?: (() => vue.VNodeChild) | undefined;
        };
        'v-slots'?: {
            default?: false | (() => vue.VNodeChild) | undefined;
            image?: false | (() => vue.VNodeChild) | undefined;
            prepend?: false | (() => vue.VNodeChild) | undefined;
            append?: false | (() => vue.VNodeChild) | undefined;
            title?: false | (() => vue.VNodeChild) | undefined;
            extension?: false | (() => vue.VNodeChild) | undefined;
        } | undefined;
    } & {
        "v-slot:default"?: false | (() => vue.VNodeChild) | undefined;
        "v-slot:image"?: false | (() => vue.VNodeChild) | undefined;
        "v-slot:prepend"?: false | (() => vue.VNodeChild) | undefined;
        "v-slot:append"?: false | (() => vue.VNodeChild) | undefined;
        "v-slot:title"?: false | (() => vue.VNodeChild) | undefined;
        "v-slot:extension"?: false | (() => vue.VNodeChild) | undefined;
    } & {
        "onUpdate:modelValue"?: ((value: boolean) => any) | undefined;
    }, {}, {}, {}, {}, {
        flat: boolean;
        style: vue.StyleValue;
        height: string | number;
        tag: string;
        collapse: boolean;
        order: string | number;
        absolute: boolean;
        modelValue: boolean;
        rounded: string | number | boolean;
        tile: boolean;
        density: Density$1;
        extended: boolean;
        extensionHeight: string | number;
        floating: boolean;
        scrollThreshold: string | number;
        location: "top" | "bottom";
    }>;
    __isFragment?: undefined;
    __isTeleport?: undefined;
    __isSuspense?: undefined;
} & vue.ComponentOptionsBase<{
    flat: boolean;
    style: vue.StyleValue;
    height: string | number;
    tag: string;
    collapse: boolean;
    order: string | number;
    absolute: boolean;
    modelValue: boolean;
    tile: boolean;
    density: Density$1;
    extended: boolean;
    extensionHeight: string | number;
    floating: boolean;
    scrollThreshold: string | number;
    location: "top" | "bottom";
} & {
    class?: any;
    title?: string | undefined;
    image?: string | undefined;
    theme?: string | undefined;
    color?: string | undefined;
    name?: string | undefined;
    border?: string | number | boolean | undefined;
    rounded?: string | number | boolean | undefined;
    elevation?: string | number | undefined;
    scrollTarget?: string | undefined;
    scrollBehavior?: (string & {}) | "collapse" | "hide" | "inverted" | "elevate" | "fade-image" | undefined;
} & {
    $children?: vue.VNodeChild | (() => vue.VNodeChild) | {
        default?: (() => vue.VNodeChild) | undefined;
        image?: (() => vue.VNodeChild) | undefined;
        prepend?: (() => vue.VNodeChild) | undefined;
        append?: (() => vue.VNodeChild) | undefined;
        title?: (() => vue.VNodeChild) | undefined;
        extension?: (() => vue.VNodeChild) | undefined;
    };
    'v-slots'?: {
        default?: false | (() => vue.VNodeChild) | undefined;
        image?: false | (() => vue.VNodeChild) | undefined;
        prepend?: false | (() => vue.VNodeChild) | undefined;
        append?: false | (() => vue.VNodeChild) | undefined;
        title?: false | (() => vue.VNodeChild) | undefined;
        extension?: false | (() => vue.VNodeChild) | undefined;
    } | undefined;
} & {
    "v-slot:default"?: false | (() => vue.VNodeChild) | undefined;
    "v-slot:image"?: false | (() => vue.VNodeChild) | undefined;
    "v-slot:prepend"?: false | (() => vue.VNodeChild) | undefined;
    "v-slot:append"?: false | (() => vue.VNodeChild) | undefined;
    "v-slot:title"?: false | (() => vue.VNodeChild) | undefined;
    "v-slot:extension"?: false | (() => vue.VNodeChild) | undefined;
} & {
    "onUpdate:modelValue"?: ((value: boolean) => any) | undefined;
}, void, unknown, {}, {}, vue.ComponentOptionsMixin, vue.ComponentOptionsMixin, {
    'update:modelValue': (value: boolean) => boolean;
}, string, {
    flat: boolean;
    style: vue.StyleValue;
    height: string | number;
    tag: string;
    collapse: boolean;
    order: string | number;
    absolute: boolean;
    modelValue: boolean;
    rounded: string | number | boolean;
    tile: boolean;
    density: Density$1;
    extended: boolean;
    extensionHeight: string | number;
    floating: boolean;
    scrollThreshold: string | number;
    location: "top" | "bottom";
}, {}, string, vue.SlotsType<Partial<{
    default: () => vue.VNode<vue.RendererNode, vue.RendererElement, {
        [key: string]: any;
    }>[];
    image: () => vue.VNode<vue.RendererNode, vue.RendererElement, {
        [key: string]: any;
    }>[];
    prepend: () => vue.VNode<vue.RendererNode, vue.RendererElement, {
        [key: string]: any;
    }>[];
    append: () => vue.VNode<vue.RendererNode, vue.RendererElement, {
        [key: string]: any;
    }>[];
    title: () => vue.VNode<vue.RendererNode, vue.RendererElement, {
        [key: string]: any;
    }>[];
    extension: () => vue.VNode<vue.RendererNode, vue.RendererElement, {
        [key: string]: any;
    }>[];
}>>> & vue.VNodeProps & vue.AllowedComponentProps & vue.ComponentCustomProps & FilterPropsOptions<{
    height: {
        type: (StringConstructor | NumberConstructor)[];
        default: number;
    };
    scrollTarget: {
        type: StringConstructor;
    };
    scrollThreshold: {
        type: (StringConstructor | NumberConstructor)[];
        default: number;
    };
    name: {
        type: StringConstructor;
    };
    order: {
        type: (StringConstructor | NumberConstructor)[];
        default: number;
    };
    absolute: BooleanConstructor;
    theme: StringConstructor;
    tag: Omit<{
        type: StringConstructor;
        default: string;
    }, "default" | "type"> & {
        type: PropType<string>;
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
    class: PropType<any>;
    style: {
        type: PropType<vue.StyleValue>;
        default: null;
    };
    border: (StringConstructor | NumberConstructor | BooleanConstructor)[];
    collapse: BooleanConstructor;
    color: StringConstructor;
    density: {
        type: PropType<Density$1>;
        default: string;
        validator: (v: any) => boolean;
    };
    extended: BooleanConstructor;
    extensionHeight: {
        type: (StringConstructor | NumberConstructor)[];
        default: number;
    };
    flat: BooleanConstructor;
    floating: BooleanConstructor;
    image: StringConstructor;
    title: StringConstructor;
    scrollBehavior: PropType<(string & {}) | "collapse" | "hide" | "inverted" | "elevate" | "fade-image">;
    modelValue: {
        type: BooleanConstructor;
        default: boolean;
    };
    location: {
        type: PropType<"top" | "bottom">;
        default: string;
        validator: (value: any) => boolean;
    };
}, vue.ExtractPropTypes<{
    height: {
        type: (StringConstructor | NumberConstructor)[];
        default: number;
    };
    scrollTarget: {
        type: StringConstructor;
    };
    scrollThreshold: {
        type: (StringConstructor | NumberConstructor)[];
        default: number;
    };
    name: {
        type: StringConstructor;
    };
    order: {
        type: (StringConstructor | NumberConstructor)[];
        default: number;
    };
    absolute: BooleanConstructor;
    theme: StringConstructor;
    tag: Omit<{
        type: StringConstructor;
        default: string;
    }, "default" | "type"> & {
        type: PropType<string>;
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
    class: PropType<any>;
    style: {
        type: PropType<vue.StyleValue>;
        default: null;
    };
    border: (StringConstructor | NumberConstructor | BooleanConstructor)[];
    collapse: BooleanConstructor;
    color: StringConstructor;
    density: {
        type: PropType<Density$1>;
        default: string;
        validator: (v: any) => boolean;
    };
    extended: BooleanConstructor;
    extensionHeight: {
        type: (StringConstructor | NumberConstructor)[];
        default: number;
    };
    flat: BooleanConstructor;
    floating: BooleanConstructor;
    image: StringConstructor;
    title: StringConstructor;
    scrollBehavior: PropType<(string & {}) | "collapse" | "hide" | "inverted" | "elevate" | "fade-image">;
    modelValue: {
        type: BooleanConstructor;
        default: boolean;
    };
    location: {
        type: PropType<"top" | "bottom">;
        default: string;
        validator: (value: any) => boolean;
    };
}>>;
type VAppBar = InstanceType<typeof VAppBar>;

type IconValue = string | (string | [path: string, opacity: number])[] | JSXComponent;
declare const IconValue: PropType<IconValue>;

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

type Density = null | 'default' | 'comfortable' | 'compact';

declare const VAppBarNavIcon: {
    new (...args: any[]): vue.CreateComponentPublicInstance<{
        symbol: any;
        flat: boolean;
        replace: boolean;
        style: vue.StyleValue;
        size: string | number;
        disabled: boolean;
        tag: string;
        icon: NonNullable<boolean | IconValue>;
        readonly: boolean;
        variant: NonNullable<NonNullable<"flat" | "text" | "elevated" | "tonal" | "outlined" | "plain">>;
        block: boolean;
        exact: boolean;
        tile: boolean;
        density: Density;
        slim: boolean;
        stacked: boolean;
        ripple: boolean | {
            class: string;
        } | undefined;
    } & {
        class?: any;
        text?: string | undefined;
        value?: any;
        width?: string | number | undefined;
        height?: string | number | undefined;
        active?: boolean | undefined;
        theme?: string | undefined;
        href?: string | undefined;
        color?: string | undefined;
        loading?: string | boolean | undefined;
        to?: vue_router.RouteLocationRaw | undefined;
        border?: string | number | boolean | undefined;
        position?: "fixed" | "absolute" | "relative" | "static" | "sticky" | undefined;
        rounded?: string | number | boolean | undefined;
        maxHeight?: string | number | undefined;
        maxWidth?: string | number | undefined;
        minHeight?: string | number | undefined;
        minWidth?: string | number | undefined;
        elevation?: string | number | undefined;
        location?: Anchor | undefined;
        baseColor?: string | undefined;
        selectedClass?: string | undefined;
        prependIcon?: IconValue | undefined;
        appendIcon?: IconValue | undefined;
    } & {
        $children?: vue.VNodeChild | (() => vue.VNodeChild) | {
            default?: (() => vue.VNodeChild) | undefined;
            prepend?: (() => vue.VNodeChild) | undefined;
            append?: (() => vue.VNodeChild) | undefined;
            loader?: (() => vue.VNodeChild) | undefined;
        };
        'v-slots'?: {
            default?: false | (() => vue.VNodeChild) | undefined;
            prepend?: false | (() => vue.VNodeChild) | undefined;
            append?: false | (() => vue.VNodeChild) | undefined;
            loader?: false | (() => vue.VNodeChild) | undefined;
        } | undefined;
    } & {
        "v-slot:default"?: false | (() => vue.VNodeChild) | undefined;
        "v-slot:prepend"?: false | (() => vue.VNodeChild) | undefined;
        "v-slot:append"?: false | (() => vue.VNodeChild) | undefined;
        "v-slot:loader"?: false | (() => vue.VNodeChild) | undefined;
    }, {}, unknown, {}, {}, vue.ComponentOptionsMixin, vue.ComponentOptionsMixin, Record<string, any>, vue.VNodeProps & vue.AllowedComponentProps & vue.ComponentCustomProps & {
        symbol: any;
        flat: boolean;
        replace: boolean;
        style: vue.StyleValue;
        size: string | number;
        disabled: boolean;
        tag: string;
        icon: NonNullable<boolean | IconValue>;
        readonly: boolean;
        variant: NonNullable<NonNullable<"flat" | "text" | "elevated" | "tonal" | "outlined" | "plain">>;
        block: boolean;
        exact: boolean;
        tile: boolean;
        density: Density;
        slim: boolean;
        stacked: boolean;
        ripple: boolean | {
            class: string;
        } | undefined;
    } & {
        class?: any;
        text?: string | undefined;
        value?: any;
        width?: string | number | undefined;
        height?: string | number | undefined;
        active?: boolean | undefined;
        theme?: string | undefined;
        href?: string | undefined;
        color?: string | undefined;
        loading?: string | boolean | undefined;
        to?: vue_router.RouteLocationRaw | undefined;
        border?: string | number | boolean | undefined;
        position?: "fixed" | "absolute" | "relative" | "static" | "sticky" | undefined;
        rounded?: string | number | boolean | undefined;
        maxHeight?: string | number | undefined;
        maxWidth?: string | number | undefined;
        minHeight?: string | number | undefined;
        minWidth?: string | number | undefined;
        elevation?: string | number | undefined;
        location?: Anchor | undefined;
        baseColor?: string | undefined;
        selectedClass?: string | undefined;
        prependIcon?: IconValue | undefined;
        appendIcon?: IconValue | undefined;
    } & {
        $children?: vue.VNodeChild | (() => vue.VNodeChild) | {
            default?: (() => vue.VNodeChild) | undefined;
            prepend?: (() => vue.VNodeChild) | undefined;
            append?: (() => vue.VNodeChild) | undefined;
            loader?: (() => vue.VNodeChild) | undefined;
        };
        'v-slots'?: {
            default?: false | (() => vue.VNodeChild) | undefined;
            prepend?: false | (() => vue.VNodeChild) | undefined;
            append?: false | (() => vue.VNodeChild) | undefined;
            loader?: false | (() => vue.VNodeChild) | undefined;
        } | undefined;
    } & {
        "v-slot:default"?: false | (() => vue.VNodeChild) | undefined;
        "v-slot:prepend"?: false | (() => vue.VNodeChild) | undefined;
        "v-slot:append"?: false | (() => vue.VNodeChild) | undefined;
        "v-slot:loader"?: false | (() => vue.VNodeChild) | undefined;
    }, {
        symbol: any;
        flat: boolean;
        replace: boolean;
        style: vue.StyleValue;
        size: string | number;
        active: boolean;
        disabled: boolean;
        tag: string;
        icon: NonNullable<boolean | IconValue>;
        readonly: boolean;
        rounded: string | number | boolean;
        variant: NonNullable<NonNullable<"flat" | "text" | "elevated" | "tonal" | "outlined" | "plain">>;
        block: boolean;
        exact: boolean;
        tile: boolean;
        density: Density;
        slim: boolean;
        stacked: boolean;
        ripple: boolean | {
            class: string;
        } | undefined;
    }, true, {}, vue.SlotsType<Partial<{
        default: () => vue.VNode<vue.RendererNode, vue.RendererElement, {
            [key: string]: any;
        }>[];
        prepend: () => vue.VNode<vue.RendererNode, vue.RendererElement, {
            [key: string]: any;
        }>[];
        append: () => vue.VNode<vue.RendererNode, vue.RendererElement, {
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
        symbol: any;
        flat: boolean;
        replace: boolean;
        style: vue.StyleValue;
        size: string | number;
        disabled: boolean;
        tag: string;
        icon: NonNullable<boolean | IconValue>;
        readonly: boolean;
        variant: NonNullable<NonNullable<"flat" | "text" | "elevated" | "tonal" | "outlined" | "plain">>;
        block: boolean;
        exact: boolean;
        tile: boolean;
        density: Density;
        slim: boolean;
        stacked: boolean;
        ripple: boolean | {
            class: string;
        } | undefined;
    } & {
        class?: any;
        text?: string | undefined;
        value?: any;
        width?: string | number | undefined;
        height?: string | number | undefined;
        active?: boolean | undefined;
        theme?: string | undefined;
        href?: string | undefined;
        color?: string | undefined;
        loading?: string | boolean | undefined;
        to?: vue_router.RouteLocationRaw | undefined;
        border?: string | number | boolean | undefined;
        position?: "fixed" | "absolute" | "relative" | "static" | "sticky" | undefined;
        rounded?: string | number | boolean | undefined;
        maxHeight?: string | number | undefined;
        maxWidth?: string | number | undefined;
        minHeight?: string | number | undefined;
        minWidth?: string | number | undefined;
        elevation?: string | number | undefined;
        location?: Anchor | undefined;
        baseColor?: string | undefined;
        selectedClass?: string | undefined;
        prependIcon?: IconValue | undefined;
        appendIcon?: IconValue | undefined;
    } & {
        $children?: vue.VNodeChild | (() => vue.VNodeChild) | {
            default?: (() => vue.VNodeChild) | undefined;
            prepend?: (() => vue.VNodeChild) | undefined;
            append?: (() => vue.VNodeChild) | undefined;
            loader?: (() => vue.VNodeChild) | undefined;
        };
        'v-slots'?: {
            default?: false | (() => vue.VNodeChild) | undefined;
            prepend?: false | (() => vue.VNodeChild) | undefined;
            append?: false | (() => vue.VNodeChild) | undefined;
            loader?: false | (() => vue.VNodeChild) | undefined;
        } | undefined;
    } & {
        "v-slot:default"?: false | (() => vue.VNodeChild) | undefined;
        "v-slot:prepend"?: false | (() => vue.VNodeChild) | undefined;
        "v-slot:append"?: false | (() => vue.VNodeChild) | undefined;
        "v-slot:loader"?: false | (() => vue.VNodeChild) | undefined;
    }, {}, {}, {}, {}, {
        symbol: any;
        flat: boolean;
        replace: boolean;
        style: vue.StyleValue;
        size: string | number;
        active: boolean;
        disabled: boolean;
        tag: string;
        icon: NonNullable<boolean | IconValue>;
        readonly: boolean;
        rounded: string | number | boolean;
        variant: NonNullable<NonNullable<"flat" | "text" | "elevated" | "tonal" | "outlined" | "plain">>;
        block: boolean;
        exact: boolean;
        tile: boolean;
        density: Density;
        slim: boolean;
        stacked: boolean;
        ripple: boolean | {
            class: string;
        } | undefined;
    }>;
    __isFragment?: undefined;
    __isTeleport?: undefined;
    __isSuspense?: undefined;
} & vue.ComponentOptionsBase<{
    symbol: any;
    flat: boolean;
    replace: boolean;
    style: vue.StyleValue;
    size: string | number;
    disabled: boolean;
    tag: string;
    icon: NonNullable<boolean | IconValue>;
    readonly: boolean;
    variant: NonNullable<NonNullable<"flat" | "text" | "elevated" | "tonal" | "outlined" | "plain">>;
    block: boolean;
    exact: boolean;
    tile: boolean;
    density: Density;
    slim: boolean;
    stacked: boolean;
    ripple: boolean | {
        class: string;
    } | undefined;
} & {
    class?: any;
    text?: string | undefined;
    value?: any;
    width?: string | number | undefined;
    height?: string | number | undefined;
    active?: boolean | undefined;
    theme?: string | undefined;
    href?: string | undefined;
    color?: string | undefined;
    loading?: string | boolean | undefined;
    to?: vue_router.RouteLocationRaw | undefined;
    border?: string | number | boolean | undefined;
    position?: "fixed" | "absolute" | "relative" | "static" | "sticky" | undefined;
    rounded?: string | number | boolean | undefined;
    maxHeight?: string | number | undefined;
    maxWidth?: string | number | undefined;
    minHeight?: string | number | undefined;
    minWidth?: string | number | undefined;
    elevation?: string | number | undefined;
    location?: Anchor | undefined;
    baseColor?: string | undefined;
    selectedClass?: string | undefined;
    prependIcon?: IconValue | undefined;
    appendIcon?: IconValue | undefined;
} & {
    $children?: vue.VNodeChild | (() => vue.VNodeChild) | {
        default?: (() => vue.VNodeChild) | undefined;
        prepend?: (() => vue.VNodeChild) | undefined;
        append?: (() => vue.VNodeChild) | undefined;
        loader?: (() => vue.VNodeChild) | undefined;
    };
    'v-slots'?: {
        default?: false | (() => vue.VNodeChild) | undefined;
        prepend?: false | (() => vue.VNodeChild) | undefined;
        append?: false | (() => vue.VNodeChild) | undefined;
        loader?: false | (() => vue.VNodeChild) | undefined;
    } | undefined;
} & {
    "v-slot:default"?: false | (() => vue.VNodeChild) | undefined;
    "v-slot:prepend"?: false | (() => vue.VNodeChild) | undefined;
    "v-slot:append"?: false | (() => vue.VNodeChild) | undefined;
    "v-slot:loader"?: false | (() => vue.VNodeChild) | undefined;
}, {}, unknown, {}, {}, vue.ComponentOptionsMixin, vue.ComponentOptionsMixin, Record<string, any>, string, {
    symbol: any;
    flat: boolean;
    replace: boolean;
    style: vue.StyleValue;
    size: string | number;
    active: boolean;
    disabled: boolean;
    tag: string;
    icon: NonNullable<boolean | IconValue>;
    readonly: boolean;
    rounded: string | number | boolean;
    variant: NonNullable<NonNullable<"flat" | "text" | "elevated" | "tonal" | "outlined" | "plain">>;
    block: boolean;
    exact: boolean;
    tile: boolean;
    density: Density;
    slim: boolean;
    stacked: boolean;
    ripple: boolean | {
        class: string;
    } | undefined;
}, {}, string, vue.SlotsType<Partial<{
    default: () => vue.VNode<vue.RendererNode, vue.RendererElement, {
        [key: string]: any;
    }>[];
    prepend: () => vue.VNode<vue.RendererNode, vue.RendererElement, {
        [key: string]: any;
    }>[];
    append: () => vue.VNode<vue.RendererNode, vue.RendererElement, {
        [key: string]: any;
    }>[];
    loader: () => vue.VNode<vue.RendererNode, vue.RendererElement, {
        [key: string]: any;
    }>[];
}>>> & vue.VNodeProps & vue.AllowedComponentProps & vue.ComponentCustomProps & FilterPropsOptions<{
    color: StringConstructor;
    variant: Omit<Omit<{
        type: vue.PropType<"flat" | "text" | "elevated" | "tonal" | "outlined" | "plain">;
        default: string;
        validator: (v: any) => boolean;
    }, "default" | "type"> & {
        type: vue.PropType<NonNullable<"flat" | "text" | "elevated" | "tonal" | "outlined" | "plain">>;
        default: NonNullable<"flat" | "text" | "elevated" | "tonal" | "outlined" | "plain">;
    }, "default" | "type"> & {
        type: vue.PropType<NonNullable<NonNullable<"flat" | "text" | "elevated" | "tonal" | "outlined" | "plain">>>;
        default: NonNullable<NonNullable<"flat" | "text" | "elevated" | "tonal" | "outlined" | "plain">>;
    };
    theme: StringConstructor;
    tag: Omit<{
        type: StringConstructor;
        default: string;
    }, "default" | "type"> & {
        type: vue.PropType<string>;
        default: string;
    };
    size: {
        type: (StringConstructor | NumberConstructor)[];
        default: string;
    };
    href: StringConstructor;
    replace: BooleanConstructor;
    to: vue.PropType<vue_router.RouteLocationRaw>;
    exact: BooleanConstructor;
    rounded: {
        type: (StringConstructor | NumberConstructor | BooleanConstructor)[];
        default: undefined;
    };
    tile: BooleanConstructor;
    position: {
        type: vue.PropType<"fixed" | "absolute" | "relative" | "static" | "sticky">;
        validator: (v: any) => boolean;
    };
    location: vue.PropType<Anchor>;
    loading: (StringConstructor | BooleanConstructor)[];
    value: null;
    disabled: BooleanConstructor;
    selectedClass: StringConstructor;
    elevation: {
        type: (StringConstructor | NumberConstructor)[];
        validator(v: any): boolean;
    };
    height: (StringConstructor | NumberConstructor)[];
    maxHeight: (StringConstructor | NumberConstructor)[];
    maxWidth: (StringConstructor | NumberConstructor)[];
    minHeight: (StringConstructor | NumberConstructor)[];
    minWidth: (StringConstructor | NumberConstructor)[];
    width: (StringConstructor | NumberConstructor)[];
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
    active: {
        type: BooleanConstructor;
        default: undefined;
    };
    baseColor: StringConstructor;
    symbol: {
        type: null;
        default: vue.InjectionKey<GroupProvide>;
    };
    flat: BooleanConstructor;
    icon: {
        type: vue.PropType<NonNullable<boolean | IconValue>>;
        default: NonNullable<boolean | IconValue>;
    };
    prependIcon: vue.PropType<IconValue>;
    appendIcon: vue.PropType<IconValue>;
    block: BooleanConstructor;
    readonly: BooleanConstructor;
    slim: BooleanConstructor;
    stacked: BooleanConstructor;
    ripple: {
        type: vue.PropType<boolean | {
            class: string;
        } | undefined>;
        default: boolean;
    };
    text: StringConstructor;
}, vue.ExtractPropTypes<{
    color: StringConstructor;
    variant: Omit<Omit<{
        type: vue.PropType<"flat" | "text" | "elevated" | "tonal" | "outlined" | "plain">;
        default: string;
        validator: (v: any) => boolean;
    }, "default" | "type"> & {
        type: vue.PropType<NonNullable<"flat" | "text" | "elevated" | "tonal" | "outlined" | "plain">>;
        default: NonNullable<"flat" | "text" | "elevated" | "tonal" | "outlined" | "plain">;
    }, "default" | "type"> & {
        type: vue.PropType<NonNullable<NonNullable<"flat" | "text" | "elevated" | "tonal" | "outlined" | "plain">>>;
        default: NonNullable<NonNullable<"flat" | "text" | "elevated" | "tonal" | "outlined" | "plain">>;
    };
    theme: StringConstructor;
    tag: Omit<{
        type: StringConstructor;
        default: string;
    }, "default" | "type"> & {
        type: vue.PropType<string>;
        default: string;
    };
    size: {
        type: (StringConstructor | NumberConstructor)[];
        default: string;
    };
    href: StringConstructor;
    replace: BooleanConstructor;
    to: vue.PropType<vue_router.RouteLocationRaw>;
    exact: BooleanConstructor;
    rounded: {
        type: (StringConstructor | NumberConstructor | BooleanConstructor)[];
        default: undefined;
    };
    tile: BooleanConstructor;
    position: {
        type: vue.PropType<"fixed" | "absolute" | "relative" | "static" | "sticky">;
        validator: (v: any) => boolean;
    };
    location: vue.PropType<Anchor>;
    loading: (StringConstructor | BooleanConstructor)[];
    value: null;
    disabled: BooleanConstructor;
    selectedClass: StringConstructor;
    elevation: {
        type: (StringConstructor | NumberConstructor)[];
        validator(v: any): boolean;
    };
    height: (StringConstructor | NumberConstructor)[];
    maxHeight: (StringConstructor | NumberConstructor)[];
    maxWidth: (StringConstructor | NumberConstructor)[];
    minHeight: (StringConstructor | NumberConstructor)[];
    minWidth: (StringConstructor | NumberConstructor)[];
    width: (StringConstructor | NumberConstructor)[];
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
    active: {
        type: BooleanConstructor;
        default: undefined;
    };
    baseColor: StringConstructor;
    symbol: {
        type: null;
        default: vue.InjectionKey<GroupProvide>;
    };
    flat: BooleanConstructor;
    icon: {
        type: vue.PropType<NonNullable<boolean | IconValue>>;
        default: NonNullable<boolean | IconValue>;
    };
    prependIcon: vue.PropType<IconValue>;
    appendIcon: vue.PropType<IconValue>;
    block: BooleanConstructor;
    readonly: BooleanConstructor;
    slim: BooleanConstructor;
    stacked: BooleanConstructor;
    ripple: {
        type: vue.PropType<boolean | {
            class: string;
        } | undefined>;
        default: boolean;
    };
    text: StringConstructor;
}>>;
type VAppBarNavIcon = InstanceType<typeof VAppBarNavIcon>;

declare const VAppBarTitle: {
    new (...args: any[]): vue.CreateComponentPublicInstance<{
        style: vue.StyleValue;
        tag: string;
    } & {
        class?: any;
        text?: string | undefined;
    } & {
        $children?: vue.VNodeChild | (() => vue.VNodeChild) | {
            default?: (() => vue.VNodeChild) | undefined;
            text?: (() => vue.VNodeChild) | undefined;
        };
        'v-slots'?: {
            default?: false | (() => vue.VNodeChild) | undefined;
            text?: false | (() => vue.VNodeChild) | undefined;
        } | undefined;
    } & {
        "v-slot:default"?: false | (() => vue.VNodeChild) | undefined;
        "v-slot:text"?: false | (() => vue.VNodeChild) | undefined;
    }, {}, unknown, {}, {}, vue.ComponentOptionsMixin, vue.ComponentOptionsMixin, Record<string, any>, vue.VNodeProps & vue.AllowedComponentProps & vue.ComponentCustomProps & {
        style: vue.StyleValue;
        tag: string;
    } & {
        class?: any;
        text?: string | undefined;
    } & {
        $children?: vue.VNodeChild | (() => vue.VNodeChild) | {
            default?: (() => vue.VNodeChild) | undefined;
            text?: (() => vue.VNodeChild) | undefined;
        };
        'v-slots'?: {
            default?: false | (() => vue.VNodeChild) | undefined;
            text?: false | (() => vue.VNodeChild) | undefined;
        } | undefined;
    } & {
        "v-slot:default"?: false | (() => vue.VNodeChild) | undefined;
        "v-slot:text"?: false | (() => vue.VNodeChild) | undefined;
    }, {
        style: vue.StyleValue;
        tag: string;
    }, true, {}, vue.SlotsType<Partial<{
        default: () => vue.VNode<vue.RendererNode, vue.RendererElement, {
            [key: string]: any;
        }>[];
        text: () => vue.VNode<vue.RendererNode, vue.RendererElement, {
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
        tag: string;
    } & {
        class?: any;
        text?: string | undefined;
    } & {
        $children?: vue.VNodeChild | (() => vue.VNodeChild) | {
            default?: (() => vue.VNodeChild) | undefined;
            text?: (() => vue.VNodeChild) | undefined;
        };
        'v-slots'?: {
            default?: false | (() => vue.VNodeChild) | undefined;
            text?: false | (() => vue.VNodeChild) | undefined;
        } | undefined;
    } & {
        "v-slot:default"?: false | (() => vue.VNodeChild) | undefined;
        "v-slot:text"?: false | (() => vue.VNodeChild) | undefined;
    }, {}, {}, {}, {}, {
        style: vue.StyleValue;
        tag: string;
    }>;
    __isFragment?: undefined;
    __isTeleport?: undefined;
    __isSuspense?: undefined;
} & vue.ComponentOptionsBase<{
    style: vue.StyleValue;
    tag: string;
} & {
    class?: any;
    text?: string | undefined;
} & {
    $children?: vue.VNodeChild | (() => vue.VNodeChild) | {
        default?: (() => vue.VNodeChild) | undefined;
        text?: (() => vue.VNodeChild) | undefined;
    };
    'v-slots'?: {
        default?: false | (() => vue.VNodeChild) | undefined;
        text?: false | (() => vue.VNodeChild) | undefined;
    } | undefined;
} & {
    "v-slot:default"?: false | (() => vue.VNodeChild) | undefined;
    "v-slot:text"?: false | (() => vue.VNodeChild) | undefined;
}, {}, unknown, {}, {}, vue.ComponentOptionsMixin, vue.ComponentOptionsMixin, Record<string, any>, string, {
    style: vue.StyleValue;
    tag: string;
}, {}, string, vue.SlotsType<Partial<{
    default: () => vue.VNode<vue.RendererNode, vue.RendererElement, {
        [key: string]: any;
    }>[];
    text: () => vue.VNode<vue.RendererNode, vue.RendererElement, {
        [key: string]: any;
    }>[];
}>>> & vue.VNodeProps & vue.AllowedComponentProps & vue.ComponentCustomProps & FilterPropsOptions<{
    tag: {
        type: StringConstructor;
        default: string;
    };
    class: vue.PropType<any>;
    style: {
        type: vue.PropType<vue.StyleValue>;
        default: null;
    };
    text: StringConstructor;
}, vue.ExtractPropTypes<{
    tag: {
        type: StringConstructor;
        default: string;
    };
    class: vue.PropType<any>;
    style: {
        type: vue.PropType<vue.StyleValue>;
        default: null;
    };
    text: StringConstructor;
}>>;
type VAppBarTitle = InstanceType<typeof VAppBarTitle>;

export { VAppBar, VAppBarNavIcon, VAppBarTitle };
