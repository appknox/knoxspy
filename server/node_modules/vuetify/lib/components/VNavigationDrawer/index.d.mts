import * as vue from 'vue';
import { ComponentPropsOptions, ExtractPropTypes, PropType } from 'vue';

interface FilterPropsOptions<PropsOptions extends Readonly<ComponentPropsOptions>, Props = ExtractPropTypes<PropsOptions>> {
    filterProps<T extends Partial<Props>, U extends Exclude<keyof Props, Exclude<keyof Props, keyof T>>>(props: T): Partial<Pick<T, U>>;
}

declare const breakpoints: readonly ["sm", "md", "lg", "xl", "xxl"];
type Breakpoint = typeof breakpoints[number];
type DisplayBreakpoint = 'xs' | Breakpoint;

type VNavigationDrawerImageSlot = {
    image: string | undefined;
};
declare const VNavigationDrawer: {
    new (...args: any[]): vue.CreateComponentPublicInstance<{
        style: vue.StyleValue;
        width: string | number;
        tag: string;
        mobile: NonNullable<boolean | null> | null;
        order: string | number;
        absolute: boolean;
        sticky: boolean;
        modelValue: boolean | null;
        tile: boolean;
        floating: boolean;
        location: "left" | "right" | "end" | "top" | "bottom" | "start";
        persistent: boolean;
        scrim: string | boolean;
        touchless: boolean;
        disableResizeWatcher: boolean;
        disableRouteWatcher: boolean;
        expandOnHover: boolean;
        permanent: boolean;
        rail: boolean | null;
        railWidth: string | number;
        temporary: boolean;
    } & {
        class?: any;
        image?: string | undefined;
        theme?: string | undefined;
        color?: string | undefined;
        name?: string | undefined;
        mobileBreakpoint?: number | DisplayBreakpoint | undefined;
        border?: string | number | boolean | undefined;
        rounded?: string | number | boolean | undefined;
        elevation?: string | number | undefined;
        closeDelay?: string | number | undefined;
        openDelay?: string | number | undefined;
    } & {
        $children?: vue.VNodeChild | (() => vue.VNodeChild) | {
            default?: (() => vue.VNodeChild) | undefined;
            prepend?: (() => vue.VNodeChild) | undefined;
            append?: (() => vue.VNodeChild) | undefined;
            image?: ((arg: VNavigationDrawerImageSlot) => vue.VNodeChild) | undefined;
        };
        'v-slots'?: {
            default?: false | (() => vue.VNodeChild) | undefined;
            prepend?: false | (() => vue.VNodeChild) | undefined;
            append?: false | (() => vue.VNodeChild) | undefined;
            image?: false | ((arg: VNavigationDrawerImageSlot) => vue.VNodeChild) | undefined;
        } | undefined;
    } & {
        "v-slot:default"?: false | (() => vue.VNodeChild) | undefined;
        "v-slot:prepend"?: false | (() => vue.VNodeChild) | undefined;
        "v-slot:append"?: false | (() => vue.VNodeChild) | undefined;
        "v-slot:image"?: false | ((arg: VNavigationDrawerImageSlot) => vue.VNodeChild) | undefined;
    } & {
        "onUpdate:modelValue"?: ((val: boolean) => any) | undefined;
        "onUpdate:rail"?: ((val: boolean) => any) | undefined;
    }, {
        isStuck: vue.ShallowRef<boolean | "top" | "bottom">;
    }, unknown, {}, {}, vue.ComponentOptionsMixin, vue.ComponentOptionsMixin, {
        'update:modelValue': (val: boolean) => true;
        'update:rail': (val: boolean) => true;
    }, vue.VNodeProps & vue.AllowedComponentProps & vue.ComponentCustomProps & {
        style: vue.StyleValue;
        width: string | number;
        tag: string;
        mobile: NonNullable<boolean | null> | null;
        order: string | number;
        absolute: boolean;
        sticky: boolean;
        modelValue: boolean | null;
        tile: boolean;
        floating: boolean;
        location: "left" | "right" | "end" | "top" | "bottom" | "start";
        persistent: boolean;
        scrim: string | boolean;
        touchless: boolean;
        disableResizeWatcher: boolean;
        disableRouteWatcher: boolean;
        expandOnHover: boolean;
        permanent: boolean;
        rail: boolean | null;
        railWidth: string | number;
        temporary: boolean;
    } & {
        class?: any;
        image?: string | undefined;
        theme?: string | undefined;
        color?: string | undefined;
        name?: string | undefined;
        mobileBreakpoint?: number | DisplayBreakpoint | undefined;
        border?: string | number | boolean | undefined;
        rounded?: string | number | boolean | undefined;
        elevation?: string | number | undefined;
        closeDelay?: string | number | undefined;
        openDelay?: string | number | undefined;
    } & {
        $children?: vue.VNodeChild | (() => vue.VNodeChild) | {
            default?: (() => vue.VNodeChild) | undefined;
            prepend?: (() => vue.VNodeChild) | undefined;
            append?: (() => vue.VNodeChild) | undefined;
            image?: ((arg: VNavigationDrawerImageSlot) => vue.VNodeChild) | undefined;
        };
        'v-slots'?: {
            default?: false | (() => vue.VNodeChild) | undefined;
            prepend?: false | (() => vue.VNodeChild) | undefined;
            append?: false | (() => vue.VNodeChild) | undefined;
            image?: false | ((arg: VNavigationDrawerImageSlot) => vue.VNodeChild) | undefined;
        } | undefined;
    } & {
        "v-slot:default"?: false | (() => vue.VNodeChild) | undefined;
        "v-slot:prepend"?: false | (() => vue.VNodeChild) | undefined;
        "v-slot:append"?: false | (() => vue.VNodeChild) | undefined;
        "v-slot:image"?: false | ((arg: VNavigationDrawerImageSlot) => vue.VNodeChild) | undefined;
    } & {
        "onUpdate:modelValue"?: ((val: boolean) => any) | undefined;
        "onUpdate:rail"?: ((val: boolean) => any) | undefined;
    }, {
        style: vue.StyleValue;
        width: string | number;
        tag: string;
        mobile: NonNullable<boolean | null> | null;
        order: string | number;
        absolute: boolean;
        sticky: boolean;
        modelValue: boolean | null;
        rounded: string | number | boolean;
        tile: boolean;
        floating: boolean;
        location: "left" | "right" | "end" | "top" | "bottom" | "start";
        persistent: boolean;
        scrim: string | boolean;
        touchless: boolean;
        disableResizeWatcher: boolean;
        disableRouteWatcher: boolean;
        expandOnHover: boolean;
        permanent: boolean;
        rail: boolean | null;
        railWidth: string | number;
        temporary: boolean;
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
        image: (arg: VNavigationDrawerImageSlot) => vue.VNode<vue.RendererNode, vue.RendererElement, {
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
        width: string | number;
        tag: string;
        mobile: NonNullable<boolean | null> | null;
        order: string | number;
        absolute: boolean;
        sticky: boolean;
        modelValue: boolean | null;
        tile: boolean;
        floating: boolean;
        location: "left" | "right" | "end" | "top" | "bottom" | "start";
        persistent: boolean;
        scrim: string | boolean;
        touchless: boolean;
        disableResizeWatcher: boolean;
        disableRouteWatcher: boolean;
        expandOnHover: boolean;
        permanent: boolean;
        rail: boolean | null;
        railWidth: string | number;
        temporary: boolean;
    } & {
        class?: any;
        image?: string | undefined;
        theme?: string | undefined;
        color?: string | undefined;
        name?: string | undefined;
        mobileBreakpoint?: number | DisplayBreakpoint | undefined;
        border?: string | number | boolean | undefined;
        rounded?: string | number | boolean | undefined;
        elevation?: string | number | undefined;
        closeDelay?: string | number | undefined;
        openDelay?: string | number | undefined;
    } & {
        $children?: vue.VNodeChild | (() => vue.VNodeChild) | {
            default?: (() => vue.VNodeChild) | undefined;
            prepend?: (() => vue.VNodeChild) | undefined;
            append?: (() => vue.VNodeChild) | undefined;
            image?: ((arg: VNavigationDrawerImageSlot) => vue.VNodeChild) | undefined;
        };
        'v-slots'?: {
            default?: false | (() => vue.VNodeChild) | undefined;
            prepend?: false | (() => vue.VNodeChild) | undefined;
            append?: false | (() => vue.VNodeChild) | undefined;
            image?: false | ((arg: VNavigationDrawerImageSlot) => vue.VNodeChild) | undefined;
        } | undefined;
    } & {
        "v-slot:default"?: false | (() => vue.VNodeChild) | undefined;
        "v-slot:prepend"?: false | (() => vue.VNodeChild) | undefined;
        "v-slot:append"?: false | (() => vue.VNodeChild) | undefined;
        "v-slot:image"?: false | ((arg: VNavigationDrawerImageSlot) => vue.VNodeChild) | undefined;
    } & {
        "onUpdate:modelValue"?: ((val: boolean) => any) | undefined;
        "onUpdate:rail"?: ((val: boolean) => any) | undefined;
    }, {
        isStuck: vue.ShallowRef<boolean | "top" | "bottom">;
    }, {}, {}, {}, {
        style: vue.StyleValue;
        width: string | number;
        tag: string;
        mobile: NonNullable<boolean | null> | null;
        order: string | number;
        absolute: boolean;
        sticky: boolean;
        modelValue: boolean | null;
        rounded: string | number | boolean;
        tile: boolean;
        floating: boolean;
        location: "left" | "right" | "end" | "top" | "bottom" | "start";
        persistent: boolean;
        scrim: string | boolean;
        touchless: boolean;
        disableResizeWatcher: boolean;
        disableRouteWatcher: boolean;
        expandOnHover: boolean;
        permanent: boolean;
        rail: boolean | null;
        railWidth: string | number;
        temporary: boolean;
    }>;
    __isFragment?: undefined;
    __isTeleport?: undefined;
    __isSuspense?: undefined;
} & vue.ComponentOptionsBase<{
    style: vue.StyleValue;
    width: string | number;
    tag: string;
    mobile: NonNullable<boolean | null> | null;
    order: string | number;
    absolute: boolean;
    sticky: boolean;
    modelValue: boolean | null;
    tile: boolean;
    floating: boolean;
    location: "left" | "right" | "end" | "top" | "bottom" | "start";
    persistent: boolean;
    scrim: string | boolean;
    touchless: boolean;
    disableResizeWatcher: boolean;
    disableRouteWatcher: boolean;
    expandOnHover: boolean;
    permanent: boolean;
    rail: boolean | null;
    railWidth: string | number;
    temporary: boolean;
} & {
    class?: any;
    image?: string | undefined;
    theme?: string | undefined;
    color?: string | undefined;
    name?: string | undefined;
    mobileBreakpoint?: number | DisplayBreakpoint | undefined;
    border?: string | number | boolean | undefined;
    rounded?: string | number | boolean | undefined;
    elevation?: string | number | undefined;
    closeDelay?: string | number | undefined;
    openDelay?: string | number | undefined;
} & {
    $children?: vue.VNodeChild | (() => vue.VNodeChild) | {
        default?: (() => vue.VNodeChild) | undefined;
        prepend?: (() => vue.VNodeChild) | undefined;
        append?: (() => vue.VNodeChild) | undefined;
        image?: ((arg: VNavigationDrawerImageSlot) => vue.VNodeChild) | undefined;
    };
    'v-slots'?: {
        default?: false | (() => vue.VNodeChild) | undefined;
        prepend?: false | (() => vue.VNodeChild) | undefined;
        append?: false | (() => vue.VNodeChild) | undefined;
        image?: false | ((arg: VNavigationDrawerImageSlot) => vue.VNodeChild) | undefined;
    } | undefined;
} & {
    "v-slot:default"?: false | (() => vue.VNodeChild) | undefined;
    "v-slot:prepend"?: false | (() => vue.VNodeChild) | undefined;
    "v-slot:append"?: false | (() => vue.VNodeChild) | undefined;
    "v-slot:image"?: false | ((arg: VNavigationDrawerImageSlot) => vue.VNodeChild) | undefined;
} & {
    "onUpdate:modelValue"?: ((val: boolean) => any) | undefined;
    "onUpdate:rail"?: ((val: boolean) => any) | undefined;
}, {
    isStuck: vue.ShallowRef<boolean | "top" | "bottom">;
}, unknown, {}, {}, vue.ComponentOptionsMixin, vue.ComponentOptionsMixin, {
    'update:modelValue': (val: boolean) => true;
    'update:rail': (val: boolean) => true;
}, string, {
    style: vue.StyleValue;
    width: string | number;
    tag: string;
    mobile: NonNullable<boolean | null> | null;
    order: string | number;
    absolute: boolean;
    sticky: boolean;
    modelValue: boolean | null;
    rounded: string | number | boolean;
    tile: boolean;
    floating: boolean;
    location: "left" | "right" | "end" | "top" | "bottom" | "start";
    persistent: boolean;
    scrim: string | boolean;
    touchless: boolean;
    disableResizeWatcher: boolean;
    disableRouteWatcher: boolean;
    expandOnHover: boolean;
    permanent: boolean;
    rail: boolean | null;
    railWidth: string | number;
    temporary: boolean;
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
    image: (arg: VNavigationDrawerImageSlot) => vue.VNode<vue.RendererNode, vue.RendererElement, {
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
    rounded: {
        type: (StringConstructor | NumberConstructor | BooleanConstructor)[];
        default: undefined;
    };
    tile: BooleanConstructor;
    name: {
        type: StringConstructor;
    };
    order: {
        type: (StringConstructor | NumberConstructor)[];
        default: number;
    };
    absolute: BooleanConstructor;
    elevation: {
        type: (StringConstructor | NumberConstructor)[];
        validator(v: any): boolean;
    };
    mobile: Omit<{
        type: PropType<boolean | null>;
        default: boolean;
    }, "default" | "type"> & {
        type: PropType<NonNullable<boolean | null> | null>;
        default: NonNullable<boolean | null> | null;
    };
    mobileBreakpoint: PropType<number | DisplayBreakpoint>;
    closeDelay: (StringConstructor | NumberConstructor)[];
    openDelay: (StringConstructor | NumberConstructor)[];
    class: PropType<any>;
    style: {
        type: PropType<vue.StyleValue>;
        default: null;
    };
    border: (StringConstructor | NumberConstructor | BooleanConstructor)[];
    color: StringConstructor;
    disableResizeWatcher: BooleanConstructor;
    disableRouteWatcher: BooleanConstructor;
    expandOnHover: BooleanConstructor;
    floating: BooleanConstructor;
    modelValue: {
        type: PropType<boolean | null>;
        default: null;
    };
    permanent: BooleanConstructor;
    rail: {
        type: PropType<boolean | null>;
        default: null;
    };
    railWidth: {
        type: (StringConstructor | NumberConstructor)[];
        default: number;
    };
    scrim: {
        type: (StringConstructor | BooleanConstructor)[];
        default: boolean;
    };
    image: StringConstructor;
    temporary: BooleanConstructor;
    persistent: BooleanConstructor;
    touchless: BooleanConstructor;
    width: {
        type: (StringConstructor | NumberConstructor)[];
        default: number;
    };
    location: {
        type: PropType<"left" | "right" | "end" | "top" | "bottom" | "start">;
        default: string;
        validator: (value: any) => boolean;
    };
    sticky: BooleanConstructor;
}, vue.ExtractPropTypes<{
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
    name: {
        type: StringConstructor;
    };
    order: {
        type: (StringConstructor | NumberConstructor)[];
        default: number;
    };
    absolute: BooleanConstructor;
    elevation: {
        type: (StringConstructor | NumberConstructor)[];
        validator(v: any): boolean;
    };
    mobile: Omit<{
        type: PropType<boolean | null>;
        default: boolean;
    }, "default" | "type"> & {
        type: PropType<NonNullable<boolean | null> | null>;
        default: NonNullable<boolean | null> | null;
    };
    mobileBreakpoint: PropType<number | DisplayBreakpoint>;
    closeDelay: (StringConstructor | NumberConstructor)[];
    openDelay: (StringConstructor | NumberConstructor)[];
    class: PropType<any>;
    style: {
        type: PropType<vue.StyleValue>;
        default: null;
    };
    border: (StringConstructor | NumberConstructor | BooleanConstructor)[];
    color: StringConstructor;
    disableResizeWatcher: BooleanConstructor;
    disableRouteWatcher: BooleanConstructor;
    expandOnHover: BooleanConstructor;
    floating: BooleanConstructor;
    modelValue: {
        type: PropType<boolean | null>;
        default: null;
    };
    permanent: BooleanConstructor;
    rail: {
        type: PropType<boolean | null>;
        default: null;
    };
    railWidth: {
        type: (StringConstructor | NumberConstructor)[];
        default: number;
    };
    scrim: {
        type: (StringConstructor | BooleanConstructor)[];
        default: boolean;
    };
    image: StringConstructor;
    temporary: BooleanConstructor;
    persistent: BooleanConstructor;
    touchless: BooleanConstructor;
    width: {
        type: (StringConstructor | NumberConstructor)[];
        default: number;
    };
    location: {
        type: PropType<"left" | "right" | "end" | "top" | "bottom" | "start">;
        default: string;
        validator: (value: any) => boolean;
    };
    sticky: BooleanConstructor;
}>>;
type VNavigationDrawer = InstanceType<typeof VNavigationDrawer>;

export { VNavigationDrawer };
