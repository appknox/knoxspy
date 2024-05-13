import * as vue from 'vue';
import { ComponentPropsOptions, ExtractPropTypes, VNodeChild, VNode, JSXComponent, PropType } from 'vue';
// @ts-ignore
import * as vue_router from 'vue-router';
// @ts-ignore
import { RouteLocationRaw } from 'vue-router';

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

type IconValue = string | (string | [path: string, opacity: number])[] | JSXComponent;
declare const IconValue: PropType<IconValue>;

interface LinkProps {
    href: string | undefined;
    replace: boolean | undefined;
    to: RouteLocationRaw | undefined;
    exact: boolean | undefined;
}

type InternalBreadcrumbItem = Partial<LinkProps> & {
    title: string;
    disabled?: boolean;
};
type BreadcrumbItem = string | InternalBreadcrumbItem;
declare const VBreadcrumbs: {
    new (...args: any[]): vue.CreateComponentPublicInstance<{
        style: vue.StyleValue;
        disabled: boolean;
        tag: string;
        divider: string;
        tile: boolean;
        density: Density;
    } & {
        class?: any;
        color?: string | undefined;
        icon?: IconValue | undefined;
        rounded?: string | number | boolean | undefined;
        bgColor?: string | undefined;
        activeClass?: string | undefined;
        activeColor?: string | undefined;
    }, {}, unknown, {}, {}, vue.ComponentOptionsMixin, vue.ComponentOptionsMixin, Omit<Record<string, any>, "v-slot:default" | "$children" | "v-slots" | "items" | "v-slot:title" | "v-slot:prepend" | "v-slot:divider" | "v-slot:item">, vue.VNodeProps & vue.AllowedComponentProps & vue.ComponentCustomProps & {
        style: vue.StyleValue;
        disabled: boolean;
        tag: string;
        divider: string;
        tile: boolean;
        density: Density;
    } & {
        class?: any;
        color?: string | undefined;
        icon?: IconValue | undefined;
        rounded?: string | number | boolean | undefined;
        bgColor?: string | undefined;
        activeClass?: string | undefined;
        activeColor?: string | undefined;
    }, {
        style: vue.StyleValue;
        disabled: boolean;
        tag: string;
        divider: string;
        rounded: string | number | boolean;
        tile: boolean;
        density: Density;
    }, true, {}, vue.SlotsType<Partial<{
        prepend: () => vue.VNode<vue.RendererNode, vue.RendererElement, {
            [key: string]: any;
        }>[];
        title: (arg: {
            item: InternalBreadcrumbItem;
            index: number;
        }) => vue.VNode<vue.RendererNode, vue.RendererElement, {
            [key: string]: any;
        }>[];
        divider: (arg: {
            item: BreadcrumbItem;
            index: number;
        }) => vue.VNode<vue.RendererNode, vue.RendererElement, {
            [key: string]: any;
        }>[];
        item: (arg: {
            item: InternalBreadcrumbItem;
            index: number;
        }) => vue.VNode<vue.RendererNode, vue.RendererElement, {
            [key: string]: any;
        }>[];
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
        disabled: boolean;
        tag: string;
        divider: string;
        tile: boolean;
        density: Density;
    } & {
        class?: any;
        color?: string | undefined;
        icon?: IconValue | undefined;
        rounded?: string | number | boolean | undefined;
        bgColor?: string | undefined;
        activeClass?: string | undefined;
        activeColor?: string | undefined;
    }, {}, {}, {}, {}, {
        style: vue.StyleValue;
        disabled: boolean;
        tag: string;
        divider: string;
        rounded: string | number | boolean;
        tile: boolean;
        density: Density;
    }>;
    __isFragment?: undefined;
    __isTeleport?: undefined;
    __isSuspense?: undefined;
} & vue.ComponentOptionsBase<{
    style: vue.StyleValue;
    disabled: boolean;
    tag: string;
    divider: string;
    tile: boolean;
    density: Density;
} & {
    class?: any;
    color?: string | undefined;
    icon?: IconValue | undefined;
    rounded?: string | number | boolean | undefined;
    bgColor?: string | undefined;
    activeClass?: string | undefined;
    activeColor?: string | undefined;
}, {}, unknown, {}, {}, vue.ComponentOptionsMixin, vue.ComponentOptionsMixin, Omit<Record<string, any>, "v-slot:default" | "$children" | "v-slots" | "items" | "v-slot:title" | "v-slot:prepend" | "v-slot:divider" | "v-slot:item">, string, {
    style: vue.StyleValue;
    disabled: boolean;
    tag: string;
    divider: string;
    rounded: string | number | boolean;
    tile: boolean;
    density: Density;
}, {}, string, vue.SlotsType<Partial<{
    prepend: () => vue.VNode<vue.RendererNode, vue.RendererElement, {
        [key: string]: any;
    }>[];
    title: (arg: {
        item: InternalBreadcrumbItem;
        index: number;
    }) => vue.VNode<vue.RendererNode, vue.RendererElement, {
        [key: string]: any;
    }>[];
    divider: (arg: {
        item: BreadcrumbItem;
        index: number;
    }) => vue.VNode<vue.RendererNode, vue.RendererElement, {
        [key: string]: any;
    }>[];
    item: (arg: {
        item: InternalBreadcrumbItem;
        index: number;
    }) => vue.VNode<vue.RendererNode, vue.RendererElement, {
        [key: string]: any;
    }>[];
    default: () => vue.VNode<vue.RendererNode, vue.RendererElement, {
        [key: string]: any;
    }>[];
}>>> & vue.VNodeProps & vue.AllowedComponentProps & vue.ComponentCustomProps & (new <T extends BreadcrumbItem>(props: {
    items?: T[] | undefined;
}, slots: {
    prepend: never;
    title: {
        item: InternalBreadcrumbItem;
        index: number;
    };
    divider: {
        item: T;
        index: number;
    };
    item: {
        item: InternalBreadcrumbItem;
        index: number;
    };
    default: never;
}) => GenericProps<{
    items?: T[] | undefined;
}, {
    prepend: never;
    title: {
        item: InternalBreadcrumbItem;
        index: number;
    };
    divider: {
        item: T;
        index: number;
    };
    item: {
        item: InternalBreadcrumbItem;
        index: number;
    };
    default: never;
}>) & FilterPropsOptions<{
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
    density: {
        type: PropType<Density>;
        default: string;
        validator: (v: any) => boolean;
    };
    class: PropType<any>;
    style: {
        type: PropType<vue.StyleValue>;
        default: null;
    };
    activeClass: StringConstructor;
    activeColor: StringConstructor;
    bgColor: StringConstructor;
    color: StringConstructor;
    disabled: BooleanConstructor;
    divider: {
        type: StringConstructor;
        default: string;
    };
    icon: PropType<IconValue>;
    items: {
        type: PropType<readonly BreadcrumbItem[]>;
        default: () => never[];
    };
}, vue.ExtractPropTypes<{
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
    density: {
        type: PropType<Density>;
        default: string;
        validator: (v: any) => boolean;
    };
    class: PropType<any>;
    style: {
        type: PropType<vue.StyleValue>;
        default: null;
    };
    activeClass: StringConstructor;
    activeColor: StringConstructor;
    bgColor: StringConstructor;
    color: StringConstructor;
    disabled: BooleanConstructor;
    divider: {
        type: StringConstructor;
        default: string;
    };
    icon: PropType<IconValue>;
    items: {
        type: PropType<readonly BreadcrumbItem[]>;
        default: () => never[];
    };
}>>;
type VBreadcrumbs = InstanceType<typeof VBreadcrumbs>;

declare const VBreadcrumbsItem: {
    new (...args: any[]): vue.CreateComponentPublicInstance<{
        replace: boolean;
        style: vue.StyleValue;
        active: boolean;
        disabled: boolean;
        tag: string;
        exact: boolean;
    } & {
        class?: any;
        title?: string | undefined;
        href?: string | undefined;
        color?: string | undefined;
        to?: vue_router.RouteLocationRaw | undefined;
        activeClass?: string | undefined;
        activeColor?: string | undefined;
    } & {
        $children?: vue.VNodeChild | {
            default?: (() => vue.VNodeChild) | undefined;
        } | (() => vue.VNodeChild);
        'v-slots'?: {
            default?: false | (() => vue.VNodeChild) | undefined;
        } | undefined;
    } & {
        "v-slot:default"?: false | (() => vue.VNodeChild) | undefined;
    }, {}, unknown, {}, {}, vue.ComponentOptionsMixin, vue.ComponentOptionsMixin, Record<string, any>, vue.VNodeProps & vue.AllowedComponentProps & vue.ComponentCustomProps & {
        replace: boolean;
        style: vue.StyleValue;
        active: boolean;
        disabled: boolean;
        tag: string;
        exact: boolean;
    } & {
        class?: any;
        title?: string | undefined;
        href?: string | undefined;
        color?: string | undefined;
        to?: vue_router.RouteLocationRaw | undefined;
        activeClass?: string | undefined;
        activeColor?: string | undefined;
    } & {
        $children?: vue.VNodeChild | {
            default?: (() => vue.VNodeChild) | undefined;
        } | (() => vue.VNodeChild);
        'v-slots'?: {
            default?: false | (() => vue.VNodeChild) | undefined;
        } | undefined;
    } & {
        "v-slot:default"?: false | (() => vue.VNodeChild) | undefined;
    }, {
        replace: boolean;
        style: vue.StyleValue;
        active: boolean;
        disabled: boolean;
        tag: string;
        exact: boolean;
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
        replace: boolean;
        style: vue.StyleValue;
        active: boolean;
        disabled: boolean;
        tag: string;
        exact: boolean;
    } & {
        class?: any;
        title?: string | undefined;
        href?: string | undefined;
        color?: string | undefined;
        to?: vue_router.RouteLocationRaw | undefined;
        activeClass?: string | undefined;
        activeColor?: string | undefined;
    } & {
        $children?: vue.VNodeChild | {
            default?: (() => vue.VNodeChild) | undefined;
        } | (() => vue.VNodeChild);
        'v-slots'?: {
            default?: false | (() => vue.VNodeChild) | undefined;
        } | undefined;
    } & {
        "v-slot:default"?: false | (() => vue.VNodeChild) | undefined;
    }, {}, {}, {}, {}, {
        replace: boolean;
        style: vue.StyleValue;
        active: boolean;
        disabled: boolean;
        tag: string;
        exact: boolean;
    }>;
    __isFragment?: undefined;
    __isTeleport?: undefined;
    __isSuspense?: undefined;
} & vue.ComponentOptionsBase<{
    replace: boolean;
    style: vue.StyleValue;
    active: boolean;
    disabled: boolean;
    tag: string;
    exact: boolean;
} & {
    class?: any;
    title?: string | undefined;
    href?: string | undefined;
    color?: string | undefined;
    to?: vue_router.RouteLocationRaw | undefined;
    activeClass?: string | undefined;
    activeColor?: string | undefined;
} & {
    $children?: vue.VNodeChild | {
        default?: (() => vue.VNodeChild) | undefined;
    } | (() => vue.VNodeChild);
    'v-slots'?: {
        default?: false | (() => vue.VNodeChild) | undefined;
    } | undefined;
} & {
    "v-slot:default"?: false | (() => vue.VNodeChild) | undefined;
}, {}, unknown, {}, {}, vue.ComponentOptionsMixin, vue.ComponentOptionsMixin, Record<string, any>, string, {
    replace: boolean;
    style: vue.StyleValue;
    active: boolean;
    disabled: boolean;
    tag: string;
    exact: boolean;
}, {}, string, vue.SlotsType<Partial<{
    default: () => vue.VNode<vue.RendererNode, vue.RendererElement, {
        [key: string]: any;
    }>[];
}>>> & vue.VNodeProps & vue.AllowedComponentProps & vue.ComponentCustomProps & FilterPropsOptions<{
    tag: Omit<{
        type: StringConstructor;
        default: string;
    }, "default" | "type"> & {
        type: vue.PropType<string>;
        default: string;
    };
    href: StringConstructor;
    replace: BooleanConstructor;
    to: vue.PropType<vue_router.RouteLocationRaw>;
    exact: BooleanConstructor;
    class: vue.PropType<any>;
    style: {
        type: vue.PropType<vue.StyleValue>;
        default: null;
    };
    active: BooleanConstructor;
    activeClass: StringConstructor;
    activeColor: StringConstructor;
    color: StringConstructor;
    disabled: BooleanConstructor;
    title: StringConstructor;
}, vue.ExtractPropTypes<{
    tag: Omit<{
        type: StringConstructor;
        default: string;
    }, "default" | "type"> & {
        type: vue.PropType<string>;
        default: string;
    };
    href: StringConstructor;
    replace: BooleanConstructor;
    to: vue.PropType<vue_router.RouteLocationRaw>;
    exact: BooleanConstructor;
    class: vue.PropType<any>;
    style: {
        type: vue.PropType<vue.StyleValue>;
        default: null;
    };
    active: BooleanConstructor;
    activeClass: StringConstructor;
    activeColor: StringConstructor;
    color: StringConstructor;
    disabled: BooleanConstructor;
    title: StringConstructor;
}>>;
type VBreadcrumbsItem = InstanceType<typeof VBreadcrumbsItem>;

declare const VBreadcrumbsDivider: {
    new (...args: any[]): vue.CreateComponentPublicInstance<{
        style: vue.StyleValue;
    } & {
        class?: any;
        divider?: string | number | undefined;
    } & {
        $children?: vue.VNodeChild | {
            default?: (() => vue.VNodeChild) | undefined;
        } | (() => vue.VNodeChild);
        'v-slots'?: {
            default?: false | (() => vue.VNodeChild) | undefined;
        } | undefined;
    } & {
        "v-slot:default"?: false | (() => vue.VNodeChild) | undefined;
    }, {}, unknown, {}, {}, vue.ComponentOptionsMixin, vue.ComponentOptionsMixin, Record<string, any>, vue.VNodeProps & vue.AllowedComponentProps & vue.ComponentCustomProps & {
        style: vue.StyleValue;
    } & {
        class?: any;
        divider?: string | number | undefined;
    } & {
        $children?: vue.VNodeChild | {
            default?: (() => vue.VNodeChild) | undefined;
        } | (() => vue.VNodeChild);
        'v-slots'?: {
            default?: false | (() => vue.VNodeChild) | undefined;
        } | undefined;
    } & {
        "v-slot:default"?: false | (() => vue.VNodeChild) | undefined;
    }, {
        style: vue.StyleValue;
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
    } & {
        class?: any;
        divider?: string | number | undefined;
    } & {
        $children?: vue.VNodeChild | {
            default?: (() => vue.VNodeChild) | undefined;
        } | (() => vue.VNodeChild);
        'v-slots'?: {
            default?: false | (() => vue.VNodeChild) | undefined;
        } | undefined;
    } & {
        "v-slot:default"?: false | (() => vue.VNodeChild) | undefined;
    }, {}, {}, {}, {}, {
        style: vue.StyleValue;
    }>;
    __isFragment?: undefined;
    __isTeleport?: undefined;
    __isSuspense?: undefined;
} & vue.ComponentOptionsBase<{
    style: vue.StyleValue;
} & {
    class?: any;
    divider?: string | number | undefined;
} & {
    $children?: vue.VNodeChild | {
        default?: (() => vue.VNodeChild) | undefined;
    } | (() => vue.VNodeChild);
    'v-slots'?: {
        default?: false | (() => vue.VNodeChild) | undefined;
    } | undefined;
} & {
    "v-slot:default"?: false | (() => vue.VNodeChild) | undefined;
}, {}, unknown, {}, {}, vue.ComponentOptionsMixin, vue.ComponentOptionsMixin, Record<string, any>, string, {
    style: vue.StyleValue;
}, {}, string, vue.SlotsType<Partial<{
    default: () => vue.VNode<vue.RendererNode, vue.RendererElement, {
        [key: string]: any;
    }>[];
}>>> & vue.VNodeProps & vue.AllowedComponentProps & vue.ComponentCustomProps & FilterPropsOptions<{
    class: vue.PropType<any>;
    style: {
        type: vue.PropType<vue.StyleValue>;
        default: null;
    };
    divider: (StringConstructor | NumberConstructor)[];
}, vue.ExtractPropTypes<{
    class: vue.PropType<any>;
    style: {
        type: vue.PropType<vue.StyleValue>;
        default: null;
    };
    divider: (StringConstructor | NumberConstructor)[];
}>>;
type VBreadcrumbsDivider = InstanceType<typeof VBreadcrumbsDivider>;

export { VBreadcrumbs, VBreadcrumbsDivider, VBreadcrumbsItem };
