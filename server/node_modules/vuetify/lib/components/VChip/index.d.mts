import * as vue from 'vue';
import { ComponentPropsOptions, ExtractPropTypes, JSXComponent, PropType } from 'vue';
// @ts-ignore
import * as vue_router from 'vue-router';

interface FilterPropsOptions<PropsOptions extends Readonly<ComponentPropsOptions>, Props = ExtractPropTypes<PropsOptions>> {
    filterProps<T extends Partial<Props>, U extends Exclude<keyof Props, Exclude<keyof Props, keyof T>>>(props: T): Partial<Pick<T, U>>;
}

type Density = null | 'default' | 'comfortable' | 'compact';

type IconValue = string | (string | [path: string, opacity: number])[] | JSXComponent;
declare const IconValue: PropType<IconValue>;

declare const VChip: {
    new (...args: any[]): vue.CreateComponentPublicInstance<{
        filter: boolean;
        replace: boolean;
        style: vue.StyleValue;
        size: string | number;
        label: boolean;
        disabled: boolean;
        tag: string;
        modelValue: boolean;
        variant: NonNullable<"flat" | "text" | "elevated" | "tonal" | "outlined" | "plain">;
        exact: boolean;
        tile: boolean;
        draggable: boolean;
        density: Density;
        ripple: boolean | {
            class: string;
        } | undefined;
        closable: boolean;
        closeIcon: IconValue;
        closeLabel: string;
        filterIcon: string;
        pill: boolean;
    } & {
        link?: boolean | undefined;
        onClick?: ((args_0: MouseEvent) => void) | undefined;
        class?: any;
        text?: string | undefined;
        value?: any;
        theme?: string | undefined;
        href?: string | undefined;
        color?: string | undefined;
        to?: vue_router.RouteLocationRaw | undefined;
        border?: string | number | boolean | undefined;
        rounded?: string | number | boolean | undefined;
        onClickOnce?: ((args_0: MouseEvent) => void) | undefined;
        elevation?: string | number | undefined;
        selectedClass?: string | undefined;
        prependIcon?: IconValue | undefined;
        appendIcon?: IconValue | undefined;
        activeClass?: string | undefined;
        appendAvatar?: string | undefined;
        prependAvatar?: string | undefined;
    } & {
        $children?: vue.VNodeChild | {
            default?: ((arg: {
                isSelected: boolean | undefined;
                selectedClass: boolean | (string | undefined)[] | undefined;
                select: ((value: boolean) => void) | undefined;
                toggle: (() => void) | undefined;
                value: unknown;
                disabled: boolean;
            }) => vue.VNodeChild) | undefined;
            label?: (() => vue.VNodeChild) | undefined;
            prepend?: (() => vue.VNodeChild) | undefined;
            append?: (() => vue.VNodeChild) | undefined;
            close?: (() => vue.VNodeChild) | undefined;
            filter?: (() => vue.VNodeChild) | undefined;
        } | ((arg: {
            isSelected: boolean | undefined;
            selectedClass: boolean | (string | undefined)[] | undefined;
            select: ((value: boolean) => void) | undefined;
            toggle: (() => void) | undefined;
            value: unknown;
            disabled: boolean;
        }) => vue.VNodeChild);
        'v-slots'?: {
            default?: false | ((arg: {
                isSelected: boolean | undefined;
                selectedClass: boolean | (string | undefined)[] | undefined;
                select: ((value: boolean) => void) | undefined;
                toggle: (() => void) | undefined;
                value: unknown;
                disabled: boolean;
            }) => vue.VNodeChild) | undefined;
            label?: false | (() => vue.VNodeChild) | undefined;
            prepend?: false | (() => vue.VNodeChild) | undefined;
            append?: false | (() => vue.VNodeChild) | undefined;
            close?: false | (() => vue.VNodeChild) | undefined;
            filter?: false | (() => vue.VNodeChild) | undefined;
        } | undefined;
    } & {
        "v-slot:default"?: false | ((arg: {
            isSelected: boolean | undefined;
            selectedClass: boolean | (string | undefined)[] | undefined;
            select: ((value: boolean) => void) | undefined;
            toggle: (() => void) | undefined;
            value: unknown;
            disabled: boolean;
        }) => vue.VNodeChild) | undefined;
        "v-slot:label"?: false | (() => vue.VNodeChild) | undefined;
        "v-slot:prepend"?: false | (() => vue.VNodeChild) | undefined;
        "v-slot:append"?: false | (() => vue.VNodeChild) | undefined;
        "v-slot:close"?: false | (() => vue.VNodeChild) | undefined;
        "v-slot:filter"?: false | (() => vue.VNodeChild) | undefined;
    } & {
        onClick?: ((e: KeyboardEvent | MouseEvent) => any) | undefined;
        "onUpdate:modelValue"?: ((value: boolean) => any) | undefined;
        "onGroup:selected"?: ((val: {
            value: boolean;
        }) => any) | undefined;
        "onClick:close"?: ((e: MouseEvent) => any) | undefined;
    }, () => false | JSX.Element, unknown, {}, {}, vue.ComponentOptionsMixin, vue.ComponentOptionsMixin, {
        'click:close': (e: MouseEvent) => true;
        'update:modelValue': (value: boolean) => true;
        'group:selected': (val: {
            value: boolean;
        }) => true;
        click: (e: MouseEvent | KeyboardEvent) => true;
    }, vue.VNodeProps & vue.AllowedComponentProps & vue.ComponentCustomProps & {
        filter: boolean;
        replace: boolean;
        style: vue.StyleValue;
        size: string | number;
        label: boolean;
        disabled: boolean;
        tag: string;
        modelValue: boolean;
        variant: NonNullable<"flat" | "text" | "elevated" | "tonal" | "outlined" | "plain">;
        exact: boolean;
        tile: boolean;
        draggable: boolean;
        density: Density;
        ripple: boolean | {
            class: string;
        } | undefined;
        closable: boolean;
        closeIcon: IconValue;
        closeLabel: string;
        filterIcon: string;
        pill: boolean;
    } & {
        link?: boolean | undefined;
        onClick?: ((args_0: MouseEvent) => void) | undefined;
        class?: any;
        text?: string | undefined;
        value?: any;
        theme?: string | undefined;
        href?: string | undefined;
        color?: string | undefined;
        to?: vue_router.RouteLocationRaw | undefined;
        border?: string | number | boolean | undefined;
        rounded?: string | number | boolean | undefined;
        onClickOnce?: ((args_0: MouseEvent) => void) | undefined;
        elevation?: string | number | undefined;
        selectedClass?: string | undefined;
        prependIcon?: IconValue | undefined;
        appendIcon?: IconValue | undefined;
        activeClass?: string | undefined;
        appendAvatar?: string | undefined;
        prependAvatar?: string | undefined;
    } & {
        $children?: vue.VNodeChild | {
            default?: ((arg: {
                isSelected: boolean | undefined;
                selectedClass: boolean | (string | undefined)[] | undefined;
                select: ((value: boolean) => void) | undefined;
                toggle: (() => void) | undefined;
                value: unknown;
                disabled: boolean;
            }) => vue.VNodeChild) | undefined;
            label?: (() => vue.VNodeChild) | undefined;
            prepend?: (() => vue.VNodeChild) | undefined;
            append?: (() => vue.VNodeChild) | undefined;
            close?: (() => vue.VNodeChild) | undefined;
            filter?: (() => vue.VNodeChild) | undefined;
        } | ((arg: {
            isSelected: boolean | undefined;
            selectedClass: boolean | (string | undefined)[] | undefined;
            select: ((value: boolean) => void) | undefined;
            toggle: (() => void) | undefined;
            value: unknown;
            disabled: boolean;
        }) => vue.VNodeChild);
        'v-slots'?: {
            default?: false | ((arg: {
                isSelected: boolean | undefined;
                selectedClass: boolean | (string | undefined)[] | undefined;
                select: ((value: boolean) => void) | undefined;
                toggle: (() => void) | undefined;
                value: unknown;
                disabled: boolean;
            }) => vue.VNodeChild) | undefined;
            label?: false | (() => vue.VNodeChild) | undefined;
            prepend?: false | (() => vue.VNodeChild) | undefined;
            append?: false | (() => vue.VNodeChild) | undefined;
            close?: false | (() => vue.VNodeChild) | undefined;
            filter?: false | (() => vue.VNodeChild) | undefined;
        } | undefined;
    } & {
        "v-slot:default"?: false | ((arg: {
            isSelected: boolean | undefined;
            selectedClass: boolean | (string | undefined)[] | undefined;
            select: ((value: boolean) => void) | undefined;
            toggle: (() => void) | undefined;
            value: unknown;
            disabled: boolean;
        }) => vue.VNodeChild) | undefined;
        "v-slot:label"?: false | (() => vue.VNodeChild) | undefined;
        "v-slot:prepend"?: false | (() => vue.VNodeChild) | undefined;
        "v-slot:append"?: false | (() => vue.VNodeChild) | undefined;
        "v-slot:close"?: false | (() => vue.VNodeChild) | undefined;
        "v-slot:filter"?: false | (() => vue.VNodeChild) | undefined;
    } & {
        onClick?: ((e: KeyboardEvent | MouseEvent) => any) | undefined;
        "onUpdate:modelValue"?: ((value: boolean) => any) | undefined;
        "onGroup:selected"?: ((val: {
            value: boolean;
        }) => any) | undefined;
        "onClick:close"?: ((e: MouseEvent) => any) | undefined;
    }, {
        filter: boolean;
        replace: boolean;
        link: boolean;
        style: vue.StyleValue;
        size: string | number;
        label: boolean;
        disabled: boolean;
        tag: string;
        modelValue: boolean;
        rounded: string | number | boolean;
        variant: NonNullable<"flat" | "text" | "elevated" | "tonal" | "outlined" | "plain">;
        exact: boolean;
        tile: boolean;
        draggable: boolean;
        density: Density;
        ripple: boolean | {
            class: string;
        } | undefined;
        closable: boolean;
        closeIcon: IconValue;
        closeLabel: string;
        filterIcon: string;
        pill: boolean;
    }, true, {}, vue.SlotsType<Partial<{
        default: (arg: {
            isSelected: boolean | undefined;
            selectedClass: boolean | (string | undefined)[] | undefined;
            select: ((value: boolean) => void) | undefined;
            toggle: (() => void) | undefined;
            value: unknown;
            disabled: boolean;
        }) => vue.VNode<vue.RendererNode, vue.RendererElement, {
            [key: string]: any;
        }>[];
        label: () => vue.VNode<vue.RendererNode, vue.RendererElement, {
            [key: string]: any;
        }>[];
        prepend: () => vue.VNode<vue.RendererNode, vue.RendererElement, {
            [key: string]: any;
        }>[];
        append: () => vue.VNode<vue.RendererNode, vue.RendererElement, {
            [key: string]: any;
        }>[];
        close: () => vue.VNode<vue.RendererNode, vue.RendererElement, {
            [key: string]: any;
        }>[];
        filter: () => vue.VNode<vue.RendererNode, vue.RendererElement, {
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
        filter: boolean;
        replace: boolean;
        style: vue.StyleValue;
        size: string | number;
        label: boolean;
        disabled: boolean;
        tag: string;
        modelValue: boolean;
        variant: NonNullable<"flat" | "text" | "elevated" | "tonal" | "outlined" | "plain">;
        exact: boolean;
        tile: boolean;
        draggable: boolean;
        density: Density;
        ripple: boolean | {
            class: string;
        } | undefined;
        closable: boolean;
        closeIcon: IconValue;
        closeLabel: string;
        filterIcon: string;
        pill: boolean;
    } & {
        link?: boolean | undefined;
        onClick?: ((args_0: MouseEvent) => void) | undefined;
        class?: any;
        text?: string | undefined;
        value?: any;
        theme?: string | undefined;
        href?: string | undefined;
        color?: string | undefined;
        to?: vue_router.RouteLocationRaw | undefined;
        border?: string | number | boolean | undefined;
        rounded?: string | number | boolean | undefined;
        onClickOnce?: ((args_0: MouseEvent) => void) | undefined;
        elevation?: string | number | undefined;
        selectedClass?: string | undefined;
        prependIcon?: IconValue | undefined;
        appendIcon?: IconValue | undefined;
        activeClass?: string | undefined;
        appendAvatar?: string | undefined;
        prependAvatar?: string | undefined;
    } & {
        $children?: vue.VNodeChild | {
            default?: ((arg: {
                isSelected: boolean | undefined;
                selectedClass: boolean | (string | undefined)[] | undefined;
                select: ((value: boolean) => void) | undefined;
                toggle: (() => void) | undefined;
                value: unknown;
                disabled: boolean;
            }) => vue.VNodeChild) | undefined;
            label?: (() => vue.VNodeChild) | undefined;
            prepend?: (() => vue.VNodeChild) | undefined;
            append?: (() => vue.VNodeChild) | undefined;
            close?: (() => vue.VNodeChild) | undefined;
            filter?: (() => vue.VNodeChild) | undefined;
        } | ((arg: {
            isSelected: boolean | undefined;
            selectedClass: boolean | (string | undefined)[] | undefined;
            select: ((value: boolean) => void) | undefined;
            toggle: (() => void) | undefined;
            value: unknown;
            disabled: boolean;
        }) => vue.VNodeChild);
        'v-slots'?: {
            default?: false | ((arg: {
                isSelected: boolean | undefined;
                selectedClass: boolean | (string | undefined)[] | undefined;
                select: ((value: boolean) => void) | undefined;
                toggle: (() => void) | undefined;
                value: unknown;
                disabled: boolean;
            }) => vue.VNodeChild) | undefined;
            label?: false | (() => vue.VNodeChild) | undefined;
            prepend?: false | (() => vue.VNodeChild) | undefined;
            append?: false | (() => vue.VNodeChild) | undefined;
            close?: false | (() => vue.VNodeChild) | undefined;
            filter?: false | (() => vue.VNodeChild) | undefined;
        } | undefined;
    } & {
        "v-slot:default"?: false | ((arg: {
            isSelected: boolean | undefined;
            selectedClass: boolean | (string | undefined)[] | undefined;
            select: ((value: boolean) => void) | undefined;
            toggle: (() => void) | undefined;
            value: unknown;
            disabled: boolean;
        }) => vue.VNodeChild) | undefined;
        "v-slot:label"?: false | (() => vue.VNodeChild) | undefined;
        "v-slot:prepend"?: false | (() => vue.VNodeChild) | undefined;
        "v-slot:append"?: false | (() => vue.VNodeChild) | undefined;
        "v-slot:close"?: false | (() => vue.VNodeChild) | undefined;
        "v-slot:filter"?: false | (() => vue.VNodeChild) | undefined;
    } & {
        onClick?: ((e: KeyboardEvent | MouseEvent) => any) | undefined;
        "onUpdate:modelValue"?: ((value: boolean) => any) | undefined;
        "onGroup:selected"?: ((val: {
            value: boolean;
        }) => any) | undefined;
        "onClick:close"?: ((e: MouseEvent) => any) | undefined;
    }, () => false | JSX.Element, {}, {}, {}, {
        filter: boolean;
        replace: boolean;
        link: boolean;
        style: vue.StyleValue;
        size: string | number;
        label: boolean;
        disabled: boolean;
        tag: string;
        modelValue: boolean;
        rounded: string | number | boolean;
        variant: NonNullable<"flat" | "text" | "elevated" | "tonal" | "outlined" | "plain">;
        exact: boolean;
        tile: boolean;
        draggable: boolean;
        density: Density;
        ripple: boolean | {
            class: string;
        } | undefined;
        closable: boolean;
        closeIcon: IconValue;
        closeLabel: string;
        filterIcon: string;
        pill: boolean;
    }>;
    __isFragment?: undefined;
    __isTeleport?: undefined;
    __isSuspense?: undefined;
} & vue.ComponentOptionsBase<{
    filter: boolean;
    replace: boolean;
    style: vue.StyleValue;
    size: string | number;
    label: boolean;
    disabled: boolean;
    tag: string;
    modelValue: boolean;
    variant: NonNullable<"flat" | "text" | "elevated" | "tonal" | "outlined" | "plain">;
    exact: boolean;
    tile: boolean;
    draggable: boolean;
    density: Density;
    ripple: boolean | {
        class: string;
    } | undefined;
    closable: boolean;
    closeIcon: IconValue;
    closeLabel: string;
    filterIcon: string;
    pill: boolean;
} & {
    link?: boolean | undefined;
    onClick?: ((args_0: MouseEvent) => void) | undefined;
    class?: any;
    text?: string | undefined;
    value?: any;
    theme?: string | undefined;
    href?: string | undefined;
    color?: string | undefined;
    to?: vue_router.RouteLocationRaw | undefined;
    border?: string | number | boolean | undefined;
    rounded?: string | number | boolean | undefined;
    onClickOnce?: ((args_0: MouseEvent) => void) | undefined;
    elevation?: string | number | undefined;
    selectedClass?: string | undefined;
    prependIcon?: IconValue | undefined;
    appendIcon?: IconValue | undefined;
    activeClass?: string | undefined;
    appendAvatar?: string | undefined;
    prependAvatar?: string | undefined;
} & {
    $children?: vue.VNodeChild | {
        default?: ((arg: {
            isSelected: boolean | undefined;
            selectedClass: boolean | (string | undefined)[] | undefined;
            select: ((value: boolean) => void) | undefined;
            toggle: (() => void) | undefined;
            value: unknown;
            disabled: boolean;
        }) => vue.VNodeChild) | undefined;
        label?: (() => vue.VNodeChild) | undefined;
        prepend?: (() => vue.VNodeChild) | undefined;
        append?: (() => vue.VNodeChild) | undefined;
        close?: (() => vue.VNodeChild) | undefined;
        filter?: (() => vue.VNodeChild) | undefined;
    } | ((arg: {
        isSelected: boolean | undefined;
        selectedClass: boolean | (string | undefined)[] | undefined;
        select: ((value: boolean) => void) | undefined;
        toggle: (() => void) | undefined;
        value: unknown;
        disabled: boolean;
    }) => vue.VNodeChild);
    'v-slots'?: {
        default?: false | ((arg: {
            isSelected: boolean | undefined;
            selectedClass: boolean | (string | undefined)[] | undefined;
            select: ((value: boolean) => void) | undefined;
            toggle: (() => void) | undefined;
            value: unknown;
            disabled: boolean;
        }) => vue.VNodeChild) | undefined;
        label?: false | (() => vue.VNodeChild) | undefined;
        prepend?: false | (() => vue.VNodeChild) | undefined;
        append?: false | (() => vue.VNodeChild) | undefined;
        close?: false | (() => vue.VNodeChild) | undefined;
        filter?: false | (() => vue.VNodeChild) | undefined;
    } | undefined;
} & {
    "v-slot:default"?: false | ((arg: {
        isSelected: boolean | undefined;
        selectedClass: boolean | (string | undefined)[] | undefined;
        select: ((value: boolean) => void) | undefined;
        toggle: (() => void) | undefined;
        value: unknown;
        disabled: boolean;
    }) => vue.VNodeChild) | undefined;
    "v-slot:label"?: false | (() => vue.VNodeChild) | undefined;
    "v-slot:prepend"?: false | (() => vue.VNodeChild) | undefined;
    "v-slot:append"?: false | (() => vue.VNodeChild) | undefined;
    "v-slot:close"?: false | (() => vue.VNodeChild) | undefined;
    "v-slot:filter"?: false | (() => vue.VNodeChild) | undefined;
} & {
    onClick?: ((e: KeyboardEvent | MouseEvent) => any) | undefined;
    "onUpdate:modelValue"?: ((value: boolean) => any) | undefined;
    "onGroup:selected"?: ((val: {
        value: boolean;
    }) => any) | undefined;
    "onClick:close"?: ((e: MouseEvent) => any) | undefined;
}, () => false | JSX.Element, unknown, {}, {}, vue.ComponentOptionsMixin, vue.ComponentOptionsMixin, {
    'click:close': (e: MouseEvent) => true;
    'update:modelValue': (value: boolean) => true;
    'group:selected': (val: {
        value: boolean;
    }) => true;
    click: (e: MouseEvent | KeyboardEvent) => true;
}, string, {
    filter: boolean;
    replace: boolean;
    link: boolean;
    style: vue.StyleValue;
    size: string | number;
    label: boolean;
    disabled: boolean;
    tag: string;
    modelValue: boolean;
    rounded: string | number | boolean;
    variant: NonNullable<"flat" | "text" | "elevated" | "tonal" | "outlined" | "plain">;
    exact: boolean;
    tile: boolean;
    draggable: boolean;
    density: Density;
    ripple: boolean | {
        class: string;
    } | undefined;
    closable: boolean;
    closeIcon: IconValue;
    closeLabel: string;
    filterIcon: string;
    pill: boolean;
}, {}, string, vue.SlotsType<Partial<{
    default: (arg: {
        isSelected: boolean | undefined;
        selectedClass: boolean | (string | undefined)[] | undefined;
        select: ((value: boolean) => void) | undefined;
        toggle: (() => void) | undefined;
        value: unknown;
        disabled: boolean;
    }) => vue.VNode<vue.RendererNode, vue.RendererElement, {
        [key: string]: any;
    }>[];
    label: () => vue.VNode<vue.RendererNode, vue.RendererElement, {
        [key: string]: any;
    }>[];
    prepend: () => vue.VNode<vue.RendererNode, vue.RendererElement, {
        [key: string]: any;
    }>[];
    append: () => vue.VNode<vue.RendererNode, vue.RendererElement, {
        [key: string]: any;
    }>[];
    close: () => vue.VNode<vue.RendererNode, vue.RendererElement, {
        [key: string]: any;
    }>[];
    filter: () => vue.VNode<vue.RendererNode, vue.RendererElement, {
        [key: string]: any;
    }>[];
}>>> & vue.VNodeProps & vue.AllowedComponentProps & vue.ComponentCustomProps & FilterPropsOptions<{
    color: StringConstructor;
    variant: Omit<{
        type: PropType<"flat" | "text" | "elevated" | "tonal" | "outlined" | "plain">;
        default: string;
        validator: (v: any) => boolean;
    }, "default" | "type"> & {
        type: PropType<NonNullable<"flat" | "text" | "elevated" | "tonal" | "outlined" | "plain">>;
        default: NonNullable<"flat" | "text" | "elevated" | "tonal" | "outlined" | "plain">;
    };
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
    href: StringConstructor;
    replace: BooleanConstructor;
    to: PropType<vue_router.RouteLocationRaw>;
    exact: BooleanConstructor;
    rounded: {
        type: (StringConstructor | NumberConstructor | BooleanConstructor)[];
        default: undefined;
    };
    tile: BooleanConstructor;
    value: null;
    disabled: BooleanConstructor;
    selectedClass: StringConstructor;
    elevation: {
        type: (StringConstructor | NumberConstructor)[];
        validator(v: any): boolean;
    };
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
    border: (StringConstructor | NumberConstructor | BooleanConstructor)[];
    activeClass: StringConstructor;
    appendAvatar: StringConstructor;
    appendIcon: PropType<IconValue>;
    closable: BooleanConstructor;
    closeIcon: {
        type: PropType<IconValue>;
        default: string;
    };
    closeLabel: {
        type: StringConstructor;
        default: string;
    };
    draggable: BooleanConstructor;
    filter: BooleanConstructor;
    filterIcon: {
        type: StringConstructor;
        default: string;
    };
    label: BooleanConstructor;
    link: {
        type: BooleanConstructor;
        default: undefined;
    };
    pill: BooleanConstructor;
    prependAvatar: StringConstructor;
    prependIcon: PropType<IconValue>;
    ripple: {
        type: PropType<boolean | {
            class: string;
        } | undefined>;
        default: boolean;
    };
    text: StringConstructor;
    modelValue: {
        type: BooleanConstructor;
        default: boolean;
    };
    onClick: PropType<(args_0: MouseEvent) => void>;
    onClickOnce: PropType<(args_0: MouseEvent) => void>;
}, vue.ExtractPropTypes<{
    color: StringConstructor;
    variant: Omit<{
        type: PropType<"flat" | "text" | "elevated" | "tonal" | "outlined" | "plain">;
        default: string;
        validator: (v: any) => boolean;
    }, "default" | "type"> & {
        type: PropType<NonNullable<"flat" | "text" | "elevated" | "tonal" | "outlined" | "plain">>;
        default: NonNullable<"flat" | "text" | "elevated" | "tonal" | "outlined" | "plain">;
    };
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
    href: StringConstructor;
    replace: BooleanConstructor;
    to: PropType<vue_router.RouteLocationRaw>;
    exact: BooleanConstructor;
    rounded: {
        type: (StringConstructor | NumberConstructor | BooleanConstructor)[];
        default: undefined;
    };
    tile: BooleanConstructor;
    value: null;
    disabled: BooleanConstructor;
    selectedClass: StringConstructor;
    elevation: {
        type: (StringConstructor | NumberConstructor)[];
        validator(v: any): boolean;
    };
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
    border: (StringConstructor | NumberConstructor | BooleanConstructor)[];
    activeClass: StringConstructor;
    appendAvatar: StringConstructor;
    appendIcon: PropType<IconValue>;
    closable: BooleanConstructor;
    closeIcon: {
        type: PropType<IconValue>;
        default: string;
    };
    closeLabel: {
        type: StringConstructor;
        default: string;
    };
    draggable: BooleanConstructor;
    filter: BooleanConstructor;
    filterIcon: {
        type: StringConstructor;
        default: string;
    };
    label: BooleanConstructor;
    link: {
        type: BooleanConstructor;
        default: undefined;
    };
    pill: BooleanConstructor;
    prependAvatar: StringConstructor;
    prependIcon: PropType<IconValue>;
    ripple: {
        type: PropType<boolean | {
            class: string;
        } | undefined>;
        default: boolean;
    };
    text: StringConstructor;
    modelValue: {
        type: BooleanConstructor;
        default: boolean;
    };
    onClick: PropType<(args_0: MouseEvent) => void>;
    onClickOnce: PropType<(args_0: MouseEvent) => void>;
}>>;
type VChip = InstanceType<typeof VChip>;

export { VChip };
