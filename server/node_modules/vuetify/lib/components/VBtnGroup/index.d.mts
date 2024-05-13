import * as vue from 'vue';
import { ComponentPropsOptions, ExtractPropTypes } from 'vue';

interface FilterPropsOptions<PropsOptions extends Readonly<ComponentPropsOptions>, Props = ExtractPropTypes<PropsOptions>> {
    filterProps<T extends Partial<Props>, U extends Exclude<keyof Props, Exclude<keyof Props, keyof T>>>(props: T): Partial<Pick<T, U>>;
}

type Density = null | 'default' | 'comfortable' | 'compact';

declare const VBtnGroup: {
    new (...args: any[]): vue.CreateComponentPublicInstance<{
        style: vue.StyleValue;
        tag: string;
        variant: "flat" | "text" | "elevated" | "tonal" | "outlined" | "plain";
        tile: boolean;
        density: Density;
        divided: boolean;
    } & {
        class?: any;
        theme?: string | undefined;
        color?: string | undefined;
        border?: string | number | boolean | undefined;
        rounded?: string | number | boolean | undefined;
        elevation?: string | number | undefined;
        baseColor?: string | undefined;
    } & {
        $children?: vue.VNodeChild | {
            default?: (() => vue.VNodeChild) | undefined;
        } | (() => vue.VNodeChild);
        'v-slots'?: {
            default?: false | (() => vue.VNodeChild) | undefined;
        } | undefined;
    } & {
        "v-slot:default"?: false | (() => vue.VNodeChild) | undefined;
    }, void, unknown, {}, {}, vue.ComponentOptionsMixin, vue.ComponentOptionsMixin, Record<string, any>, vue.VNodeProps & vue.AllowedComponentProps & vue.ComponentCustomProps & {
        style: vue.StyleValue;
        tag: string;
        variant: "flat" | "text" | "elevated" | "tonal" | "outlined" | "plain";
        tile: boolean;
        density: Density;
        divided: boolean;
    } & {
        class?: any;
        theme?: string | undefined;
        color?: string | undefined;
        border?: string | number | boolean | undefined;
        rounded?: string | number | boolean | undefined;
        elevation?: string | number | undefined;
        baseColor?: string | undefined;
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
        tag: string;
        rounded: string | number | boolean;
        variant: "flat" | "text" | "elevated" | "tonal" | "outlined" | "plain";
        tile: boolean;
        density: Density;
        divided: boolean;
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
        tag: string;
        variant: "flat" | "text" | "elevated" | "tonal" | "outlined" | "plain";
        tile: boolean;
        density: Density;
        divided: boolean;
    } & {
        class?: any;
        theme?: string | undefined;
        color?: string | undefined;
        border?: string | number | boolean | undefined;
        rounded?: string | number | boolean | undefined;
        elevation?: string | number | undefined;
        baseColor?: string | undefined;
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
        tag: string;
        rounded: string | number | boolean;
        variant: "flat" | "text" | "elevated" | "tonal" | "outlined" | "plain";
        tile: boolean;
        density: Density;
        divided: boolean;
    }>;
    __isFragment?: undefined;
    __isTeleport?: undefined;
    __isSuspense?: undefined;
} & vue.ComponentOptionsBase<{
    style: vue.StyleValue;
    tag: string;
    variant: "flat" | "text" | "elevated" | "tonal" | "outlined" | "plain";
    tile: boolean;
    density: Density;
    divided: boolean;
} & {
    class?: any;
    theme?: string | undefined;
    color?: string | undefined;
    border?: string | number | boolean | undefined;
    rounded?: string | number | boolean | undefined;
    elevation?: string | number | undefined;
    baseColor?: string | undefined;
} & {
    $children?: vue.VNodeChild | {
        default?: (() => vue.VNodeChild) | undefined;
    } | (() => vue.VNodeChild);
    'v-slots'?: {
        default?: false | (() => vue.VNodeChild) | undefined;
    } | undefined;
} & {
    "v-slot:default"?: false | (() => vue.VNodeChild) | undefined;
}, void, unknown, {}, {}, vue.ComponentOptionsMixin, vue.ComponentOptionsMixin, Record<string, any>, string, {
    style: vue.StyleValue;
    tag: string;
    rounded: string | number | boolean;
    variant: "flat" | "text" | "elevated" | "tonal" | "outlined" | "plain";
    tile: boolean;
    density: Density;
    divided: boolean;
}, {}, string, vue.SlotsType<Partial<{
    default: () => vue.VNode<vue.RendererNode, vue.RendererElement, {
        [key: string]: any;
    }>[];
}>>> & vue.VNodeProps & vue.AllowedComponentProps & vue.ComponentCustomProps & FilterPropsOptions<{
    color: StringConstructor;
    variant: {
        type: vue.PropType<"flat" | "text" | "elevated" | "tonal" | "outlined" | "plain">;
        default: string;
        validator: (v: any) => boolean;
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
    divided: BooleanConstructor;
}, vue.ExtractPropTypes<{
    color: StringConstructor;
    variant: {
        type: vue.PropType<"flat" | "text" | "elevated" | "tonal" | "outlined" | "plain">;
        default: string;
        validator: (v: any) => boolean;
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
    divided: BooleanConstructor;
}>>;
type VBtnGroup = InstanceType<typeof VBtnGroup>;

export { VBtnGroup };
