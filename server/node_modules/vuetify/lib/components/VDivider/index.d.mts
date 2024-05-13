import * as vue from 'vue';
import { ComponentPropsOptions, ExtractPropTypes } from 'vue';

interface FilterPropsOptions<PropsOptions extends Readonly<ComponentPropsOptions>, Props = ExtractPropTypes<PropsOptions>> {
    filterProps<T extends Partial<Props>, U extends Exclude<keyof Props, Exclude<keyof Props, keyof T>>>(props: T): Partial<Pick<T, U>>;
}

declare const VDivider: {
    new (...args: any[]): vue.CreateComponentPublicInstance<{
        style: vue.StyleValue;
        inset: boolean;
        vertical: boolean;
    } & {
        length?: string | number | undefined;
        class?: any;
        theme?: string | undefined;
        color?: string | undefined;
        opacity?: string | number | undefined;
        thickness?: string | number | undefined;
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
        inset: boolean;
        vertical: boolean;
    } & {
        length?: string | number | undefined;
        class?: any;
        theme?: string | undefined;
        color?: string | undefined;
        opacity?: string | number | undefined;
        thickness?: string | number | undefined;
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
        inset: boolean;
        vertical: boolean;
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
        inset: boolean;
        vertical: boolean;
    } & {
        length?: string | number | undefined;
        class?: any;
        theme?: string | undefined;
        color?: string | undefined;
        opacity?: string | number | undefined;
        thickness?: string | number | undefined;
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
        inset: boolean;
        vertical: boolean;
    }>;
    __isFragment?: undefined;
    __isTeleport?: undefined;
    __isSuspense?: undefined;
} & vue.ComponentOptionsBase<{
    style: vue.StyleValue;
    inset: boolean;
    vertical: boolean;
} & {
    length?: string | number | undefined;
    class?: any;
    theme?: string | undefined;
    color?: string | undefined;
    opacity?: string | number | undefined;
    thickness?: string | number | undefined;
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
    inset: boolean;
    vertical: boolean;
}, {}, string, vue.SlotsType<Partial<{
    default: () => vue.VNode<vue.RendererNode, vue.RendererElement, {
        [key: string]: any;
    }>[];
}>>> & vue.VNodeProps & vue.AllowedComponentProps & vue.ComponentCustomProps & FilterPropsOptions<{
    theme: StringConstructor;
    class: vue.PropType<any>;
    style: {
        type: vue.PropType<vue.StyleValue>;
        default: null;
    };
    color: StringConstructor;
    inset: BooleanConstructor;
    length: (StringConstructor | NumberConstructor)[];
    opacity: (StringConstructor | NumberConstructor)[];
    thickness: (StringConstructor | NumberConstructor)[];
    vertical: BooleanConstructor;
}, vue.ExtractPropTypes<{
    theme: StringConstructor;
    class: vue.PropType<any>;
    style: {
        type: vue.PropType<vue.StyleValue>;
        default: null;
    };
    color: StringConstructor;
    inset: BooleanConstructor;
    length: (StringConstructor | NumberConstructor)[];
    opacity: (StringConstructor | NumberConstructor)[];
    thickness: (StringConstructor | NumberConstructor)[];
    vertical: BooleanConstructor;
}>>;
type VDivider = InstanceType<typeof VDivider>;

export { VDivider };
