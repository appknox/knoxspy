import * as vue from 'vue';
import { ComponentPropsOptions, ExtractPropTypes, Component, PropType } from 'vue';

interface FilterPropsOptions<PropsOptions extends Readonly<ComponentPropsOptions>, Props = ExtractPropTypes<PropsOptions>> {
    filterProps<T extends Partial<Props>, U extends Exclude<keyof Props, Exclude<keyof Props, keyof T>>>(props: T): Partial<Pick<T, U>>;
}

type VMessageSlot = {
    message: string;
};
declare const VMessages: {
    new (...args: any[]): vue.CreateComponentPublicInstance<{
        style: vue.StyleValue;
        active: boolean;
        messages: string | readonly string[];
        transition: {
            component: Component;
            leaveAbsolute: boolean;
            group: boolean;
        } | NonNullable<string | boolean | (vue.TransitionProps & {
            component?: Component | undefined;
        })>;
    } & {
        class?: any;
        color?: string | undefined;
    } & {
        $children?: {} | vue.VNodeChild | {
            message?: ((arg: VMessageSlot) => vue.VNodeChild) | undefined;
        };
        'v-slots'?: {
            message?: false | ((arg: VMessageSlot) => vue.VNodeChild) | undefined;
        } | undefined;
    } & {
        "v-slot:message"?: false | ((arg: VMessageSlot) => vue.VNodeChild) | undefined;
    }, {}, unknown, {}, {}, vue.ComponentOptionsMixin, vue.ComponentOptionsMixin, Record<string, any>, vue.VNodeProps & vue.AllowedComponentProps & vue.ComponentCustomProps & {
        style: vue.StyleValue;
        active: boolean;
        messages: string | readonly string[];
        transition: {
            component: Component;
            leaveAbsolute: boolean;
            group: boolean;
        } | NonNullable<string | boolean | (vue.TransitionProps & {
            component?: Component | undefined;
        })>;
    } & {
        class?: any;
        color?: string | undefined;
    } & {
        $children?: {} | vue.VNodeChild | {
            message?: ((arg: VMessageSlot) => vue.VNodeChild) | undefined;
        };
        'v-slots'?: {
            message?: false | ((arg: VMessageSlot) => vue.VNodeChild) | undefined;
        } | undefined;
    } & {
        "v-slot:message"?: false | ((arg: VMessageSlot) => vue.VNodeChild) | undefined;
    }, {
        style: vue.StyleValue;
        active: boolean;
        messages: string | readonly string[];
        transition: {
            component: Component;
            leaveAbsolute: boolean;
            group: boolean;
        } | NonNullable<string | boolean | (vue.TransitionProps & {
            component?: Component | undefined;
        })>;
    }, true, {}, vue.SlotsType<Partial<{
        message: (arg: VMessageSlot) => vue.VNode<vue.RendererNode, vue.RendererElement, {
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
        active: boolean;
        messages: string | readonly string[];
        transition: {
            component: Component;
            leaveAbsolute: boolean;
            group: boolean;
        } | NonNullable<string | boolean | (vue.TransitionProps & {
            component?: Component | undefined;
        })>;
    } & {
        class?: any;
        color?: string | undefined;
    } & {
        $children?: {} | vue.VNodeChild | {
            message?: ((arg: VMessageSlot) => vue.VNodeChild) | undefined;
        };
        'v-slots'?: {
            message?: false | ((arg: VMessageSlot) => vue.VNodeChild) | undefined;
        } | undefined;
    } & {
        "v-slot:message"?: false | ((arg: VMessageSlot) => vue.VNodeChild) | undefined;
    }, {}, {}, {}, {}, {
        style: vue.StyleValue;
        active: boolean;
        messages: string | readonly string[];
        transition: {
            component: Component;
            leaveAbsolute: boolean;
            group: boolean;
        } | NonNullable<string | boolean | (vue.TransitionProps & {
            component?: Component | undefined;
        })>;
    }>;
    __isFragment?: undefined;
    __isTeleport?: undefined;
    __isSuspense?: undefined;
} & vue.ComponentOptionsBase<{
    style: vue.StyleValue;
    active: boolean;
    messages: string | readonly string[];
    transition: {
        component: Component;
        leaveAbsolute: boolean;
        group: boolean;
    } | NonNullable<string | boolean | (vue.TransitionProps & {
        component?: Component | undefined;
    })>;
} & {
    class?: any;
    color?: string | undefined;
} & {
    $children?: {} | vue.VNodeChild | {
        message?: ((arg: VMessageSlot) => vue.VNodeChild) | undefined;
    };
    'v-slots'?: {
        message?: false | ((arg: VMessageSlot) => vue.VNodeChild) | undefined;
    } | undefined;
} & {
    "v-slot:message"?: false | ((arg: VMessageSlot) => vue.VNodeChild) | undefined;
}, {}, unknown, {}, {}, vue.ComponentOptionsMixin, vue.ComponentOptionsMixin, Record<string, any>, string, {
    style: vue.StyleValue;
    active: boolean;
    messages: string | readonly string[];
    transition: {
        component: Component;
        leaveAbsolute: boolean;
        group: boolean;
    } | NonNullable<string | boolean | (vue.TransitionProps & {
        component?: Component | undefined;
    })>;
}, {}, string, vue.SlotsType<Partial<{
    message: (arg: VMessageSlot) => vue.VNode<vue.RendererNode, vue.RendererElement, {
        [key: string]: any;
    }>[];
}>>> & vue.VNodeProps & vue.AllowedComponentProps & vue.ComponentCustomProps & FilterPropsOptions<{
    transition: Omit<{
        type: PropType<string | boolean | (vue.TransitionProps & {
            component?: Component | undefined;
        })>;
        default: string;
        validator: (val: unknown) => boolean;
    }, "default" | "type"> & {
        type: PropType<{
            component: Component;
            leaveAbsolute: boolean;
            group: boolean;
        } | NonNullable<string | boolean | (vue.TransitionProps & {
            component?: Component | undefined;
        })>>;
        default: {
            component: Component;
            leaveAbsolute: boolean;
            group: boolean;
        } | NonNullable<string | boolean | (vue.TransitionProps & {
            component?: Component | undefined;
        })>;
    };
    class: PropType<any>;
    style: {
        type: PropType<vue.StyleValue>;
        default: null;
    };
    active: BooleanConstructor;
    color: StringConstructor;
    messages: {
        type: PropType<string | readonly string[]>;
        default: () => never[];
    };
}, vue.ExtractPropTypes<{
    transition: Omit<{
        type: PropType<string | boolean | (vue.TransitionProps & {
            component?: Component | undefined;
        })>;
        default: string;
        validator: (val: unknown) => boolean;
    }, "default" | "type"> & {
        type: PropType<{
            component: Component;
            leaveAbsolute: boolean;
            group: boolean;
        } | NonNullable<string | boolean | (vue.TransitionProps & {
            component?: Component | undefined;
        })>>;
        default: {
            component: Component;
            leaveAbsolute: boolean;
            group: boolean;
        } | NonNullable<string | boolean | (vue.TransitionProps & {
            component?: Component | undefined;
        })>;
    };
    class: PropType<any>;
    style: {
        type: PropType<vue.StyleValue>;
        default: null;
    };
    active: BooleanConstructor;
    color: StringConstructor;
    messages: {
        type: PropType<string | readonly string[]>;
        default: () => never[];
    };
}>>;
type VMessages = InstanceType<typeof VMessages>;

export { VMessages };
