import * as vue from 'vue';
import { ComponentPropsOptions, ExtractPropTypes, Component } from 'vue';

interface FilterPropsOptions<PropsOptions extends Readonly<ComponentPropsOptions>, Props = ExtractPropTypes<PropsOptions>> {
    filterProps<T extends Partial<Props>, U extends Exclude<keyof Props, Exclude<keyof Props, keyof T>>>(props: T): Partial<Pick<T, U>>;
}

type VCounterSlot = {
    counter: string;
    max: string | number | undefined;
    value: string | number | undefined;
};
declare const VCounter: {
    new (...args: any[]): vue.CreateComponentPublicInstance<{
        style: vue.StyleValue;
        value: string | number;
        active: boolean;
        disabled: boolean;
        transition: NonNullable<string | boolean | (vue.TransitionProps & {
            component?: Component | undefined;
        })> | {
            component: Component;
        };
    } & {
        class?: any;
        max?: string | number | undefined;
    } & {
        $children?: vue.VNodeChild | {
            default?: ((arg: VCounterSlot) => vue.VNodeChild) | undefined;
        } | ((arg: VCounterSlot) => vue.VNodeChild);
        'v-slots'?: {
            default?: false | ((arg: VCounterSlot) => vue.VNodeChild) | undefined;
        } | undefined;
    } & {
        "v-slot:default"?: false | ((arg: VCounterSlot) => vue.VNodeChild) | undefined;
    }, {}, unknown, {}, {}, vue.ComponentOptionsMixin, vue.ComponentOptionsMixin, Record<string, any>, vue.VNodeProps & vue.AllowedComponentProps & vue.ComponentCustomProps & {
        style: vue.StyleValue;
        value: string | number;
        active: boolean;
        disabled: boolean;
        transition: NonNullable<string | boolean | (vue.TransitionProps & {
            component?: Component | undefined;
        })> | {
            component: Component;
        };
    } & {
        class?: any;
        max?: string | number | undefined;
    } & {
        $children?: vue.VNodeChild | {
            default?: ((arg: VCounterSlot) => vue.VNodeChild) | undefined;
        } | ((arg: VCounterSlot) => vue.VNodeChild);
        'v-slots'?: {
            default?: false | ((arg: VCounterSlot) => vue.VNodeChild) | undefined;
        } | undefined;
    } & {
        "v-slot:default"?: false | ((arg: VCounterSlot) => vue.VNodeChild) | undefined;
    }, {
        style: vue.StyleValue;
        value: string | number;
        active: boolean;
        disabled: boolean;
        transition: NonNullable<string | boolean | (vue.TransitionProps & {
            component?: Component | undefined;
        })> | {
            component: Component;
        };
    }, true, {}, vue.SlotsType<Partial<{
        default: (arg: VCounterSlot) => vue.VNode<vue.RendererNode, vue.RendererElement, {
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
        value: string | number;
        active: boolean;
        disabled: boolean;
        transition: NonNullable<string | boolean | (vue.TransitionProps & {
            component?: Component | undefined;
        })> | {
            component: Component;
        };
    } & {
        class?: any;
        max?: string | number | undefined;
    } & {
        $children?: vue.VNodeChild | {
            default?: ((arg: VCounterSlot) => vue.VNodeChild) | undefined;
        } | ((arg: VCounterSlot) => vue.VNodeChild);
        'v-slots'?: {
            default?: false | ((arg: VCounterSlot) => vue.VNodeChild) | undefined;
        } | undefined;
    } & {
        "v-slot:default"?: false | ((arg: VCounterSlot) => vue.VNodeChild) | undefined;
    }, {}, {}, {}, {}, {
        style: vue.StyleValue;
        value: string | number;
        active: boolean;
        disabled: boolean;
        transition: NonNullable<string | boolean | (vue.TransitionProps & {
            component?: Component | undefined;
        })> | {
            component: Component;
        };
    }>;
    __isFragment?: undefined;
    __isTeleport?: undefined;
    __isSuspense?: undefined;
} & vue.ComponentOptionsBase<{
    style: vue.StyleValue;
    value: string | number;
    active: boolean;
    disabled: boolean;
    transition: NonNullable<string | boolean | (vue.TransitionProps & {
        component?: Component | undefined;
    })> | {
        component: Component;
    };
} & {
    class?: any;
    max?: string | number | undefined;
} & {
    $children?: vue.VNodeChild | {
        default?: ((arg: VCounterSlot) => vue.VNodeChild) | undefined;
    } | ((arg: VCounterSlot) => vue.VNodeChild);
    'v-slots'?: {
        default?: false | ((arg: VCounterSlot) => vue.VNodeChild) | undefined;
    } | undefined;
} & {
    "v-slot:default"?: false | ((arg: VCounterSlot) => vue.VNodeChild) | undefined;
}, {}, unknown, {}, {}, vue.ComponentOptionsMixin, vue.ComponentOptionsMixin, Record<string, any>, string, {
    style: vue.StyleValue;
    value: string | number;
    active: boolean;
    disabled: boolean;
    transition: NonNullable<string | boolean | (vue.TransitionProps & {
        component?: Component | undefined;
    })> | {
        component: Component;
    };
}, {}, string, vue.SlotsType<Partial<{
    default: (arg: VCounterSlot) => vue.VNode<vue.RendererNode, vue.RendererElement, {
        [key: string]: any;
    }>[];
}>>> & vue.VNodeProps & vue.AllowedComponentProps & vue.ComponentCustomProps & FilterPropsOptions<{
    transition: Omit<{
        type: vue.PropType<string | boolean | (vue.TransitionProps & {
            component?: Component | undefined;
        })>;
        default: string;
        validator: (val: unknown) => boolean;
    }, "default" | "type"> & {
        type: vue.PropType<NonNullable<string | boolean | (vue.TransitionProps & {
            component?: Component | undefined;
        })> | {
            component: Component;
        }>;
        default: NonNullable<string | boolean | (vue.TransitionProps & {
            component?: Component | undefined;
        })> | {
            component: Component;
        };
    };
    class: vue.PropType<any>;
    style: {
        type: vue.PropType<vue.StyleValue>;
        default: null;
    };
    active: BooleanConstructor;
    disabled: BooleanConstructor;
    max: (StringConstructor | NumberConstructor)[];
    value: {
        type: (StringConstructor | NumberConstructor)[];
        default: number;
    };
}, vue.ExtractPropTypes<{
    transition: Omit<{
        type: vue.PropType<string | boolean | (vue.TransitionProps & {
            component?: Component | undefined;
        })>;
        default: string;
        validator: (val: unknown) => boolean;
    }, "default" | "type"> & {
        type: vue.PropType<NonNullable<string | boolean | (vue.TransitionProps & {
            component?: Component | undefined;
        })> | {
            component: Component;
        }>;
        default: NonNullable<string | boolean | (vue.TransitionProps & {
            component?: Component | undefined;
        })> | {
            component: Component;
        };
    };
    class: vue.PropType<any>;
    style: {
        type: vue.PropType<vue.StyleValue>;
        default: null;
    };
    active: BooleanConstructor;
    disabled: BooleanConstructor;
    max: (StringConstructor | NumberConstructor)[];
    value: {
        type: (StringConstructor | NumberConstructor)[];
        default: number;
    };
}>>;
type VCounter = InstanceType<typeof VCounter>;

export { VCounter };
