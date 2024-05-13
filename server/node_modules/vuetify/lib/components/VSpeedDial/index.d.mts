import * as vue from 'vue';
import { ComponentPropsOptions, ExtractPropTypes, ComponentPublicInstance, Ref, EffectScope } from 'vue';

declare const block: readonly ["top", "bottom"];
declare const inline: readonly ["start", "end", "left", "right"];
type Tblock = typeof block[number];
type Tinline = typeof inline[number];
type Anchor = Tblock | Tinline | 'center' | 'center center' | `${Tblock} ${Tinline | 'center'}` | `${Tinline} ${Tblock | 'center'}`;

declare class Box {
    x: number;
    y: number;
    width: number;
    height: number;
    constructor({ x, y, width, height }: {
        x: number;
        y: number;
        width: number;
        height: number;
    });
    get top(): number;
    get bottom(): number;
    get left(): number;
    get right(): number;
}

interface FilterPropsOptions<PropsOptions extends Readonly<ComponentPropsOptions>, Props = ExtractPropTypes<PropsOptions>> {
    filterProps<T extends Partial<Props>, U extends Exclude<keyof Props, Exclude<keyof Props, keyof T>>>(props: T): Partial<Pick<T, U>>;
}

type TemplateRef = {
    (target: Element | ComponentPublicInstance | null): void;
    value: HTMLElement | ComponentPublicInstance | null | undefined;
    readonly el: HTMLElement | undefined;
};

interface ScrollStrategyData {
    root: Ref<HTMLElement | undefined>;
    contentEl: Ref<HTMLElement | undefined>;
    targetEl: Ref<HTMLElement | undefined>;
    isActive: Ref<boolean>;
    updateLocation: Ref<((e: Event) => void) | undefined>;
}
type ScrollStrategyFn = (data: ScrollStrategyData, props: StrategyProps$1, scope: EffectScope) => void;
declare const scrollStrategies: {
    none: null;
    close: typeof closeScrollStrategy;
    block: typeof blockScrollStrategy;
    reposition: typeof repositionScrollStrategy;
};
interface StrategyProps$1 {
    scrollStrategy: keyof typeof scrollStrategies | ScrollStrategyFn;
    contained: boolean | undefined;
}
declare function closeScrollStrategy(data: ScrollStrategyData): void;
declare function blockScrollStrategy(data: ScrollStrategyData, props: StrategyProps$1): void;
declare function repositionScrollStrategy(data: ScrollStrategyData, props: StrategyProps$1, scope: EffectScope): void;

interface LocationStrategyData {
    contentEl: Ref<HTMLElement | undefined>;
    target: Ref<HTMLElement | [x: number, y: number] | undefined>;
    isActive: Ref<boolean>;
    isRtl: Ref<boolean>;
}
type LocationStrategyFn = (data: LocationStrategyData, props: StrategyProps, contentStyles: Ref<Record<string, string>>) => undefined | {
    updateLocation: (e: Event) => void;
};
declare const locationStrategies: {
    static: typeof staticLocationStrategy;
    connected: typeof connectedLocationStrategy;
};
interface StrategyProps {
    locationStrategy: keyof typeof locationStrategies | LocationStrategyFn;
    location: Anchor;
    origin: Anchor | 'auto' | 'overlap';
    offset?: number | string | number[];
    maxHeight?: number | string;
    maxWidth?: number | string;
    minHeight?: number | string;
    minWidth?: number | string;
}
declare function staticLocationStrategy(): void;
declare function connectedLocationStrategy(data: LocationStrategyData, props: StrategyProps, contentStyles: Ref<Record<string, string>>): {
    updateLocation: () => {
        available: {
            x: number;
            y: number;
        };
        contentBox: Box;
    } | undefined;
};

declare const VSpeedDial: {
    new (...args: any[]): vue.CreateComponentPublicInstance<{
        style: vue.StyleValue;
        disabled: boolean;
        offset: NonNullable<string | number | number[] | undefined>;
        transition: NonNullable<NonNullable<string | boolean | (vue.TransitionProps & {
            component?: vue.Component | undefined;
        })> | {
            component: vue.Component;
        }>;
        zIndex: string | number;
        modelValue: boolean;
        origin: Anchor | "auto" | "overlap";
        minWidth: NonNullable<string | number>;
        eager: boolean;
        location: NonNullable<Anchor>;
        locationStrategy: NonNullable<"static" | ((data: LocationStrategyData, props: StrategyProps, contentStyles: vue.Ref<Record<string, string>>) => {
            updateLocation: (e: Event) => void;
        } | undefined) | "connected">;
        scrollStrategy: NonNullable<"close" | "none" | "block" | ((data: ScrollStrategyData, props: StrategyProps$1, scope: vue.EffectScope) => void) | "reposition">;
        closeDelay: NonNullable<NonNullable<string | number>>;
        openDelay: NonNullable<NonNullable<string | number>>;
        activatorProps: Record<string, any>;
        openOnHover: boolean;
        closeOnContentClick: boolean;
        closeOnBack: boolean;
        contained: boolean;
        noClickAnimation: boolean;
        persistent: boolean;
        scrim: NonNullable<string | boolean>;
    } & {
        class?: any;
        id?: string | undefined;
        width?: string | number | undefined;
        height?: string | number | undefined;
        theme?: string | undefined;
        target?: Element | vue.ComponentPublicInstance | (string & {}) | "parent" | "cursor" | [x: number, y: number] | undefined;
        contentClass?: any;
        opacity?: string | number | undefined;
        maxHeight?: string | number | undefined;
        maxWidth?: string | number | undefined;
        minHeight?: string | number | undefined;
        activator?: Element | vue.ComponentPublicInstance | (string & {}) | "parent" | undefined;
        openOnClick?: boolean | undefined;
        openOnFocus?: boolean | undefined;
        contentProps?: any;
        attach?: string | boolean | Element | undefined;
    } & {
        $children?: vue.VNodeChild | {
            default?: ((arg: {
                isActive: vue.Ref<boolean>;
            }) => vue.VNodeChild) | undefined;
            activator?: ((arg: {
                isActive: boolean;
                props: Record<string, any>;
                targetRef: TemplateRef;
            }) => vue.VNodeChild) | undefined;
        } | ((arg: {
            isActive: vue.Ref<boolean>;
        }) => vue.VNodeChild);
        'v-slots'?: {
            default?: false | ((arg: {
                isActive: vue.Ref<boolean>;
            }) => vue.VNodeChild) | undefined;
            activator?: false | ((arg: {
                isActive: boolean;
                props: Record<string, any>;
                targetRef: TemplateRef;
            }) => vue.VNodeChild) | undefined;
        } | undefined;
    } & {
        "v-slot:default"?: false | ((arg: {
            isActive: vue.Ref<boolean>;
        }) => vue.VNodeChild) | undefined;
        "v-slot:activator"?: false | ((arg: {
            isActive: boolean;
            props: Record<string, any>;
            targetRef: TemplateRef;
        }) => vue.VNodeChild) | undefined;
    } & {
        "onUpdate:modelValue"?: ((value: boolean) => any) | undefined;
    }, {}, unknown, {}, {}, vue.ComponentOptionsMixin, vue.ComponentOptionsMixin, {
        'update:modelValue': (value: boolean) => boolean;
    }, vue.VNodeProps & vue.AllowedComponentProps & vue.ComponentCustomProps & {
        style: vue.StyleValue;
        disabled: boolean;
        offset: NonNullable<string | number | number[] | undefined>;
        transition: NonNullable<NonNullable<string | boolean | (vue.TransitionProps & {
            component?: vue.Component | undefined;
        })> | {
            component: vue.Component;
        }>;
        zIndex: string | number;
        modelValue: boolean;
        origin: Anchor | "auto" | "overlap";
        minWidth: NonNullable<string | number>;
        eager: boolean;
        location: NonNullable<Anchor>;
        locationStrategy: NonNullable<"static" | ((data: LocationStrategyData, props: StrategyProps, contentStyles: vue.Ref<Record<string, string>>) => {
            updateLocation: (e: Event) => void;
        } | undefined) | "connected">;
        scrollStrategy: NonNullable<"close" | "none" | "block" | ((data: ScrollStrategyData, props: StrategyProps$1, scope: vue.EffectScope) => void) | "reposition">;
        closeDelay: NonNullable<NonNullable<string | number>>;
        openDelay: NonNullable<NonNullable<string | number>>;
        activatorProps: Record<string, any>;
        openOnHover: boolean;
        closeOnContentClick: boolean;
        closeOnBack: boolean;
        contained: boolean;
        noClickAnimation: boolean;
        persistent: boolean;
        scrim: NonNullable<string | boolean>;
    } & {
        class?: any;
        id?: string | undefined;
        width?: string | number | undefined;
        height?: string | number | undefined;
        theme?: string | undefined;
        target?: Element | vue.ComponentPublicInstance | (string & {}) | "parent" | "cursor" | [x: number, y: number] | undefined;
        contentClass?: any;
        opacity?: string | number | undefined;
        maxHeight?: string | number | undefined;
        maxWidth?: string | number | undefined;
        minHeight?: string | number | undefined;
        activator?: Element | vue.ComponentPublicInstance | (string & {}) | "parent" | undefined;
        openOnClick?: boolean | undefined;
        openOnFocus?: boolean | undefined;
        contentProps?: any;
        attach?: string | boolean | Element | undefined;
    } & {
        $children?: vue.VNodeChild | {
            default?: ((arg: {
                isActive: vue.Ref<boolean>;
            }) => vue.VNodeChild) | undefined;
            activator?: ((arg: {
                isActive: boolean;
                props: Record<string, any>;
                targetRef: TemplateRef;
            }) => vue.VNodeChild) | undefined;
        } | ((arg: {
            isActive: vue.Ref<boolean>;
        }) => vue.VNodeChild);
        'v-slots'?: {
            default?: false | ((arg: {
                isActive: vue.Ref<boolean>;
            }) => vue.VNodeChild) | undefined;
            activator?: false | ((arg: {
                isActive: boolean;
                props: Record<string, any>;
                targetRef: TemplateRef;
            }) => vue.VNodeChild) | undefined;
        } | undefined;
    } & {
        "v-slot:default"?: false | ((arg: {
            isActive: vue.Ref<boolean>;
        }) => vue.VNodeChild) | undefined;
        "v-slot:activator"?: false | ((arg: {
            isActive: boolean;
            props: Record<string, any>;
            targetRef: TemplateRef;
        }) => vue.VNodeChild) | undefined;
    } & {
        "onUpdate:modelValue"?: ((value: boolean) => any) | undefined;
    }, {
        style: vue.StyleValue;
        disabled: boolean;
        offset: NonNullable<string | number | number[] | undefined>;
        transition: NonNullable<NonNullable<string | boolean | (vue.TransitionProps & {
            component?: vue.Component | undefined;
        })> | {
            component: vue.Component;
        }>;
        zIndex: string | number;
        modelValue: boolean;
        origin: Anchor | "auto" | "overlap";
        minWidth: NonNullable<string | number>;
        eager: boolean;
        location: NonNullable<Anchor>;
        locationStrategy: NonNullable<"static" | ((data: LocationStrategyData, props: StrategyProps, contentStyles: vue.Ref<Record<string, string>>) => {
            updateLocation: (e: Event) => void;
        } | undefined) | "connected">;
        scrollStrategy: NonNullable<"close" | "none" | "block" | ((data: ScrollStrategyData, props: StrategyProps$1, scope: vue.EffectScope) => void) | "reposition">;
        closeDelay: NonNullable<NonNullable<string | number>>;
        openDelay: NonNullable<NonNullable<string | number>>;
        activatorProps: Record<string, any>;
        openOnClick: boolean;
        openOnHover: boolean;
        openOnFocus: boolean;
        closeOnContentClick: boolean;
        closeOnBack: boolean;
        contained: boolean;
        noClickAnimation: boolean;
        persistent: boolean;
        scrim: NonNullable<string | boolean>;
    }, true, {}, vue.SlotsType<Partial<{
        default: (arg: {
            isActive: vue.Ref<boolean>;
        }) => vue.VNode<vue.RendererNode, vue.RendererElement, {
            [key: string]: any;
        }>[];
        activator: (arg: {
            isActive: boolean;
            props: Record<string, any>;
            targetRef: TemplateRef;
        }) => vue.VNode<vue.RendererNode, vue.RendererElement, {
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
        offset: NonNullable<string | number | number[] | undefined>;
        transition: NonNullable<NonNullable<string | boolean | (vue.TransitionProps & {
            component?: vue.Component | undefined;
        })> | {
            component: vue.Component;
        }>;
        zIndex: string | number;
        modelValue: boolean;
        origin: Anchor | "auto" | "overlap";
        minWidth: NonNullable<string | number>;
        eager: boolean;
        location: NonNullable<Anchor>;
        locationStrategy: NonNullable<"static" | ((data: LocationStrategyData, props: StrategyProps, contentStyles: vue.Ref<Record<string, string>>) => {
            updateLocation: (e: Event) => void;
        } | undefined) | "connected">;
        scrollStrategy: NonNullable<"close" | "none" | "block" | ((data: ScrollStrategyData, props: StrategyProps$1, scope: vue.EffectScope) => void) | "reposition">;
        closeDelay: NonNullable<NonNullable<string | number>>;
        openDelay: NonNullable<NonNullable<string | number>>;
        activatorProps: Record<string, any>;
        openOnHover: boolean;
        closeOnContentClick: boolean;
        closeOnBack: boolean;
        contained: boolean;
        noClickAnimation: boolean;
        persistent: boolean;
        scrim: NonNullable<string | boolean>;
    } & {
        class?: any;
        id?: string | undefined;
        width?: string | number | undefined;
        height?: string | number | undefined;
        theme?: string | undefined;
        target?: Element | vue.ComponentPublicInstance | (string & {}) | "parent" | "cursor" | [x: number, y: number] | undefined;
        contentClass?: any;
        opacity?: string | number | undefined;
        maxHeight?: string | number | undefined;
        maxWidth?: string | number | undefined;
        minHeight?: string | number | undefined;
        activator?: Element | vue.ComponentPublicInstance | (string & {}) | "parent" | undefined;
        openOnClick?: boolean | undefined;
        openOnFocus?: boolean | undefined;
        contentProps?: any;
        attach?: string | boolean | Element | undefined;
    } & {
        $children?: vue.VNodeChild | {
            default?: ((arg: {
                isActive: vue.Ref<boolean>;
            }) => vue.VNodeChild) | undefined;
            activator?: ((arg: {
                isActive: boolean;
                props: Record<string, any>;
                targetRef: TemplateRef;
            }) => vue.VNodeChild) | undefined;
        } | ((arg: {
            isActive: vue.Ref<boolean>;
        }) => vue.VNodeChild);
        'v-slots'?: {
            default?: false | ((arg: {
                isActive: vue.Ref<boolean>;
            }) => vue.VNodeChild) | undefined;
            activator?: false | ((arg: {
                isActive: boolean;
                props: Record<string, any>;
                targetRef: TemplateRef;
            }) => vue.VNodeChild) | undefined;
        } | undefined;
    } & {
        "v-slot:default"?: false | ((arg: {
            isActive: vue.Ref<boolean>;
        }) => vue.VNodeChild) | undefined;
        "v-slot:activator"?: false | ((arg: {
            isActive: boolean;
            props: Record<string, any>;
            targetRef: TemplateRef;
        }) => vue.VNodeChild) | undefined;
    } & {
        "onUpdate:modelValue"?: ((value: boolean) => any) | undefined;
    }, {}, {}, {}, {}, {
        style: vue.StyleValue;
        disabled: boolean;
        offset: NonNullable<string | number | number[] | undefined>;
        transition: NonNullable<NonNullable<string | boolean | (vue.TransitionProps & {
            component?: vue.Component | undefined;
        })> | {
            component: vue.Component;
        }>;
        zIndex: string | number;
        modelValue: boolean;
        origin: Anchor | "auto" | "overlap";
        minWidth: NonNullable<string | number>;
        eager: boolean;
        location: NonNullable<Anchor>;
        locationStrategy: NonNullable<"static" | ((data: LocationStrategyData, props: StrategyProps, contentStyles: vue.Ref<Record<string, string>>) => {
            updateLocation: (e: Event) => void;
        } | undefined) | "connected">;
        scrollStrategy: NonNullable<"close" | "none" | "block" | ((data: ScrollStrategyData, props: StrategyProps$1, scope: vue.EffectScope) => void) | "reposition">;
        closeDelay: NonNullable<NonNullable<string | number>>;
        openDelay: NonNullable<NonNullable<string | number>>;
        activatorProps: Record<string, any>;
        openOnClick: boolean;
        openOnHover: boolean;
        openOnFocus: boolean;
        closeOnContentClick: boolean;
        closeOnBack: boolean;
        contained: boolean;
        noClickAnimation: boolean;
        persistent: boolean;
        scrim: NonNullable<string | boolean>;
    }>;
    __isFragment?: undefined;
    __isTeleport?: undefined;
    __isSuspense?: undefined;
} & vue.ComponentOptionsBase<{
    style: vue.StyleValue;
    disabled: boolean;
    offset: NonNullable<string | number | number[] | undefined>;
    transition: NonNullable<NonNullable<string | boolean | (vue.TransitionProps & {
        component?: vue.Component | undefined;
    })> | {
        component: vue.Component;
    }>;
    zIndex: string | number;
    modelValue: boolean;
    origin: Anchor | "auto" | "overlap";
    minWidth: NonNullable<string | number>;
    eager: boolean;
    location: NonNullable<Anchor>;
    locationStrategy: NonNullable<"static" | ((data: LocationStrategyData, props: StrategyProps, contentStyles: vue.Ref<Record<string, string>>) => {
        updateLocation: (e: Event) => void;
    } | undefined) | "connected">;
    scrollStrategy: NonNullable<"close" | "none" | "block" | ((data: ScrollStrategyData, props: StrategyProps$1, scope: vue.EffectScope) => void) | "reposition">;
    closeDelay: NonNullable<NonNullable<string | number>>;
    openDelay: NonNullable<NonNullable<string | number>>;
    activatorProps: Record<string, any>;
    openOnHover: boolean;
    closeOnContentClick: boolean;
    closeOnBack: boolean;
    contained: boolean;
    noClickAnimation: boolean;
    persistent: boolean;
    scrim: NonNullable<string | boolean>;
} & {
    class?: any;
    id?: string | undefined;
    width?: string | number | undefined;
    height?: string | number | undefined;
    theme?: string | undefined;
    target?: Element | vue.ComponentPublicInstance | (string & {}) | "parent" | "cursor" | [x: number, y: number] | undefined;
    contentClass?: any;
    opacity?: string | number | undefined;
    maxHeight?: string | number | undefined;
    maxWidth?: string | number | undefined;
    minHeight?: string | number | undefined;
    activator?: Element | vue.ComponentPublicInstance | (string & {}) | "parent" | undefined;
    openOnClick?: boolean | undefined;
    openOnFocus?: boolean | undefined;
    contentProps?: any;
    attach?: string | boolean | Element | undefined;
} & {
    $children?: vue.VNodeChild | {
        default?: ((arg: {
            isActive: vue.Ref<boolean>;
        }) => vue.VNodeChild) | undefined;
        activator?: ((arg: {
            isActive: boolean;
            props: Record<string, any>;
            targetRef: TemplateRef;
        }) => vue.VNodeChild) | undefined;
    } | ((arg: {
        isActive: vue.Ref<boolean>;
    }) => vue.VNodeChild);
    'v-slots'?: {
        default?: false | ((arg: {
            isActive: vue.Ref<boolean>;
        }) => vue.VNodeChild) | undefined;
        activator?: false | ((arg: {
            isActive: boolean;
            props: Record<string, any>;
            targetRef: TemplateRef;
        }) => vue.VNodeChild) | undefined;
    } | undefined;
} & {
    "v-slot:default"?: false | ((arg: {
        isActive: vue.Ref<boolean>;
    }) => vue.VNodeChild) | undefined;
    "v-slot:activator"?: false | ((arg: {
        isActive: boolean;
        props: Record<string, any>;
        targetRef: TemplateRef;
    }) => vue.VNodeChild) | undefined;
} & {
    "onUpdate:modelValue"?: ((value: boolean) => any) | undefined;
}, {}, unknown, {}, {}, vue.ComponentOptionsMixin, vue.ComponentOptionsMixin, {
    'update:modelValue': (value: boolean) => boolean;
}, string, {
    style: vue.StyleValue;
    disabled: boolean;
    offset: NonNullable<string | number | number[] | undefined>;
    transition: NonNullable<NonNullable<string | boolean | (vue.TransitionProps & {
        component?: vue.Component | undefined;
    })> | {
        component: vue.Component;
    }>;
    zIndex: string | number;
    modelValue: boolean;
    origin: Anchor | "auto" | "overlap";
    minWidth: NonNullable<string | number>;
    eager: boolean;
    location: NonNullable<Anchor>;
    locationStrategy: NonNullable<"static" | ((data: LocationStrategyData, props: StrategyProps, contentStyles: vue.Ref<Record<string, string>>) => {
        updateLocation: (e: Event) => void;
    } | undefined) | "connected">;
    scrollStrategy: NonNullable<"close" | "none" | "block" | ((data: ScrollStrategyData, props: StrategyProps$1, scope: vue.EffectScope) => void) | "reposition">;
    closeDelay: NonNullable<NonNullable<string | number>>;
    openDelay: NonNullable<NonNullable<string | number>>;
    activatorProps: Record<string, any>;
    openOnClick: boolean;
    openOnHover: boolean;
    openOnFocus: boolean;
    closeOnContentClick: boolean;
    closeOnBack: boolean;
    contained: boolean;
    noClickAnimation: boolean;
    persistent: boolean;
    scrim: NonNullable<string | boolean>;
}, {}, string, vue.SlotsType<Partial<{
    default: (arg: {
        isActive: vue.Ref<boolean>;
    }) => vue.VNode<vue.RendererNode, vue.RendererElement, {
        [key: string]: any;
    }>[];
    activator: (arg: {
        isActive: boolean;
        props: Record<string, any>;
        targetRef: TemplateRef;
    }) => vue.VNode<vue.RendererNode, vue.RendererElement, {
        [key: string]: any;
    }>[];
}>>> & vue.VNodeProps & vue.AllowedComponentProps & vue.ComponentCustomProps & FilterPropsOptions<{
    class: vue.PropType<any>;
    style: {
        type: vue.PropType<vue.StyleValue>;
        default: null;
    };
    width: (StringConstructor | NumberConstructor)[];
    height: (StringConstructor | NumberConstructor)[];
    theme: StringConstructor;
    target: vue.PropType<Element | vue.ComponentPublicInstance | (string & {}) | "parent" | "cursor" | [x: number, y: number] | undefined>;
    disabled: BooleanConstructor;
    offset: {
        type: vue.PropType<NonNullable<string | number | number[] | undefined>>;
        default: NonNullable<string | number | number[] | undefined>;
    };
    transition: Omit<Omit<{
        type: vue.PropType<string | boolean | (vue.TransitionProps & {
            component?: vue.Component | undefined;
        })>;
        default: string;
        validator: (val: unknown) => boolean;
    }, "default" | "type"> & {
        type: vue.PropType<NonNullable<string | boolean | (vue.TransitionProps & {
            component?: vue.Component | undefined;
        })> | {
            component: vue.Component;
        }>;
        default: NonNullable<string | boolean | (vue.TransitionProps & {
            component?: vue.Component | undefined;
        })> | {
            component: vue.Component;
        };
    }, "default" | "type"> & {
        type: vue.PropType<NonNullable<NonNullable<string | boolean | (vue.TransitionProps & {
            component?: vue.Component | undefined;
        })> | {
            component: vue.Component;
        }>>;
        default: NonNullable<NonNullable<string | boolean | (vue.TransitionProps & {
            component?: vue.Component | undefined;
        })> | {
            component: vue.Component;
        }>;
    };
    zIndex: {
        type: (StringConstructor | NumberConstructor)[];
        default: number;
    };
    modelValue: BooleanConstructor;
    contentClass: null;
    origin: {
        type: vue.PropType<Anchor | "auto" | "overlap">;
        default: string;
    };
    opacity: (StringConstructor | NumberConstructor)[];
    maxHeight: (StringConstructor | NumberConstructor)[];
    maxWidth: (StringConstructor | NumberConstructor)[];
    minHeight: (StringConstructor | NumberConstructor)[];
    minWidth: {
        type: vue.PropType<NonNullable<string | number>>;
        default: NonNullable<string | number>;
    };
    eager: BooleanConstructor;
    location: Omit<{
        type: vue.PropType<Anchor>;
        default: string;
    }, "default" | "type"> & {
        type: vue.PropType<NonNullable<Anchor>>;
        default: NonNullable<Anchor>;
    };
    activator: vue.PropType<Element | vue.ComponentPublicInstance | (string & {}) | "parent" | undefined>;
    locationStrategy: Omit<{
        type: vue.PropType<"static" | ((data: LocationStrategyData, props: StrategyProps, contentStyles: vue.Ref<Record<string, string>>) => {
            updateLocation: (e: Event) => void;
        } | undefined) | "connected">;
        default: string;
        validator: (val: any) => boolean;
    }, "default" | "type"> & {
        type: vue.PropType<NonNullable<"static" | ((data: LocationStrategyData, props: StrategyProps, contentStyles: vue.Ref<Record<string, string>>) => {
            updateLocation: (e: Event) => void;
        } | undefined) | "connected">>;
        default: NonNullable<"static" | ((data: LocationStrategyData, props: StrategyProps, contentStyles: vue.Ref<Record<string, string>>) => {
            updateLocation: (e: Event) => void;
        } | undefined) | "connected">;
    };
    scrollStrategy: Omit<{
        type: vue.PropType<"close" | "none" | "block" | ((data: ScrollStrategyData, props: StrategyProps$1, scope: vue.EffectScope) => void) | "reposition">;
        default: string;
        validator: (val: any) => boolean;
    }, "default" | "type"> & {
        type: vue.PropType<NonNullable<"close" | "none" | "block" | ((data: ScrollStrategyData, props: StrategyProps$1, scope: vue.EffectScope) => void) | "reposition">>;
        default: NonNullable<"close" | "none" | "block" | ((data: ScrollStrategyData, props: StrategyProps$1, scope: vue.EffectScope) => void) | "reposition">;
    };
    closeDelay: Omit<{
        type: vue.PropType<NonNullable<string | number>>;
        default: NonNullable<string | number>;
    }, "default" | "type"> & {
        type: vue.PropType<NonNullable<NonNullable<string | number>>>;
        default: NonNullable<NonNullable<string | number>>;
    };
    openDelay: Omit<{
        type: vue.PropType<NonNullable<string | number>>;
        default: NonNullable<string | number>;
    }, "default" | "type"> & {
        type: vue.PropType<NonNullable<NonNullable<string | number>>>;
        default: NonNullable<NonNullable<string | number>>;
    };
    activatorProps: {
        type: vue.PropType<Record<string, any>>;
        default: () => {};
    };
    openOnClick: {
        type: BooleanConstructor;
        default: undefined;
    };
    openOnHover: BooleanConstructor;
    openOnFocus: {
        type: BooleanConstructor;
        default: undefined;
    };
    closeOnContentClick: {
        type: vue.PropType<boolean>;
        default: boolean;
    };
    closeOnBack: {
        type: BooleanConstructor;
        default: boolean;
    };
    contained: BooleanConstructor;
    contentProps: null;
    noClickAnimation: BooleanConstructor;
    persistent: BooleanConstructor;
    scrim: Omit<{
        type: (StringConstructor | BooleanConstructor)[];
        default: boolean;
    }, "default" | "type"> & {
        type: vue.PropType<NonNullable<string | boolean>>;
        default: NonNullable<string | boolean>;
    };
    attach: vue.PropType<string | boolean | Element>;
    id: StringConstructor;
}, vue.ExtractPropTypes<{
    class: vue.PropType<any>;
    style: {
        type: vue.PropType<vue.StyleValue>;
        default: null;
    };
    width: (StringConstructor | NumberConstructor)[];
    height: (StringConstructor | NumberConstructor)[];
    theme: StringConstructor;
    target: vue.PropType<Element | vue.ComponentPublicInstance | (string & {}) | "parent" | "cursor" | [x: number, y: number] | undefined>;
    disabled: BooleanConstructor;
    offset: {
        type: vue.PropType<NonNullable<string | number | number[] | undefined>>;
        default: NonNullable<string | number | number[] | undefined>;
    };
    transition: Omit<Omit<{
        type: vue.PropType<string | boolean | (vue.TransitionProps & {
            component?: vue.Component | undefined;
        })>;
        default: string;
        validator: (val: unknown) => boolean;
    }, "default" | "type"> & {
        type: vue.PropType<NonNullable<string | boolean | (vue.TransitionProps & {
            component?: vue.Component | undefined;
        })> | {
            component: vue.Component;
        }>;
        default: NonNullable<string | boolean | (vue.TransitionProps & {
            component?: vue.Component | undefined;
        })> | {
            component: vue.Component;
        };
    }, "default" | "type"> & {
        type: vue.PropType<NonNullable<NonNullable<string | boolean | (vue.TransitionProps & {
            component?: vue.Component | undefined;
        })> | {
            component: vue.Component;
        }>>;
        default: NonNullable<NonNullable<string | boolean | (vue.TransitionProps & {
            component?: vue.Component | undefined;
        })> | {
            component: vue.Component;
        }>;
    };
    zIndex: {
        type: (StringConstructor | NumberConstructor)[];
        default: number;
    };
    modelValue: BooleanConstructor;
    contentClass: null;
    origin: {
        type: vue.PropType<Anchor | "auto" | "overlap">;
        default: string;
    };
    opacity: (StringConstructor | NumberConstructor)[];
    maxHeight: (StringConstructor | NumberConstructor)[];
    maxWidth: (StringConstructor | NumberConstructor)[];
    minHeight: (StringConstructor | NumberConstructor)[];
    minWidth: {
        type: vue.PropType<NonNullable<string | number>>;
        default: NonNullable<string | number>;
    };
    eager: BooleanConstructor;
    location: Omit<{
        type: vue.PropType<Anchor>;
        default: string;
    }, "default" | "type"> & {
        type: vue.PropType<NonNullable<Anchor>>;
        default: NonNullable<Anchor>;
    };
    activator: vue.PropType<Element | vue.ComponentPublicInstance | (string & {}) | "parent" | undefined>;
    locationStrategy: Omit<{
        type: vue.PropType<"static" | ((data: LocationStrategyData, props: StrategyProps, contentStyles: vue.Ref<Record<string, string>>) => {
            updateLocation: (e: Event) => void;
        } | undefined) | "connected">;
        default: string;
        validator: (val: any) => boolean;
    }, "default" | "type"> & {
        type: vue.PropType<NonNullable<"static" | ((data: LocationStrategyData, props: StrategyProps, contentStyles: vue.Ref<Record<string, string>>) => {
            updateLocation: (e: Event) => void;
        } | undefined) | "connected">>;
        default: NonNullable<"static" | ((data: LocationStrategyData, props: StrategyProps, contentStyles: vue.Ref<Record<string, string>>) => {
            updateLocation: (e: Event) => void;
        } | undefined) | "connected">;
    };
    scrollStrategy: Omit<{
        type: vue.PropType<"close" | "none" | "block" | ((data: ScrollStrategyData, props: StrategyProps$1, scope: vue.EffectScope) => void) | "reposition">;
        default: string;
        validator: (val: any) => boolean;
    }, "default" | "type"> & {
        type: vue.PropType<NonNullable<"close" | "none" | "block" | ((data: ScrollStrategyData, props: StrategyProps$1, scope: vue.EffectScope) => void) | "reposition">>;
        default: NonNullable<"close" | "none" | "block" | ((data: ScrollStrategyData, props: StrategyProps$1, scope: vue.EffectScope) => void) | "reposition">;
    };
    closeDelay: Omit<{
        type: vue.PropType<NonNullable<string | number>>;
        default: NonNullable<string | number>;
    }, "default" | "type"> & {
        type: vue.PropType<NonNullable<NonNullable<string | number>>>;
        default: NonNullable<NonNullable<string | number>>;
    };
    openDelay: Omit<{
        type: vue.PropType<NonNullable<string | number>>;
        default: NonNullable<string | number>;
    }, "default" | "type"> & {
        type: vue.PropType<NonNullable<NonNullable<string | number>>>;
        default: NonNullable<NonNullable<string | number>>;
    };
    activatorProps: {
        type: vue.PropType<Record<string, any>>;
        default: () => {};
    };
    openOnClick: {
        type: BooleanConstructor;
        default: undefined;
    };
    openOnHover: BooleanConstructor;
    openOnFocus: {
        type: BooleanConstructor;
        default: undefined;
    };
    closeOnContentClick: {
        type: vue.PropType<boolean>;
        default: boolean;
    };
    closeOnBack: {
        type: BooleanConstructor;
        default: boolean;
    };
    contained: BooleanConstructor;
    contentProps: null;
    noClickAnimation: BooleanConstructor;
    persistent: BooleanConstructor;
    scrim: Omit<{
        type: (StringConstructor | BooleanConstructor)[];
        default: boolean;
    }, "default" | "type"> & {
        type: vue.PropType<NonNullable<string | boolean>>;
        default: NonNullable<string | boolean>;
    };
    attach: vue.PropType<string | boolean | Element>;
    id: StringConstructor;
}>>;
type VSpeedDial = InstanceType<typeof VSpeedDial>;

export { VSpeedDial };
