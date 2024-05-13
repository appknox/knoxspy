import * as vue from 'vue';
import { ComponentPropsOptions, ExtractPropTypes, VNodeChild, VNode, ComponentPublicInstance, Ref, EffectScope, nextTick, PropType } from 'vue';

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

declare const block: readonly ["top", "bottom"];
declare const inline: readonly ["start", "end", "left", "right"];
type Tblock = typeof block[number];
type Tinline = typeof inline[number];
type Anchor = Tblock | Tinline | 'center' | 'center center' | `${Tblock} ${Tinline | 'center'}` | `${Tinline} ${Tblock | 'center'}`;

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

type TemplateRef = {
    (target: Element | ComponentPublicInstance | null): void;
    value: HTMLElement | ComponentPublicInstance | null | undefined;
    readonly el: HTMLElement | undefined;
};

interface LocationStrategyData {
    contentEl: Ref<HTMLElement | undefined>;
    target: Ref<HTMLElement | [x: number, y: number] | undefined>;
    isActive: Ref<boolean>;
    isRtl: Ref<boolean>;
}
type LocationStrategyFn = (data: LocationStrategyData, props: StrategyProps$1, contentStyles: Ref<Record<string, string>>) => undefined | {
    updateLocation: (e: Event) => void;
};
declare const locationStrategies: {
    static: typeof staticLocationStrategy;
    connected: typeof connectedLocationStrategy;
};
interface StrategyProps$1 {
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
declare function connectedLocationStrategy(data: LocationStrategyData, props: StrategyProps$1, contentStyles: Ref<Record<string, string>>): {
    updateLocation: () => {
        available: {
            x: number;
            y: number;
        };
        contentBox: Box;
    } | undefined;
};

interface ScrollStrategyData {
    root: Ref<HTMLElement | undefined>;
    contentEl: Ref<HTMLElement | undefined>;
    targetEl: Ref<HTMLElement | undefined>;
    isActive: Ref<boolean>;
    updateLocation: Ref<((e: Event) => void) | undefined>;
}
type ScrollStrategyFn = (data: ScrollStrategyData, props: StrategyProps, scope: EffectScope) => void;
declare const scrollStrategies: {
    none: null;
    close: typeof closeScrollStrategy;
    block: typeof blockScrollStrategy;
    reposition: typeof repositionScrollStrategy;
};
interface StrategyProps {
    scrollStrategy: keyof typeof scrollStrategies | ScrollStrategyFn;
    contained: boolean | undefined;
}
declare function closeScrollStrategy(data: ScrollStrategyData): void;
declare function blockScrollStrategy(data: ScrollStrategyData, props: StrategyProps): void;
declare function repositionScrollStrategy(data: ScrollStrategyData, props: StrategyProps, scope: EffectScope): void;

declare const VSnackbar: {
    new (...args: any[]): vue.CreateComponentPublicInstance<{
        style: vue.StyleValue;
        disabled: boolean;
        absolute: boolean;
        transition: NonNullable<string | boolean | (vue.TransitionProps & {
            component?: vue.Component | undefined;
        })>;
        zIndex: string | number;
        modelValue: boolean;
        variant: "flat" | "text" | "elevated" | "tonal" | "outlined" | "plain";
        origin: Anchor | "auto" | "overlap";
        vertical: boolean;
        tile: boolean;
        eager: boolean;
        location: Anchor;
        locationStrategy: "static" | ((data: LocationStrategyData, props: StrategyProps$1, contentStyles: Ref<Record<string, string>>) => {
            updateLocation: (e: Event) => void;
        } | undefined) | "connected";
        activatorProps: Record<string, any>;
        openOnHover: boolean;
        closeOnContentClick: boolean;
        closeOnBack: boolean;
        contained: boolean;
        multiLine: boolean;
        timeout: string | number;
    } & {
        class?: any;
        text?: string | undefined;
        width?: string | number | undefined;
        height?: string | number | undefined;
        theme?: string | undefined;
        target?: Element | vue.ComponentPublicInstance | (string & {}) | "parent" | "cursor" | [x: number, y: number] | undefined;
        color?: string | undefined;
        offset?: string | number | number[] | undefined;
        position?: "fixed" | "absolute" | "relative" | "static" | "sticky" | undefined;
        rounded?: string | number | boolean | undefined;
        contentClass?: any;
        opacity?: string | number | undefined;
        maxHeight?: string | number | undefined;
        maxWidth?: string | number | undefined;
        minHeight?: string | number | undefined;
        minWidth?: string | number | undefined;
        activator?: Element | vue.ComponentPublicInstance | (string & {}) | "parent" | undefined;
        closeDelay?: string | number | undefined;
        openDelay?: string | number | undefined;
        openOnClick?: boolean | undefined;
        openOnFocus?: boolean | undefined;
        contentProps?: any;
        attach?: string | boolean | Element | undefined;
        timer?: string | boolean | undefined;
    } & {
        $children?: vue.VNodeChild | (() => vue.VNodeChild) | {
            activator?: ((arg: {
                isActive: boolean;
                props: Record<string, any>;
            }) => vue.VNodeChild) | undefined;
            default?: (() => vue.VNodeChild) | undefined;
            actions?: ((arg: {
                isActive: Ref<boolean>;
            }) => vue.VNodeChild) | undefined;
            text?: (() => vue.VNodeChild) | undefined;
        };
        'v-slots'?: {
            activator?: false | ((arg: {
                isActive: boolean;
                props: Record<string, any>;
            }) => vue.VNodeChild) | undefined;
            default?: false | (() => vue.VNodeChild) | undefined;
            actions?: false | ((arg: {
                isActive: Ref<boolean>;
            }) => vue.VNodeChild) | undefined;
            text?: false | (() => vue.VNodeChild) | undefined;
        } | undefined;
    } & {
        "v-slot:activator"?: false | ((arg: {
            isActive: boolean;
            props: Record<string, any>;
        }) => vue.VNodeChild) | undefined;
        "v-slot:default"?: false | (() => vue.VNodeChild) | undefined;
        "v-slot:actions"?: false | ((arg: {
            isActive: Ref<boolean>;
        }) => vue.VNodeChild) | undefined;
        "v-slot:text"?: false | (() => vue.VNodeChild) | undefined;
    } & {
        "onUpdate:modelValue"?: ((v: boolean) => any) | undefined;
    }, Omit<Omit<{
        $: vue.ComponentInternalInstance;
        $data: {};
        $props: Partial<{
            style: vue.StyleValue;
            disabled: boolean;
            absolute: boolean;
            transition: string | boolean | (vue.TransitionProps & {
                component?: vue.Component | undefined;
            });
            zIndex: string | number;
            modelValue: boolean;
            origin: Anchor | "auto" | "overlap";
            eager: boolean;
            location: Anchor;
            locationStrategy: "static" | ((data: LocationStrategyData, props: StrategyProps$1, contentStyles: Ref<Record<string, string>>) => {
                updateLocation: (e: Event) => void;
            } | undefined) | "connected";
            scrollStrategy: "close" | "none" | "block" | ((data: ScrollStrategyData, props: StrategyProps, scope: vue.EffectScope) => void) | "reposition";
            activatorProps: Record<string, any>;
            openOnClick: boolean;
            openOnHover: boolean;
            openOnFocus: boolean;
            closeOnContentClick: boolean;
            closeOnBack: boolean;
            contained: boolean;
            noClickAnimation: boolean;
            persistent: boolean;
            scrim: string | boolean;
            _disableGlobalStack: boolean;
        }> & Omit<{
            style: vue.StyleValue;
            disabled: boolean;
            absolute: boolean;
            transition: string | boolean | (vue.TransitionProps & {
                component?: vue.Component | undefined;
            });
            zIndex: string | number;
            modelValue: boolean;
            origin: Anchor | "auto" | "overlap";
            eager: boolean;
            location: Anchor;
            locationStrategy: "static" | ((data: LocationStrategyData, props: StrategyProps$1, contentStyles: Ref<Record<string, string>>) => {
                updateLocation: (e: Event) => void;
            } | undefined) | "connected";
            scrollStrategy: "close" | "none" | "block" | ((data: ScrollStrategyData, props: StrategyProps, scope: vue.EffectScope) => void) | "reposition";
            activatorProps: Record<string, any>;
            openOnHover: boolean;
            closeOnContentClick: boolean;
            closeOnBack: boolean;
            contained: boolean;
            noClickAnimation: boolean;
            persistent: boolean;
            scrim: string | boolean;
            _disableGlobalStack: boolean;
            class?: any;
            width?: string | number | undefined;
            height?: string | number | undefined;
            theme?: string | undefined;
            target?: Element | vue.ComponentPublicInstance | (string & {}) | "parent" | "cursor" | [x: number, y: number] | undefined;
            offset?: string | number | number[] | undefined;
            contentClass?: any;
            opacity?: string | number | undefined;
            maxHeight?: string | number | undefined;
            maxWidth?: string | number | undefined;
            minHeight?: string | number | undefined;
            minWidth?: string | number | undefined;
            activator?: Element | vue.ComponentPublicInstance | (string & {}) | "parent" | undefined;
            closeDelay?: string | number | undefined;
            openDelay?: string | number | undefined;
            openOnClick?: boolean | undefined;
            openOnFocus?: boolean | undefined;
            contentProps?: any;
            attach?: string | boolean | Element | undefined;
            $children?: vue.VNodeChild | {
                default?: ((arg: {
                    isActive: Ref<boolean>;
                }) => vue.VNodeChild) | undefined;
                activator?: ((arg: {
                    isActive: boolean;
                    props: Record<string, any>;
                    targetRef: TemplateRef;
                }) => vue.VNodeChild) | undefined;
            } | ((arg: {
                isActive: Ref<boolean>;
            }) => vue.VNodeChild);
            'v-slots'?: {
                default?: false | ((arg: {
                    isActive: Ref<boolean>;
                }) => vue.VNodeChild) | undefined;
                activator?: false | ((arg: {
                    isActive: boolean;
                    props: Record<string, any>;
                    targetRef: TemplateRef;
                }) => vue.VNodeChild) | undefined;
            } | undefined;
            "v-slot:default"?: false | ((arg: {
                isActive: Ref<boolean>;
            }) => vue.VNodeChild) | undefined;
            "v-slot:activator"?: false | ((arg: {
                isActive: boolean;
                props: Record<string, any>;
                targetRef: TemplateRef;
            }) => vue.VNodeChild) | undefined;
            "onUpdate:modelValue"?: ((value: boolean) => any) | undefined;
            onAfterEnter?: (() => any) | undefined;
            onAfterLeave?: (() => any) | undefined;
            "onClick:outside"?: ((e: MouseEvent) => any) | undefined;
        } & vue.VNodeProps & vue.AllowedComponentProps & vue.ComponentCustomProps & {
            style: vue.StyleValue;
            disabled: boolean;
            absolute: boolean;
            transition: string | boolean | (vue.TransitionProps & {
                component?: vue.Component | undefined;
            });
            zIndex: string | number;
            modelValue: boolean;
            origin: Anchor | "auto" | "overlap";
            eager: boolean;
            location: Anchor;
            locationStrategy: "static" | ((data: LocationStrategyData, props: StrategyProps$1, contentStyles: Ref<Record<string, string>>) => {
                updateLocation: (e: Event) => void;
            } | undefined) | "connected";
            scrollStrategy: "close" | "none" | "block" | ((data: ScrollStrategyData, props: StrategyProps, scope: vue.EffectScope) => void) | "reposition";
            activatorProps: Record<string, any>;
            openOnHover: boolean;
            closeOnContentClick: boolean;
            closeOnBack: boolean;
            contained: boolean;
            noClickAnimation: boolean;
            persistent: boolean;
            scrim: string | boolean;
            _disableGlobalStack: boolean;
        } & {
            class?: any;
            width?: string | number | undefined;
            height?: string | number | undefined;
            theme?: string | undefined;
            target?: Element | vue.ComponentPublicInstance | (string & {}) | "parent" | "cursor" | [x: number, y: number] | undefined;
            offset?: string | number | number[] | undefined;
            contentClass?: any;
            opacity?: string | number | undefined;
            maxHeight?: string | number | undefined;
            maxWidth?: string | number | undefined;
            minHeight?: string | number | undefined;
            minWidth?: string | number | undefined;
            activator?: Element | vue.ComponentPublicInstance | (string & {}) | "parent" | undefined;
            closeDelay?: string | number | undefined;
            openDelay?: string | number | undefined;
            openOnClick?: boolean | undefined;
            openOnFocus?: boolean | undefined;
            contentProps?: any;
            attach?: string | boolean | Element | undefined;
        } & {
            $children?: vue.VNodeChild | {
                default?: ((arg: {
                    isActive: Ref<boolean>;
                }) => vue.VNodeChild) | undefined;
                activator?: ((arg: {
                    isActive: boolean;
                    props: Record<string, any>;
                    targetRef: TemplateRef;
                }) => vue.VNodeChild) | undefined;
            } | ((arg: {
                isActive: Ref<boolean>;
            }) => vue.VNodeChild);
            'v-slots'?: {
                default?: false | ((arg: {
                    isActive: Ref<boolean>;
                }) => vue.VNodeChild) | undefined;
                activator?: false | ((arg: {
                    isActive: boolean;
                    props: Record<string, any>;
                    targetRef: TemplateRef;
                }) => vue.VNodeChild) | undefined;
            } | undefined;
        } & {
            "v-slot:default"?: false | ((arg: {
                isActive: Ref<boolean>;
            }) => vue.VNodeChild) | undefined;
            "v-slot:activator"?: false | ((arg: {
                isActive: boolean;
                props: Record<string, any>;
                targetRef: TemplateRef;
            }) => vue.VNodeChild) | undefined;
        } & {
            "onUpdate:modelValue"?: ((value: boolean) => any) | undefined;
            onAfterEnter?: (() => any) | undefined;
            onAfterLeave?: (() => any) | undefined;
            "onClick:outside"?: ((e: MouseEvent) => any) | undefined;
        }, "style" | "disabled" | "absolute" | "transition" | "zIndex" | "modelValue" | "origin" | "eager" | "location" | "locationStrategy" | "scrollStrategy" | "activatorProps" | "openOnClick" | "openOnHover" | "openOnFocus" | "closeOnContentClick" | "closeOnBack" | "contained" | "noClickAnimation" | "persistent" | "scrim" | "_disableGlobalStack">;
        $attrs: {
            [x: string]: unknown;
        };
        $refs: {
            [x: string]: unknown;
        };
        $slots: Readonly<{
            default?: ((arg: {
                isActive: Ref<boolean>;
            }) => vue.VNode<vue.RendererNode, vue.RendererElement, {
                [key: string]: any;
            }>[]) | undefined;
            activator?: ((arg: {
                isActive: boolean;
                props: Record<string, any>;
                targetRef: TemplateRef;
            }) => vue.VNode<vue.RendererNode, vue.RendererElement, {
                [key: string]: any;
            }>[]) | undefined;
        }>;
        $root: vue.ComponentPublicInstance<{}, {}, {}, {}, {}, {}, {}, {}, false, vue.ComponentOptionsBase<any, any, any, any, any, any, any, any, any, {}, {}, string, {}>, {}, {}> | null;
        $parent: vue.ComponentPublicInstance<{}, {}, {}, {}, {}, {}, {}, {}, false, vue.ComponentOptionsBase<any, any, any, any, any, any, any, any, any, {}, {}, string, {}>, {}, {}> | null;
        $emit: ((event: "update:modelValue", value: boolean) => void) & ((event: "click:outside", e: MouseEvent) => void) & ((event: "afterEnter") => void) & ((event: "afterLeave") => void);
        $el: any;
        $options: vue.ComponentOptionsBase<{
            style: vue.StyleValue;
            disabled: boolean;
            absolute: boolean;
            transition: string | boolean | (vue.TransitionProps & {
                component?: vue.Component | undefined;
            });
            zIndex: string | number;
            modelValue: boolean;
            origin: Anchor | "auto" | "overlap";
            eager: boolean;
            location: Anchor;
            locationStrategy: "static" | ((data: LocationStrategyData, props: StrategyProps$1, contentStyles: Ref<Record<string, string>>) => {
                updateLocation: (e: Event) => void;
            } | undefined) | "connected";
            scrollStrategy: "close" | "none" | "block" | ((data: ScrollStrategyData, props: StrategyProps, scope: vue.EffectScope) => void) | "reposition";
            activatorProps: Record<string, any>;
            openOnHover: boolean;
            closeOnContentClick: boolean;
            closeOnBack: boolean;
            contained: boolean;
            noClickAnimation: boolean;
            persistent: boolean;
            scrim: string | boolean;
            _disableGlobalStack: boolean;
        } & {
            class?: any;
            width?: string | number | undefined;
            height?: string | number | undefined;
            theme?: string | undefined;
            target?: Element | vue.ComponentPublicInstance | (string & {}) | "parent" | "cursor" | [x: number, y: number] | undefined;
            offset?: string | number | number[] | undefined;
            contentClass?: any;
            opacity?: string | number | undefined;
            maxHeight?: string | number | undefined;
            maxWidth?: string | number | undefined;
            minHeight?: string | number | undefined;
            minWidth?: string | number | undefined;
            activator?: Element | vue.ComponentPublicInstance | (string & {}) | "parent" | undefined;
            closeDelay?: string | number | undefined;
            openDelay?: string | number | undefined;
            openOnClick?: boolean | undefined;
            openOnFocus?: boolean | undefined;
            contentProps?: any;
            attach?: string | boolean | Element | undefined;
        } & {
            $children?: vue.VNodeChild | {
                default?: ((arg: {
                    isActive: Ref<boolean>;
                }) => vue.VNodeChild) | undefined;
                activator?: ((arg: {
                    isActive: boolean;
                    props: Record<string, any>;
                    targetRef: TemplateRef;
                }) => vue.VNodeChild) | undefined;
            } | ((arg: {
                isActive: Ref<boolean>;
            }) => vue.VNodeChild);
            'v-slots'?: {
                default?: false | ((arg: {
                    isActive: Ref<boolean>;
                }) => vue.VNodeChild) | undefined;
                activator?: false | ((arg: {
                    isActive: boolean;
                    props: Record<string, any>;
                    targetRef: TemplateRef;
                }) => vue.VNodeChild) | undefined;
            } | undefined;
        } & {
            "v-slot:default"?: false | ((arg: {
                isActive: Ref<boolean>;
            }) => vue.VNodeChild) | undefined;
            "v-slot:activator"?: false | ((arg: {
                isActive: boolean;
                props: Record<string, any>;
                targetRef: TemplateRef;
            }) => vue.VNodeChild) | undefined;
        } & {
            "onUpdate:modelValue"?: ((value: boolean) => any) | undefined;
            onAfterEnter?: (() => any) | undefined;
            onAfterLeave?: (() => any) | undefined;
            "onClick:outside"?: ((e: MouseEvent) => any) | undefined;
        }, {
            activatorEl: Ref<HTMLElement | undefined>;
            scrimEl: Ref<HTMLElement | undefined>;
            target: vue.ComputedRef<HTMLElement | [x: number, y: number] | undefined>;
            animateClick: () => void;
            contentEl: Ref<HTMLElement | undefined>;
            globalTop: Readonly<Ref<boolean>>;
            localTop: vue.ComputedRef<boolean>;
            updateLocation: Ref<((e: Event) => void) | undefined>;
        }, unknown, {}, {}, vue.ComponentOptionsMixin, vue.ComponentOptionsMixin, {
            'click:outside': (e: MouseEvent) => true;
            'update:modelValue': (value: boolean) => true;
            afterEnter: () => true;
            afterLeave: () => true;
        }, string, {
            style: vue.StyleValue;
            disabled: boolean;
            absolute: boolean;
            transition: string | boolean | (vue.TransitionProps & {
                component?: vue.Component | undefined;
            });
            zIndex: string | number;
            modelValue: boolean;
            origin: Anchor | "auto" | "overlap";
            eager: boolean;
            location: Anchor;
            locationStrategy: "static" | ((data: LocationStrategyData, props: StrategyProps$1, contentStyles: Ref<Record<string, string>>) => {
                updateLocation: (e: Event) => void;
            } | undefined) | "connected";
            scrollStrategy: "close" | "none" | "block" | ((data: ScrollStrategyData, props: StrategyProps, scope: vue.EffectScope) => void) | "reposition";
            activatorProps: Record<string, any>;
            openOnClick: boolean;
            openOnHover: boolean;
            openOnFocus: boolean;
            closeOnContentClick: boolean;
            closeOnBack: boolean;
            contained: boolean;
            noClickAnimation: boolean;
            persistent: boolean;
            scrim: string | boolean;
            _disableGlobalStack: boolean;
        }, {}, string, vue.SlotsType<Partial<{
            default: (arg: {
                isActive: Ref<boolean>;
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
        }>>> & {
            beforeCreate?: ((() => void) | (() => void)[]) | undefined;
            created?: ((() => void) | (() => void)[]) | undefined;
            beforeMount?: ((() => void) | (() => void)[]) | undefined;
            mounted?: ((() => void) | (() => void)[]) | undefined;
            beforeUpdate?: ((() => void) | (() => void)[]) | undefined;
            updated?: ((() => void) | (() => void)[]) | undefined;
            activated?: ((() => void) | (() => void)[]) | undefined;
            deactivated?: ((() => void) | (() => void)[]) | undefined;
            beforeDestroy?: ((() => void) | (() => void)[]) | undefined;
            beforeUnmount?: ((() => void) | (() => void)[]) | undefined;
            destroyed?: ((() => void) | (() => void)[]) | undefined;
            unmounted?: ((() => void) | (() => void)[]) | undefined;
            renderTracked?: (((e: vue.DebuggerEvent) => void) | ((e: vue.DebuggerEvent) => void)[]) | undefined;
            renderTriggered?: (((e: vue.DebuggerEvent) => void) | ((e: vue.DebuggerEvent) => void)[]) | undefined;
            errorCaptured?: (((err: unknown, instance: vue.ComponentPublicInstance<{}, {}, {}, {}, {}, {}, {}, {}, false, vue.ComponentOptionsBase<any, any, any, any, any, any, any, any, any, {}, {}, string, {}>, {}, {}> | null, info: string) => boolean | void) | ((err: unknown, instance: vue.ComponentPublicInstance<{}, {}, {}, {}, {}, {}, {}, {}, false, vue.ComponentOptionsBase<any, any, any, any, any, any, any, any, any, {}, {}, string, {}>, {}, {}> | null, info: string) => boolean | void)[]) | undefined;
        };
        $forceUpdate: () => void;
        $nextTick: typeof nextTick;
        $watch<T extends string | ((...args: any) => any)>(source: T, cb: T extends (...args: any) => infer R ? (args_0: R, args_1: R) => any : (...args: any) => any, options?: vue.WatchOptions<boolean> | undefined): vue.WatchStopHandle;
    } & Omit<{
        style: vue.StyleValue;
        disabled: boolean;
        absolute: boolean;
        transition: string | boolean | (vue.TransitionProps & {
            component?: vue.Component | undefined;
        });
        zIndex: string | number;
        modelValue: boolean;
        origin: Anchor | "auto" | "overlap";
        eager: boolean;
        location: Anchor;
        locationStrategy: "static" | ((data: LocationStrategyData, props: StrategyProps$1, contentStyles: Ref<Record<string, string>>) => {
            updateLocation: (e: Event) => void;
        } | undefined) | "connected";
        scrollStrategy: "close" | "none" | "block" | ((data: ScrollStrategyData, props: StrategyProps, scope: vue.EffectScope) => void) | "reposition";
        activatorProps: Record<string, any>;
        openOnHover: boolean;
        closeOnContentClick: boolean;
        closeOnBack: boolean;
        contained: boolean;
        noClickAnimation: boolean;
        persistent: boolean;
        scrim: string | boolean;
        _disableGlobalStack: boolean;
    } & {
        class?: any;
        width?: string | number | undefined;
        height?: string | number | undefined;
        theme?: string | undefined;
        target?: Element | vue.ComponentPublicInstance | (string & {}) | "parent" | "cursor" | [x: number, y: number] | undefined;
        offset?: string | number | number[] | undefined;
        contentClass?: any;
        opacity?: string | number | undefined;
        maxHeight?: string | number | undefined;
        maxWidth?: string | number | undefined;
        minHeight?: string | number | undefined;
        minWidth?: string | number | undefined;
        activator?: Element | vue.ComponentPublicInstance | (string & {}) | "parent" | undefined;
        closeDelay?: string | number | undefined;
        openDelay?: string | number | undefined;
        openOnClick?: boolean | undefined;
        openOnFocus?: boolean | undefined;
        contentProps?: any;
        attach?: string | boolean | Element | undefined;
    } & {
        $children?: vue.VNodeChild | {
            default?: ((arg: {
                isActive: Ref<boolean>;
            }) => vue.VNodeChild) | undefined;
            activator?: ((arg: {
                isActive: boolean;
                props: Record<string, any>;
                targetRef: TemplateRef;
            }) => vue.VNodeChild) | undefined;
        } | ((arg: {
            isActive: Ref<boolean>;
        }) => vue.VNodeChild);
        'v-slots'?: {
            default?: false | ((arg: {
                isActive: Ref<boolean>;
            }) => vue.VNodeChild) | undefined;
            activator?: false | ((arg: {
                isActive: boolean;
                props: Record<string, any>;
                targetRef: TemplateRef;
            }) => vue.VNodeChild) | undefined;
        } | undefined;
    } & {
        "v-slot:default"?: false | ((arg: {
            isActive: Ref<boolean>;
        }) => vue.VNodeChild) | undefined;
        "v-slot:activator"?: false | ((arg: {
            isActive: boolean;
            props: Record<string, any>;
            targetRef: TemplateRef;
        }) => vue.VNodeChild) | undefined;
    } & {
        "onUpdate:modelValue"?: ((value: boolean) => any) | undefined;
        onAfterEnter?: (() => any) | undefined;
        onAfterLeave?: (() => any) | undefined;
        "onClick:outside"?: ((e: MouseEvent) => any) | undefined;
    }, "target" | "activatorEl" | "scrimEl" | "animateClick" | "contentEl" | "globalTop" | "localTop" | "updateLocation"> & vue.ShallowUnwrapRef<{
        activatorEl: Ref<HTMLElement | undefined>;
        scrimEl: Ref<HTMLElement | undefined>;
        target: vue.ComputedRef<HTMLElement | [x: number, y: number] | undefined>;
        animateClick: () => void;
        contentEl: Ref<HTMLElement | undefined>;
        globalTop: Readonly<Ref<boolean>>;
        localTop: vue.ComputedRef<boolean>;
        updateLocation: Ref<((e: Event) => void) | undefined>;
    }> & {} & vue.ComponentCustomProperties & {}, "class" | "width" | "height" | "theme" | "key" | "target" | "v-slot:default" | "$children" | "v-slots" | "ref" | "ref_for" | "ref_key" | "onVnodeBeforeMount" | "onVnodeMounted" | "onVnodeBeforeUpdate" | "onVnodeUpdated" | "onVnodeBeforeUnmount" | "onVnodeUnmounted" | "offset" | "onUpdate:modelValue" | "contentClass" | "opacity" | "maxHeight" | "maxWidth" | "minHeight" | "minWidth" | "onAfterEnter" | "onAfterLeave" | "activator" | "v-slot:activator" | "closeDelay" | "openDelay" | "contentProps" | "attach" | "onClick:outside" | ("style" | "disabled" | "absolute" | "transition" | "zIndex" | "modelValue" | "origin" | "eager" | "location" | "locationStrategy" | "scrollStrategy" | "activatorProps" | "openOnClick" | "openOnHover" | "openOnFocus" | "closeOnContentClick" | "closeOnBack" | "contained" | "noClickAnimation" | "persistent" | "scrim" | "_disableGlobalStack")>, `$${any}`>, unknown, {}, {}, vue.ComponentOptionsMixin, vue.ComponentOptionsMixin, {
        'update:modelValue': (v: boolean) => boolean;
    }, vue.VNodeProps & vue.AllowedComponentProps & vue.ComponentCustomProps & {
        style: vue.StyleValue;
        disabled: boolean;
        absolute: boolean;
        transition: NonNullable<string | boolean | (vue.TransitionProps & {
            component?: vue.Component | undefined;
        })>;
        zIndex: string | number;
        modelValue: boolean;
        variant: "flat" | "text" | "elevated" | "tonal" | "outlined" | "plain";
        origin: Anchor | "auto" | "overlap";
        vertical: boolean;
        tile: boolean;
        eager: boolean;
        location: Anchor;
        locationStrategy: "static" | ((data: LocationStrategyData, props: StrategyProps$1, contentStyles: Ref<Record<string, string>>) => {
            updateLocation: (e: Event) => void;
        } | undefined) | "connected";
        activatorProps: Record<string, any>;
        openOnHover: boolean;
        closeOnContentClick: boolean;
        closeOnBack: boolean;
        contained: boolean;
        multiLine: boolean;
        timeout: string | number;
    } & {
        class?: any;
        text?: string | undefined;
        width?: string | number | undefined;
        height?: string | number | undefined;
        theme?: string | undefined;
        target?: Element | vue.ComponentPublicInstance | (string & {}) | "parent" | "cursor" | [x: number, y: number] | undefined;
        color?: string | undefined;
        offset?: string | number | number[] | undefined;
        position?: "fixed" | "absolute" | "relative" | "static" | "sticky" | undefined;
        rounded?: string | number | boolean | undefined;
        contentClass?: any;
        opacity?: string | number | undefined;
        maxHeight?: string | number | undefined;
        maxWidth?: string | number | undefined;
        minHeight?: string | number | undefined;
        minWidth?: string | number | undefined;
        activator?: Element | vue.ComponentPublicInstance | (string & {}) | "parent" | undefined;
        closeDelay?: string | number | undefined;
        openDelay?: string | number | undefined;
        openOnClick?: boolean | undefined;
        openOnFocus?: boolean | undefined;
        contentProps?: any;
        attach?: string | boolean | Element | undefined;
        timer?: string | boolean | undefined;
    } & {
        $children?: vue.VNodeChild | (() => vue.VNodeChild) | {
            activator?: ((arg: {
                isActive: boolean;
                props: Record<string, any>;
            }) => vue.VNodeChild) | undefined;
            default?: (() => vue.VNodeChild) | undefined;
            actions?: ((arg: {
                isActive: Ref<boolean>;
            }) => vue.VNodeChild) | undefined;
            text?: (() => vue.VNodeChild) | undefined;
        };
        'v-slots'?: {
            activator?: false | ((arg: {
                isActive: boolean;
                props: Record<string, any>;
            }) => vue.VNodeChild) | undefined;
            default?: false | (() => vue.VNodeChild) | undefined;
            actions?: false | ((arg: {
                isActive: Ref<boolean>;
            }) => vue.VNodeChild) | undefined;
            text?: false | (() => vue.VNodeChild) | undefined;
        } | undefined;
    } & {
        "v-slot:activator"?: false | ((arg: {
            isActive: boolean;
            props: Record<string, any>;
        }) => vue.VNodeChild) | undefined;
        "v-slot:default"?: false | (() => vue.VNodeChild) | undefined;
        "v-slot:actions"?: false | ((arg: {
            isActive: Ref<boolean>;
        }) => vue.VNodeChild) | undefined;
        "v-slot:text"?: false | (() => vue.VNodeChild) | undefined;
    } & {
        "onUpdate:modelValue"?: ((v: boolean) => any) | undefined;
    }, {
        style: vue.StyleValue;
        disabled: boolean;
        absolute: boolean;
        transition: NonNullable<string | boolean | (vue.TransitionProps & {
            component?: vue.Component | undefined;
        })>;
        zIndex: string | number;
        modelValue: boolean;
        rounded: string | number | boolean;
        variant: "flat" | "text" | "elevated" | "tonal" | "outlined" | "plain";
        origin: Anchor | "auto" | "overlap";
        vertical: boolean;
        tile: boolean;
        eager: boolean;
        location: Anchor;
        locationStrategy: "static" | ((data: LocationStrategyData, props: StrategyProps$1, contentStyles: Ref<Record<string, string>>) => {
            updateLocation: (e: Event) => void;
        } | undefined) | "connected";
        activatorProps: Record<string, any>;
        openOnClick: boolean;
        openOnHover: boolean;
        openOnFocus: boolean;
        closeOnContentClick: boolean;
        closeOnBack: boolean;
        contained: boolean;
        multiLine: boolean;
        timeout: string | number;
    }, true, {}, vue.SlotsType<Partial<{
        activator: (arg: {
            isActive: boolean;
            props: Record<string, any>;
        }) => vue.VNode<vue.RendererNode, vue.RendererElement, {
            [key: string]: any;
        }>[];
        default: () => vue.VNode<vue.RendererNode, vue.RendererElement, {
            [key: string]: any;
        }>[];
        actions: (arg: {
            isActive: Ref<boolean>;
        }) => vue.VNode<vue.RendererNode, vue.RendererElement, {
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
        disabled: boolean;
        absolute: boolean;
        transition: NonNullable<string | boolean | (vue.TransitionProps & {
            component?: vue.Component | undefined;
        })>;
        zIndex: string | number;
        modelValue: boolean;
        variant: "flat" | "text" | "elevated" | "tonal" | "outlined" | "plain";
        origin: Anchor | "auto" | "overlap";
        vertical: boolean;
        tile: boolean;
        eager: boolean;
        location: Anchor;
        locationStrategy: "static" | ((data: LocationStrategyData, props: StrategyProps$1, contentStyles: Ref<Record<string, string>>) => {
            updateLocation: (e: Event) => void;
        } | undefined) | "connected";
        activatorProps: Record<string, any>;
        openOnHover: boolean;
        closeOnContentClick: boolean;
        closeOnBack: boolean;
        contained: boolean;
        multiLine: boolean;
        timeout: string | number;
    } & {
        class?: any;
        text?: string | undefined;
        width?: string | number | undefined;
        height?: string | number | undefined;
        theme?: string | undefined;
        target?: Element | vue.ComponentPublicInstance | (string & {}) | "parent" | "cursor" | [x: number, y: number] | undefined;
        color?: string | undefined;
        offset?: string | number | number[] | undefined;
        position?: "fixed" | "absolute" | "relative" | "static" | "sticky" | undefined;
        rounded?: string | number | boolean | undefined;
        contentClass?: any;
        opacity?: string | number | undefined;
        maxHeight?: string | number | undefined;
        maxWidth?: string | number | undefined;
        minHeight?: string | number | undefined;
        minWidth?: string | number | undefined;
        activator?: Element | vue.ComponentPublicInstance | (string & {}) | "parent" | undefined;
        closeDelay?: string | number | undefined;
        openDelay?: string | number | undefined;
        openOnClick?: boolean | undefined;
        openOnFocus?: boolean | undefined;
        contentProps?: any;
        attach?: string | boolean | Element | undefined;
        timer?: string | boolean | undefined;
    } & {
        $children?: vue.VNodeChild | (() => vue.VNodeChild) | {
            activator?: ((arg: {
                isActive: boolean;
                props: Record<string, any>;
            }) => vue.VNodeChild) | undefined;
            default?: (() => vue.VNodeChild) | undefined;
            actions?: ((arg: {
                isActive: Ref<boolean>;
            }) => vue.VNodeChild) | undefined;
            text?: (() => vue.VNodeChild) | undefined;
        };
        'v-slots'?: {
            activator?: false | ((arg: {
                isActive: boolean;
                props: Record<string, any>;
            }) => vue.VNodeChild) | undefined;
            default?: false | (() => vue.VNodeChild) | undefined;
            actions?: false | ((arg: {
                isActive: Ref<boolean>;
            }) => vue.VNodeChild) | undefined;
            text?: false | (() => vue.VNodeChild) | undefined;
        } | undefined;
    } & {
        "v-slot:activator"?: false | ((arg: {
            isActive: boolean;
            props: Record<string, any>;
        }) => vue.VNodeChild) | undefined;
        "v-slot:default"?: false | (() => vue.VNodeChild) | undefined;
        "v-slot:actions"?: false | ((arg: {
            isActive: Ref<boolean>;
        }) => vue.VNodeChild) | undefined;
        "v-slot:text"?: false | (() => vue.VNodeChild) | undefined;
    } & {
        "onUpdate:modelValue"?: ((v: boolean) => any) | undefined;
    }, Omit<Omit<{
        $: vue.ComponentInternalInstance;
        $data: {};
        $props: Partial<{
            style: vue.StyleValue;
            disabled: boolean;
            absolute: boolean;
            transition: string | boolean | (vue.TransitionProps & {
                component?: vue.Component | undefined;
            });
            zIndex: string | number;
            modelValue: boolean;
            origin: Anchor | "auto" | "overlap";
            eager: boolean;
            location: Anchor;
            locationStrategy: "static" | ((data: LocationStrategyData, props: StrategyProps$1, contentStyles: Ref<Record<string, string>>) => {
                updateLocation: (e: Event) => void;
            } | undefined) | "connected";
            scrollStrategy: "close" | "none" | "block" | ((data: ScrollStrategyData, props: StrategyProps, scope: vue.EffectScope) => void) | "reposition";
            activatorProps: Record<string, any>;
            openOnClick: boolean;
            openOnHover: boolean;
            openOnFocus: boolean;
            closeOnContentClick: boolean;
            closeOnBack: boolean;
            contained: boolean;
            noClickAnimation: boolean;
            persistent: boolean;
            scrim: string | boolean;
            _disableGlobalStack: boolean;
        }> & Omit<{
            style: vue.StyleValue;
            disabled: boolean;
            absolute: boolean;
            transition: string | boolean | (vue.TransitionProps & {
                component?: vue.Component | undefined;
            });
            zIndex: string | number;
            modelValue: boolean;
            origin: Anchor | "auto" | "overlap";
            eager: boolean;
            location: Anchor;
            locationStrategy: "static" | ((data: LocationStrategyData, props: StrategyProps$1, contentStyles: Ref<Record<string, string>>) => {
                updateLocation: (e: Event) => void;
            } | undefined) | "connected";
            scrollStrategy: "close" | "none" | "block" | ((data: ScrollStrategyData, props: StrategyProps, scope: vue.EffectScope) => void) | "reposition";
            activatorProps: Record<string, any>;
            openOnHover: boolean;
            closeOnContentClick: boolean;
            closeOnBack: boolean;
            contained: boolean;
            noClickAnimation: boolean;
            persistent: boolean;
            scrim: string | boolean;
            _disableGlobalStack: boolean;
            class?: any;
            width?: string | number | undefined;
            height?: string | number | undefined;
            theme?: string | undefined;
            target?: Element | vue.ComponentPublicInstance | (string & {}) | "parent" | "cursor" | [x: number, y: number] | undefined;
            offset?: string | number | number[] | undefined;
            contentClass?: any;
            opacity?: string | number | undefined;
            maxHeight?: string | number | undefined;
            maxWidth?: string | number | undefined;
            minHeight?: string | number | undefined;
            minWidth?: string | number | undefined;
            activator?: Element | vue.ComponentPublicInstance | (string & {}) | "parent" | undefined;
            closeDelay?: string | number | undefined;
            openDelay?: string | number | undefined;
            openOnClick?: boolean | undefined;
            openOnFocus?: boolean | undefined;
            contentProps?: any;
            attach?: string | boolean | Element | undefined;
            $children?: vue.VNodeChild | {
                default?: ((arg: {
                    isActive: Ref<boolean>;
                }) => vue.VNodeChild) | undefined;
                activator?: ((arg: {
                    isActive: boolean;
                    props: Record<string, any>;
                    targetRef: TemplateRef;
                }) => vue.VNodeChild) | undefined;
            } | ((arg: {
                isActive: Ref<boolean>;
            }) => vue.VNodeChild);
            'v-slots'?: {
                default?: false | ((arg: {
                    isActive: Ref<boolean>;
                }) => vue.VNodeChild) | undefined;
                activator?: false | ((arg: {
                    isActive: boolean;
                    props: Record<string, any>;
                    targetRef: TemplateRef;
                }) => vue.VNodeChild) | undefined;
            } | undefined;
            "v-slot:default"?: false | ((arg: {
                isActive: Ref<boolean>;
            }) => vue.VNodeChild) | undefined;
            "v-slot:activator"?: false | ((arg: {
                isActive: boolean;
                props: Record<string, any>;
                targetRef: TemplateRef;
            }) => vue.VNodeChild) | undefined;
            "onUpdate:modelValue"?: ((value: boolean) => any) | undefined;
            onAfterEnter?: (() => any) | undefined;
            onAfterLeave?: (() => any) | undefined;
            "onClick:outside"?: ((e: MouseEvent) => any) | undefined;
        } & vue.VNodeProps & vue.AllowedComponentProps & vue.ComponentCustomProps & {
            style: vue.StyleValue;
            disabled: boolean;
            absolute: boolean;
            transition: string | boolean | (vue.TransitionProps & {
                component?: vue.Component | undefined;
            });
            zIndex: string | number;
            modelValue: boolean;
            origin: Anchor | "auto" | "overlap";
            eager: boolean;
            location: Anchor;
            locationStrategy: "static" | ((data: LocationStrategyData, props: StrategyProps$1, contentStyles: Ref<Record<string, string>>) => {
                updateLocation: (e: Event) => void;
            } | undefined) | "connected";
            scrollStrategy: "close" | "none" | "block" | ((data: ScrollStrategyData, props: StrategyProps, scope: vue.EffectScope) => void) | "reposition";
            activatorProps: Record<string, any>;
            openOnHover: boolean;
            closeOnContentClick: boolean;
            closeOnBack: boolean;
            contained: boolean;
            noClickAnimation: boolean;
            persistent: boolean;
            scrim: string | boolean;
            _disableGlobalStack: boolean;
        } & {
            class?: any;
            width?: string | number | undefined;
            height?: string | number | undefined;
            theme?: string | undefined;
            target?: Element | vue.ComponentPublicInstance | (string & {}) | "parent" | "cursor" | [x: number, y: number] | undefined;
            offset?: string | number | number[] | undefined;
            contentClass?: any;
            opacity?: string | number | undefined;
            maxHeight?: string | number | undefined;
            maxWidth?: string | number | undefined;
            minHeight?: string | number | undefined;
            minWidth?: string | number | undefined;
            activator?: Element | vue.ComponentPublicInstance | (string & {}) | "parent" | undefined;
            closeDelay?: string | number | undefined;
            openDelay?: string | number | undefined;
            openOnClick?: boolean | undefined;
            openOnFocus?: boolean | undefined;
            contentProps?: any;
            attach?: string | boolean | Element | undefined;
        } & {
            $children?: vue.VNodeChild | {
                default?: ((arg: {
                    isActive: Ref<boolean>;
                }) => vue.VNodeChild) | undefined;
                activator?: ((arg: {
                    isActive: boolean;
                    props: Record<string, any>;
                    targetRef: TemplateRef;
                }) => vue.VNodeChild) | undefined;
            } | ((arg: {
                isActive: Ref<boolean>;
            }) => vue.VNodeChild);
            'v-slots'?: {
                default?: false | ((arg: {
                    isActive: Ref<boolean>;
                }) => vue.VNodeChild) | undefined;
                activator?: false | ((arg: {
                    isActive: boolean;
                    props: Record<string, any>;
                    targetRef: TemplateRef;
                }) => vue.VNodeChild) | undefined;
            } | undefined;
        } & {
            "v-slot:default"?: false | ((arg: {
                isActive: Ref<boolean>;
            }) => vue.VNodeChild) | undefined;
            "v-slot:activator"?: false | ((arg: {
                isActive: boolean;
                props: Record<string, any>;
                targetRef: TemplateRef;
            }) => vue.VNodeChild) | undefined;
        } & {
            "onUpdate:modelValue"?: ((value: boolean) => any) | undefined;
            onAfterEnter?: (() => any) | undefined;
            onAfterLeave?: (() => any) | undefined;
            "onClick:outside"?: ((e: MouseEvent) => any) | undefined;
        }, "style" | "disabled" | "absolute" | "transition" | "zIndex" | "modelValue" | "origin" | "eager" | "location" | "locationStrategy" | "scrollStrategy" | "activatorProps" | "openOnClick" | "openOnHover" | "openOnFocus" | "closeOnContentClick" | "closeOnBack" | "contained" | "noClickAnimation" | "persistent" | "scrim" | "_disableGlobalStack">;
        $attrs: {
            [x: string]: unknown;
        };
        $refs: {
            [x: string]: unknown;
        };
        $slots: Readonly<{
            default?: ((arg: {
                isActive: Ref<boolean>;
            }) => vue.VNode<vue.RendererNode, vue.RendererElement, {
                [key: string]: any;
            }>[]) | undefined;
            activator?: ((arg: {
                isActive: boolean;
                props: Record<string, any>;
                targetRef: TemplateRef;
            }) => vue.VNode<vue.RendererNode, vue.RendererElement, {
                [key: string]: any;
            }>[]) | undefined;
        }>;
        $root: vue.ComponentPublicInstance<{}, {}, {}, {}, {}, {}, {}, {}, false, vue.ComponentOptionsBase<any, any, any, any, any, any, any, any, any, {}, {}, string, {}>, {}, {}> | null;
        $parent: vue.ComponentPublicInstance<{}, {}, {}, {}, {}, {}, {}, {}, false, vue.ComponentOptionsBase<any, any, any, any, any, any, any, any, any, {}, {}, string, {}>, {}, {}> | null;
        $emit: ((event: "update:modelValue", value: boolean) => void) & ((event: "click:outside", e: MouseEvent) => void) & ((event: "afterEnter") => void) & ((event: "afterLeave") => void);
        $el: any;
        $options: vue.ComponentOptionsBase<{
            style: vue.StyleValue;
            disabled: boolean;
            absolute: boolean;
            transition: string | boolean | (vue.TransitionProps & {
                component?: vue.Component | undefined;
            });
            zIndex: string | number;
            modelValue: boolean;
            origin: Anchor | "auto" | "overlap";
            eager: boolean;
            location: Anchor;
            locationStrategy: "static" | ((data: LocationStrategyData, props: StrategyProps$1, contentStyles: Ref<Record<string, string>>) => {
                updateLocation: (e: Event) => void;
            } | undefined) | "connected";
            scrollStrategy: "close" | "none" | "block" | ((data: ScrollStrategyData, props: StrategyProps, scope: vue.EffectScope) => void) | "reposition";
            activatorProps: Record<string, any>;
            openOnHover: boolean;
            closeOnContentClick: boolean;
            closeOnBack: boolean;
            contained: boolean;
            noClickAnimation: boolean;
            persistent: boolean;
            scrim: string | boolean;
            _disableGlobalStack: boolean;
        } & {
            class?: any;
            width?: string | number | undefined;
            height?: string | number | undefined;
            theme?: string | undefined;
            target?: Element | vue.ComponentPublicInstance | (string & {}) | "parent" | "cursor" | [x: number, y: number] | undefined;
            offset?: string | number | number[] | undefined;
            contentClass?: any;
            opacity?: string | number | undefined;
            maxHeight?: string | number | undefined;
            maxWidth?: string | number | undefined;
            minHeight?: string | number | undefined;
            minWidth?: string | number | undefined;
            activator?: Element | vue.ComponentPublicInstance | (string & {}) | "parent" | undefined;
            closeDelay?: string | number | undefined;
            openDelay?: string | number | undefined;
            openOnClick?: boolean | undefined;
            openOnFocus?: boolean | undefined;
            contentProps?: any;
            attach?: string | boolean | Element | undefined;
        } & {
            $children?: vue.VNodeChild | {
                default?: ((arg: {
                    isActive: Ref<boolean>;
                }) => vue.VNodeChild) | undefined;
                activator?: ((arg: {
                    isActive: boolean;
                    props: Record<string, any>;
                    targetRef: TemplateRef;
                }) => vue.VNodeChild) | undefined;
            } | ((arg: {
                isActive: Ref<boolean>;
            }) => vue.VNodeChild);
            'v-slots'?: {
                default?: false | ((arg: {
                    isActive: Ref<boolean>;
                }) => vue.VNodeChild) | undefined;
                activator?: false | ((arg: {
                    isActive: boolean;
                    props: Record<string, any>;
                    targetRef: TemplateRef;
                }) => vue.VNodeChild) | undefined;
            } | undefined;
        } & {
            "v-slot:default"?: false | ((arg: {
                isActive: Ref<boolean>;
            }) => vue.VNodeChild) | undefined;
            "v-slot:activator"?: false | ((arg: {
                isActive: boolean;
                props: Record<string, any>;
                targetRef: TemplateRef;
            }) => vue.VNodeChild) | undefined;
        } & {
            "onUpdate:modelValue"?: ((value: boolean) => any) | undefined;
            onAfterEnter?: (() => any) | undefined;
            onAfterLeave?: (() => any) | undefined;
            "onClick:outside"?: ((e: MouseEvent) => any) | undefined;
        }, {
            activatorEl: Ref<HTMLElement | undefined>;
            scrimEl: Ref<HTMLElement | undefined>;
            target: vue.ComputedRef<HTMLElement | [x: number, y: number] | undefined>;
            animateClick: () => void;
            contentEl: Ref<HTMLElement | undefined>;
            globalTop: Readonly<Ref<boolean>>;
            localTop: vue.ComputedRef<boolean>;
            updateLocation: Ref<((e: Event) => void) | undefined>;
        }, unknown, {}, {}, vue.ComponentOptionsMixin, vue.ComponentOptionsMixin, {
            'click:outside': (e: MouseEvent) => true;
            'update:modelValue': (value: boolean) => true;
            afterEnter: () => true;
            afterLeave: () => true;
        }, string, {
            style: vue.StyleValue;
            disabled: boolean;
            absolute: boolean;
            transition: string | boolean | (vue.TransitionProps & {
                component?: vue.Component | undefined;
            });
            zIndex: string | number;
            modelValue: boolean;
            origin: Anchor | "auto" | "overlap";
            eager: boolean;
            location: Anchor;
            locationStrategy: "static" | ((data: LocationStrategyData, props: StrategyProps$1, contentStyles: Ref<Record<string, string>>) => {
                updateLocation: (e: Event) => void;
            } | undefined) | "connected";
            scrollStrategy: "close" | "none" | "block" | ((data: ScrollStrategyData, props: StrategyProps, scope: vue.EffectScope) => void) | "reposition";
            activatorProps: Record<string, any>;
            openOnClick: boolean;
            openOnHover: boolean;
            openOnFocus: boolean;
            closeOnContentClick: boolean;
            closeOnBack: boolean;
            contained: boolean;
            noClickAnimation: boolean;
            persistent: boolean;
            scrim: string | boolean;
            _disableGlobalStack: boolean;
        }, {}, string, vue.SlotsType<Partial<{
            default: (arg: {
                isActive: Ref<boolean>;
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
        }>>> & {
            beforeCreate?: ((() => void) | (() => void)[]) | undefined;
            created?: ((() => void) | (() => void)[]) | undefined;
            beforeMount?: ((() => void) | (() => void)[]) | undefined;
            mounted?: ((() => void) | (() => void)[]) | undefined;
            beforeUpdate?: ((() => void) | (() => void)[]) | undefined;
            updated?: ((() => void) | (() => void)[]) | undefined;
            activated?: ((() => void) | (() => void)[]) | undefined;
            deactivated?: ((() => void) | (() => void)[]) | undefined;
            beforeDestroy?: ((() => void) | (() => void)[]) | undefined;
            beforeUnmount?: ((() => void) | (() => void)[]) | undefined;
            destroyed?: ((() => void) | (() => void)[]) | undefined;
            unmounted?: ((() => void) | (() => void)[]) | undefined;
            renderTracked?: (((e: vue.DebuggerEvent) => void) | ((e: vue.DebuggerEvent) => void)[]) | undefined;
            renderTriggered?: (((e: vue.DebuggerEvent) => void) | ((e: vue.DebuggerEvent) => void)[]) | undefined;
            errorCaptured?: (((err: unknown, instance: vue.ComponentPublicInstance<{}, {}, {}, {}, {}, {}, {}, {}, false, vue.ComponentOptionsBase<any, any, any, any, any, any, any, any, any, {}, {}, string, {}>, {}, {}> | null, info: string) => boolean | void) | ((err: unknown, instance: vue.ComponentPublicInstance<{}, {}, {}, {}, {}, {}, {}, {}, false, vue.ComponentOptionsBase<any, any, any, any, any, any, any, any, any, {}, {}, string, {}>, {}, {}> | null, info: string) => boolean | void)[]) | undefined;
        };
        $forceUpdate: () => void;
        $nextTick: typeof nextTick;
        $watch<T extends string | ((...args: any) => any)>(source: T, cb: T extends (...args: any) => infer R ? (args_0: R, args_1: R) => any : (...args: any) => any, options?: vue.WatchOptions<boolean> | undefined): vue.WatchStopHandle;
    } & Omit<{
        style: vue.StyleValue;
        disabled: boolean;
        absolute: boolean;
        transition: string | boolean | (vue.TransitionProps & {
            component?: vue.Component | undefined;
        });
        zIndex: string | number;
        modelValue: boolean;
        origin: Anchor | "auto" | "overlap";
        eager: boolean;
        location: Anchor;
        locationStrategy: "static" | ((data: LocationStrategyData, props: StrategyProps$1, contentStyles: Ref<Record<string, string>>) => {
            updateLocation: (e: Event) => void;
        } | undefined) | "connected";
        scrollStrategy: "close" | "none" | "block" | ((data: ScrollStrategyData, props: StrategyProps, scope: vue.EffectScope) => void) | "reposition";
        activatorProps: Record<string, any>;
        openOnHover: boolean;
        closeOnContentClick: boolean;
        closeOnBack: boolean;
        contained: boolean;
        noClickAnimation: boolean;
        persistent: boolean;
        scrim: string | boolean;
        _disableGlobalStack: boolean;
    } & {
        class?: any;
        width?: string | number | undefined;
        height?: string | number | undefined;
        theme?: string | undefined;
        target?: Element | vue.ComponentPublicInstance | (string & {}) | "parent" | "cursor" | [x: number, y: number] | undefined;
        offset?: string | number | number[] | undefined;
        contentClass?: any;
        opacity?: string | number | undefined;
        maxHeight?: string | number | undefined;
        maxWidth?: string | number | undefined;
        minHeight?: string | number | undefined;
        minWidth?: string | number | undefined;
        activator?: Element | vue.ComponentPublicInstance | (string & {}) | "parent" | undefined;
        closeDelay?: string | number | undefined;
        openDelay?: string | number | undefined;
        openOnClick?: boolean | undefined;
        openOnFocus?: boolean | undefined;
        contentProps?: any;
        attach?: string | boolean | Element | undefined;
    } & {
        $children?: vue.VNodeChild | {
            default?: ((arg: {
                isActive: Ref<boolean>;
            }) => vue.VNodeChild) | undefined;
            activator?: ((arg: {
                isActive: boolean;
                props: Record<string, any>;
                targetRef: TemplateRef;
            }) => vue.VNodeChild) | undefined;
        } | ((arg: {
            isActive: Ref<boolean>;
        }) => vue.VNodeChild);
        'v-slots'?: {
            default?: false | ((arg: {
                isActive: Ref<boolean>;
            }) => vue.VNodeChild) | undefined;
            activator?: false | ((arg: {
                isActive: boolean;
                props: Record<string, any>;
                targetRef: TemplateRef;
            }) => vue.VNodeChild) | undefined;
        } | undefined;
    } & {
        "v-slot:default"?: false | ((arg: {
            isActive: Ref<boolean>;
        }) => vue.VNodeChild) | undefined;
        "v-slot:activator"?: false | ((arg: {
            isActive: boolean;
            props: Record<string, any>;
            targetRef: TemplateRef;
        }) => vue.VNodeChild) | undefined;
    } & {
        "onUpdate:modelValue"?: ((value: boolean) => any) | undefined;
        onAfterEnter?: (() => any) | undefined;
        onAfterLeave?: (() => any) | undefined;
        "onClick:outside"?: ((e: MouseEvent) => any) | undefined;
    }, "target" | "activatorEl" | "scrimEl" | "animateClick" | "contentEl" | "globalTop" | "localTop" | "updateLocation"> & vue.ShallowUnwrapRef<{
        activatorEl: Ref<HTMLElement | undefined>;
        scrimEl: Ref<HTMLElement | undefined>;
        target: vue.ComputedRef<HTMLElement | [x: number, y: number] | undefined>;
        animateClick: () => void;
        contentEl: Ref<HTMLElement | undefined>;
        globalTop: Readonly<Ref<boolean>>;
        localTop: vue.ComputedRef<boolean>;
        updateLocation: Ref<((e: Event) => void) | undefined>;
    }> & {} & vue.ComponentCustomProperties & {}, "class" | "width" | "height" | "theme" | "key" | "target" | "v-slot:default" | "$children" | "v-slots" | "ref" | "ref_for" | "ref_key" | "onVnodeBeforeMount" | "onVnodeMounted" | "onVnodeBeforeUpdate" | "onVnodeUpdated" | "onVnodeBeforeUnmount" | "onVnodeUnmounted" | "offset" | "onUpdate:modelValue" | "contentClass" | "opacity" | "maxHeight" | "maxWidth" | "minHeight" | "minWidth" | "onAfterEnter" | "onAfterLeave" | "activator" | "v-slot:activator" | "closeDelay" | "openDelay" | "contentProps" | "attach" | "onClick:outside" | ("style" | "disabled" | "absolute" | "transition" | "zIndex" | "modelValue" | "origin" | "eager" | "location" | "locationStrategy" | "scrollStrategy" | "activatorProps" | "openOnClick" | "openOnHover" | "openOnFocus" | "closeOnContentClick" | "closeOnBack" | "contained" | "noClickAnimation" | "persistent" | "scrim" | "_disableGlobalStack")>, `$${any}`>, {}, {}, {}, {
        style: vue.StyleValue;
        disabled: boolean;
        absolute: boolean;
        transition: NonNullable<string | boolean | (vue.TransitionProps & {
            component?: vue.Component | undefined;
        })>;
        zIndex: string | number;
        modelValue: boolean;
        rounded: string | number | boolean;
        variant: "flat" | "text" | "elevated" | "tonal" | "outlined" | "plain";
        origin: Anchor | "auto" | "overlap";
        vertical: boolean;
        tile: boolean;
        eager: boolean;
        location: Anchor;
        locationStrategy: "static" | ((data: LocationStrategyData, props: StrategyProps$1, contentStyles: Ref<Record<string, string>>) => {
            updateLocation: (e: Event) => void;
        } | undefined) | "connected";
        activatorProps: Record<string, any>;
        openOnClick: boolean;
        openOnHover: boolean;
        openOnFocus: boolean;
        closeOnContentClick: boolean;
        closeOnBack: boolean;
        contained: boolean;
        multiLine: boolean;
        timeout: string | number;
    }>;
    __isFragment?: undefined;
    __isTeleport?: undefined;
    __isSuspense?: undefined;
} & vue.ComponentOptionsBase<{
    style: vue.StyleValue;
    disabled: boolean;
    absolute: boolean;
    transition: NonNullable<string | boolean | (vue.TransitionProps & {
        component?: vue.Component | undefined;
    })>;
    zIndex: string | number;
    modelValue: boolean;
    variant: "flat" | "text" | "elevated" | "tonal" | "outlined" | "plain";
    origin: Anchor | "auto" | "overlap";
    vertical: boolean;
    tile: boolean;
    eager: boolean;
    location: Anchor;
    locationStrategy: "static" | ((data: LocationStrategyData, props: StrategyProps$1, contentStyles: Ref<Record<string, string>>) => {
        updateLocation: (e: Event) => void;
    } | undefined) | "connected";
    activatorProps: Record<string, any>;
    openOnHover: boolean;
    closeOnContentClick: boolean;
    closeOnBack: boolean;
    contained: boolean;
    multiLine: boolean;
    timeout: string | number;
} & {
    class?: any;
    text?: string | undefined;
    width?: string | number | undefined;
    height?: string | number | undefined;
    theme?: string | undefined;
    target?: Element | vue.ComponentPublicInstance | (string & {}) | "parent" | "cursor" | [x: number, y: number] | undefined;
    color?: string | undefined;
    offset?: string | number | number[] | undefined;
    position?: "fixed" | "absolute" | "relative" | "static" | "sticky" | undefined;
    rounded?: string | number | boolean | undefined;
    contentClass?: any;
    opacity?: string | number | undefined;
    maxHeight?: string | number | undefined;
    maxWidth?: string | number | undefined;
    minHeight?: string | number | undefined;
    minWidth?: string | number | undefined;
    activator?: Element | vue.ComponentPublicInstance | (string & {}) | "parent" | undefined;
    closeDelay?: string | number | undefined;
    openDelay?: string | number | undefined;
    openOnClick?: boolean | undefined;
    openOnFocus?: boolean | undefined;
    contentProps?: any;
    attach?: string | boolean | Element | undefined;
    timer?: string | boolean | undefined;
} & {
    $children?: vue.VNodeChild | (() => vue.VNodeChild) | {
        activator?: ((arg: {
            isActive: boolean;
            props: Record<string, any>;
        }) => vue.VNodeChild) | undefined;
        default?: (() => vue.VNodeChild) | undefined;
        actions?: ((arg: {
            isActive: Ref<boolean>;
        }) => vue.VNodeChild) | undefined;
        text?: (() => vue.VNodeChild) | undefined;
    };
    'v-slots'?: {
        activator?: false | ((arg: {
            isActive: boolean;
            props: Record<string, any>;
        }) => vue.VNodeChild) | undefined;
        default?: false | (() => vue.VNodeChild) | undefined;
        actions?: false | ((arg: {
            isActive: Ref<boolean>;
        }) => vue.VNodeChild) | undefined;
        text?: false | (() => vue.VNodeChild) | undefined;
    } | undefined;
} & {
    "v-slot:activator"?: false | ((arg: {
        isActive: boolean;
        props: Record<string, any>;
    }) => vue.VNodeChild) | undefined;
    "v-slot:default"?: false | (() => vue.VNodeChild) | undefined;
    "v-slot:actions"?: false | ((arg: {
        isActive: Ref<boolean>;
    }) => vue.VNodeChild) | undefined;
    "v-slot:text"?: false | (() => vue.VNodeChild) | undefined;
} & {
    "onUpdate:modelValue"?: ((v: boolean) => any) | undefined;
}, Omit<Omit<{
    $: vue.ComponentInternalInstance;
    $data: {};
    $props: Partial<{
        style: vue.StyleValue;
        disabled: boolean;
        absolute: boolean;
        transition: string | boolean | (vue.TransitionProps & {
            component?: vue.Component | undefined;
        });
        zIndex: string | number;
        modelValue: boolean;
        origin: Anchor | "auto" | "overlap";
        eager: boolean;
        location: Anchor;
        locationStrategy: "static" | ((data: LocationStrategyData, props: StrategyProps$1, contentStyles: Ref<Record<string, string>>) => {
            updateLocation: (e: Event) => void;
        } | undefined) | "connected";
        scrollStrategy: "close" | "none" | "block" | ((data: ScrollStrategyData, props: StrategyProps, scope: vue.EffectScope) => void) | "reposition";
        activatorProps: Record<string, any>;
        openOnClick: boolean;
        openOnHover: boolean;
        openOnFocus: boolean;
        closeOnContentClick: boolean;
        closeOnBack: boolean;
        contained: boolean;
        noClickAnimation: boolean;
        persistent: boolean;
        scrim: string | boolean;
        _disableGlobalStack: boolean;
    }> & Omit<{
        style: vue.StyleValue;
        disabled: boolean;
        absolute: boolean;
        transition: string | boolean | (vue.TransitionProps & {
            component?: vue.Component | undefined;
        });
        zIndex: string | number;
        modelValue: boolean;
        origin: Anchor | "auto" | "overlap";
        eager: boolean;
        location: Anchor;
        locationStrategy: "static" | ((data: LocationStrategyData, props: StrategyProps$1, contentStyles: Ref<Record<string, string>>) => {
            updateLocation: (e: Event) => void;
        } | undefined) | "connected";
        scrollStrategy: "close" | "none" | "block" | ((data: ScrollStrategyData, props: StrategyProps, scope: vue.EffectScope) => void) | "reposition";
        activatorProps: Record<string, any>;
        openOnHover: boolean;
        closeOnContentClick: boolean;
        closeOnBack: boolean;
        contained: boolean;
        noClickAnimation: boolean;
        persistent: boolean;
        scrim: string | boolean;
        _disableGlobalStack: boolean;
        class?: any;
        width?: string | number | undefined;
        height?: string | number | undefined;
        theme?: string | undefined;
        target?: Element | vue.ComponentPublicInstance | (string & {}) | "parent" | "cursor" | [x: number, y: number] | undefined;
        offset?: string | number | number[] | undefined;
        contentClass?: any;
        opacity?: string | number | undefined;
        maxHeight?: string | number | undefined;
        maxWidth?: string | number | undefined;
        minHeight?: string | number | undefined;
        minWidth?: string | number | undefined;
        activator?: Element | vue.ComponentPublicInstance | (string & {}) | "parent" | undefined;
        closeDelay?: string | number | undefined;
        openDelay?: string | number | undefined;
        openOnClick?: boolean | undefined;
        openOnFocus?: boolean | undefined;
        contentProps?: any;
        attach?: string | boolean | Element | undefined;
        $children?: vue.VNodeChild | {
            default?: ((arg: {
                isActive: Ref<boolean>;
            }) => vue.VNodeChild) | undefined;
            activator?: ((arg: {
                isActive: boolean;
                props: Record<string, any>;
                targetRef: TemplateRef;
            }) => vue.VNodeChild) | undefined;
        } | ((arg: {
            isActive: Ref<boolean>;
        }) => vue.VNodeChild);
        'v-slots'?: {
            default?: false | ((arg: {
                isActive: Ref<boolean>;
            }) => vue.VNodeChild) | undefined;
            activator?: false | ((arg: {
                isActive: boolean;
                props: Record<string, any>;
                targetRef: TemplateRef;
            }) => vue.VNodeChild) | undefined;
        } | undefined;
        "v-slot:default"?: false | ((arg: {
            isActive: Ref<boolean>;
        }) => vue.VNodeChild) | undefined;
        "v-slot:activator"?: false | ((arg: {
            isActive: boolean;
            props: Record<string, any>;
            targetRef: TemplateRef;
        }) => vue.VNodeChild) | undefined;
        "onUpdate:modelValue"?: ((value: boolean) => any) | undefined;
        onAfterEnter?: (() => any) | undefined;
        onAfterLeave?: (() => any) | undefined;
        "onClick:outside"?: ((e: MouseEvent) => any) | undefined;
    } & vue.VNodeProps & vue.AllowedComponentProps & vue.ComponentCustomProps & {
        style: vue.StyleValue;
        disabled: boolean;
        absolute: boolean;
        transition: string | boolean | (vue.TransitionProps & {
            component?: vue.Component | undefined;
        });
        zIndex: string | number;
        modelValue: boolean;
        origin: Anchor | "auto" | "overlap";
        eager: boolean;
        location: Anchor;
        locationStrategy: "static" | ((data: LocationStrategyData, props: StrategyProps$1, contentStyles: Ref<Record<string, string>>) => {
            updateLocation: (e: Event) => void;
        } | undefined) | "connected";
        scrollStrategy: "close" | "none" | "block" | ((data: ScrollStrategyData, props: StrategyProps, scope: vue.EffectScope) => void) | "reposition";
        activatorProps: Record<string, any>;
        openOnHover: boolean;
        closeOnContentClick: boolean;
        closeOnBack: boolean;
        contained: boolean;
        noClickAnimation: boolean;
        persistent: boolean;
        scrim: string | boolean;
        _disableGlobalStack: boolean;
    } & {
        class?: any;
        width?: string | number | undefined;
        height?: string | number | undefined;
        theme?: string | undefined;
        target?: Element | vue.ComponentPublicInstance | (string & {}) | "parent" | "cursor" | [x: number, y: number] | undefined;
        offset?: string | number | number[] | undefined;
        contentClass?: any;
        opacity?: string | number | undefined;
        maxHeight?: string | number | undefined;
        maxWidth?: string | number | undefined;
        minHeight?: string | number | undefined;
        minWidth?: string | number | undefined;
        activator?: Element | vue.ComponentPublicInstance | (string & {}) | "parent" | undefined;
        closeDelay?: string | number | undefined;
        openDelay?: string | number | undefined;
        openOnClick?: boolean | undefined;
        openOnFocus?: boolean | undefined;
        contentProps?: any;
        attach?: string | boolean | Element | undefined;
    } & {
        $children?: vue.VNodeChild | {
            default?: ((arg: {
                isActive: Ref<boolean>;
            }) => vue.VNodeChild) | undefined;
            activator?: ((arg: {
                isActive: boolean;
                props: Record<string, any>;
                targetRef: TemplateRef;
            }) => vue.VNodeChild) | undefined;
        } | ((arg: {
            isActive: Ref<boolean>;
        }) => vue.VNodeChild);
        'v-slots'?: {
            default?: false | ((arg: {
                isActive: Ref<boolean>;
            }) => vue.VNodeChild) | undefined;
            activator?: false | ((arg: {
                isActive: boolean;
                props: Record<string, any>;
                targetRef: TemplateRef;
            }) => vue.VNodeChild) | undefined;
        } | undefined;
    } & {
        "v-slot:default"?: false | ((arg: {
            isActive: Ref<boolean>;
        }) => vue.VNodeChild) | undefined;
        "v-slot:activator"?: false | ((arg: {
            isActive: boolean;
            props: Record<string, any>;
            targetRef: TemplateRef;
        }) => vue.VNodeChild) | undefined;
    } & {
        "onUpdate:modelValue"?: ((value: boolean) => any) | undefined;
        onAfterEnter?: (() => any) | undefined;
        onAfterLeave?: (() => any) | undefined;
        "onClick:outside"?: ((e: MouseEvent) => any) | undefined;
    }, "style" | "disabled" | "absolute" | "transition" | "zIndex" | "modelValue" | "origin" | "eager" | "location" | "locationStrategy" | "scrollStrategy" | "activatorProps" | "openOnClick" | "openOnHover" | "openOnFocus" | "closeOnContentClick" | "closeOnBack" | "contained" | "noClickAnimation" | "persistent" | "scrim" | "_disableGlobalStack">;
    $attrs: {
        [x: string]: unknown;
    };
    $refs: {
        [x: string]: unknown;
    };
    $slots: Readonly<{
        default?: ((arg: {
            isActive: Ref<boolean>;
        }) => vue.VNode<vue.RendererNode, vue.RendererElement, {
            [key: string]: any;
        }>[]) | undefined;
        activator?: ((arg: {
            isActive: boolean;
            props: Record<string, any>;
            targetRef: TemplateRef;
        }) => vue.VNode<vue.RendererNode, vue.RendererElement, {
            [key: string]: any;
        }>[]) | undefined;
    }>;
    $root: vue.ComponentPublicInstance<{}, {}, {}, {}, {}, {}, {}, {}, false, vue.ComponentOptionsBase<any, any, any, any, any, any, any, any, any, {}, {}, string, {}>, {}, {}> | null;
    $parent: vue.ComponentPublicInstance<{}, {}, {}, {}, {}, {}, {}, {}, false, vue.ComponentOptionsBase<any, any, any, any, any, any, any, any, any, {}, {}, string, {}>, {}, {}> | null;
    $emit: ((event: "update:modelValue", value: boolean) => void) & ((event: "click:outside", e: MouseEvent) => void) & ((event: "afterEnter") => void) & ((event: "afterLeave") => void);
    $el: any;
    $options: vue.ComponentOptionsBase<{
        style: vue.StyleValue;
        disabled: boolean;
        absolute: boolean;
        transition: string | boolean | (vue.TransitionProps & {
            component?: vue.Component | undefined;
        });
        zIndex: string | number;
        modelValue: boolean;
        origin: Anchor | "auto" | "overlap";
        eager: boolean;
        location: Anchor;
        locationStrategy: "static" | ((data: LocationStrategyData, props: StrategyProps$1, contentStyles: Ref<Record<string, string>>) => {
            updateLocation: (e: Event) => void;
        } | undefined) | "connected";
        scrollStrategy: "close" | "none" | "block" | ((data: ScrollStrategyData, props: StrategyProps, scope: vue.EffectScope) => void) | "reposition";
        activatorProps: Record<string, any>;
        openOnHover: boolean;
        closeOnContentClick: boolean;
        closeOnBack: boolean;
        contained: boolean;
        noClickAnimation: boolean;
        persistent: boolean;
        scrim: string | boolean;
        _disableGlobalStack: boolean;
    } & {
        class?: any;
        width?: string | number | undefined;
        height?: string | number | undefined;
        theme?: string | undefined;
        target?: Element | vue.ComponentPublicInstance | (string & {}) | "parent" | "cursor" | [x: number, y: number] | undefined;
        offset?: string | number | number[] | undefined;
        contentClass?: any;
        opacity?: string | number | undefined;
        maxHeight?: string | number | undefined;
        maxWidth?: string | number | undefined;
        minHeight?: string | number | undefined;
        minWidth?: string | number | undefined;
        activator?: Element | vue.ComponentPublicInstance | (string & {}) | "parent" | undefined;
        closeDelay?: string | number | undefined;
        openDelay?: string | number | undefined;
        openOnClick?: boolean | undefined;
        openOnFocus?: boolean | undefined;
        contentProps?: any;
        attach?: string | boolean | Element | undefined;
    } & {
        $children?: vue.VNodeChild | {
            default?: ((arg: {
                isActive: Ref<boolean>;
            }) => vue.VNodeChild) | undefined;
            activator?: ((arg: {
                isActive: boolean;
                props: Record<string, any>;
                targetRef: TemplateRef;
            }) => vue.VNodeChild) | undefined;
        } | ((arg: {
            isActive: Ref<boolean>;
        }) => vue.VNodeChild);
        'v-slots'?: {
            default?: false | ((arg: {
                isActive: Ref<boolean>;
            }) => vue.VNodeChild) | undefined;
            activator?: false | ((arg: {
                isActive: boolean;
                props: Record<string, any>;
                targetRef: TemplateRef;
            }) => vue.VNodeChild) | undefined;
        } | undefined;
    } & {
        "v-slot:default"?: false | ((arg: {
            isActive: Ref<boolean>;
        }) => vue.VNodeChild) | undefined;
        "v-slot:activator"?: false | ((arg: {
            isActive: boolean;
            props: Record<string, any>;
            targetRef: TemplateRef;
        }) => vue.VNodeChild) | undefined;
    } & {
        "onUpdate:modelValue"?: ((value: boolean) => any) | undefined;
        onAfterEnter?: (() => any) | undefined;
        onAfterLeave?: (() => any) | undefined;
        "onClick:outside"?: ((e: MouseEvent) => any) | undefined;
    }, {
        activatorEl: Ref<HTMLElement | undefined>;
        scrimEl: Ref<HTMLElement | undefined>;
        target: vue.ComputedRef<HTMLElement | [x: number, y: number] | undefined>;
        animateClick: () => void;
        contentEl: Ref<HTMLElement | undefined>;
        globalTop: Readonly<Ref<boolean>>;
        localTop: vue.ComputedRef<boolean>;
        updateLocation: Ref<((e: Event) => void) | undefined>;
    }, unknown, {}, {}, vue.ComponentOptionsMixin, vue.ComponentOptionsMixin, {
        'click:outside': (e: MouseEvent) => true;
        'update:modelValue': (value: boolean) => true;
        afterEnter: () => true;
        afterLeave: () => true;
    }, string, {
        style: vue.StyleValue;
        disabled: boolean;
        absolute: boolean;
        transition: string | boolean | (vue.TransitionProps & {
            component?: vue.Component | undefined;
        });
        zIndex: string | number;
        modelValue: boolean;
        origin: Anchor | "auto" | "overlap";
        eager: boolean;
        location: Anchor;
        locationStrategy: "static" | ((data: LocationStrategyData, props: StrategyProps$1, contentStyles: Ref<Record<string, string>>) => {
            updateLocation: (e: Event) => void;
        } | undefined) | "connected";
        scrollStrategy: "close" | "none" | "block" | ((data: ScrollStrategyData, props: StrategyProps, scope: vue.EffectScope) => void) | "reposition";
        activatorProps: Record<string, any>;
        openOnClick: boolean;
        openOnHover: boolean;
        openOnFocus: boolean;
        closeOnContentClick: boolean;
        closeOnBack: boolean;
        contained: boolean;
        noClickAnimation: boolean;
        persistent: boolean;
        scrim: string | boolean;
        _disableGlobalStack: boolean;
    }, {}, string, vue.SlotsType<Partial<{
        default: (arg: {
            isActive: Ref<boolean>;
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
    }>>> & {
        beforeCreate?: ((() => void) | (() => void)[]) | undefined;
        created?: ((() => void) | (() => void)[]) | undefined;
        beforeMount?: ((() => void) | (() => void)[]) | undefined;
        mounted?: ((() => void) | (() => void)[]) | undefined;
        beforeUpdate?: ((() => void) | (() => void)[]) | undefined;
        updated?: ((() => void) | (() => void)[]) | undefined;
        activated?: ((() => void) | (() => void)[]) | undefined;
        deactivated?: ((() => void) | (() => void)[]) | undefined;
        beforeDestroy?: ((() => void) | (() => void)[]) | undefined;
        beforeUnmount?: ((() => void) | (() => void)[]) | undefined;
        destroyed?: ((() => void) | (() => void)[]) | undefined;
        unmounted?: ((() => void) | (() => void)[]) | undefined;
        renderTracked?: (((e: vue.DebuggerEvent) => void) | ((e: vue.DebuggerEvent) => void)[]) | undefined;
        renderTriggered?: (((e: vue.DebuggerEvent) => void) | ((e: vue.DebuggerEvent) => void)[]) | undefined;
        errorCaptured?: (((err: unknown, instance: vue.ComponentPublicInstance<{}, {}, {}, {}, {}, {}, {}, {}, false, vue.ComponentOptionsBase<any, any, any, any, any, any, any, any, any, {}, {}, string, {}>, {}, {}> | null, info: string) => boolean | void) | ((err: unknown, instance: vue.ComponentPublicInstance<{}, {}, {}, {}, {}, {}, {}, {}, false, vue.ComponentOptionsBase<any, any, any, any, any, any, any, any, any, {}, {}, string, {}>, {}, {}> | null, info: string) => boolean | void)[]) | undefined;
    };
    $forceUpdate: () => void;
    $nextTick: typeof nextTick;
    $watch<T extends string | ((...args: any) => any)>(source: T, cb: T extends (...args: any) => infer R ? (args_0: R, args_1: R) => any : (...args: any) => any, options?: vue.WatchOptions<boolean> | undefined): vue.WatchStopHandle;
} & Omit<{
    style: vue.StyleValue;
    disabled: boolean;
    absolute: boolean;
    transition: string | boolean | (vue.TransitionProps & {
        component?: vue.Component | undefined;
    });
    zIndex: string | number;
    modelValue: boolean;
    origin: Anchor | "auto" | "overlap";
    eager: boolean;
    location: Anchor;
    locationStrategy: "static" | ((data: LocationStrategyData, props: StrategyProps$1, contentStyles: Ref<Record<string, string>>) => {
        updateLocation: (e: Event) => void;
    } | undefined) | "connected";
    scrollStrategy: "close" | "none" | "block" | ((data: ScrollStrategyData, props: StrategyProps, scope: vue.EffectScope) => void) | "reposition";
    activatorProps: Record<string, any>;
    openOnHover: boolean;
    closeOnContentClick: boolean;
    closeOnBack: boolean;
    contained: boolean;
    noClickAnimation: boolean;
    persistent: boolean;
    scrim: string | boolean;
    _disableGlobalStack: boolean;
} & {
    class?: any;
    width?: string | number | undefined;
    height?: string | number | undefined;
    theme?: string | undefined;
    target?: Element | vue.ComponentPublicInstance | (string & {}) | "parent" | "cursor" | [x: number, y: number] | undefined;
    offset?: string | number | number[] | undefined;
    contentClass?: any;
    opacity?: string | number | undefined;
    maxHeight?: string | number | undefined;
    maxWidth?: string | number | undefined;
    minHeight?: string | number | undefined;
    minWidth?: string | number | undefined;
    activator?: Element | vue.ComponentPublicInstance | (string & {}) | "parent" | undefined;
    closeDelay?: string | number | undefined;
    openDelay?: string | number | undefined;
    openOnClick?: boolean | undefined;
    openOnFocus?: boolean | undefined;
    contentProps?: any;
    attach?: string | boolean | Element | undefined;
} & {
    $children?: vue.VNodeChild | {
        default?: ((arg: {
            isActive: Ref<boolean>;
        }) => vue.VNodeChild) | undefined;
        activator?: ((arg: {
            isActive: boolean;
            props: Record<string, any>;
            targetRef: TemplateRef;
        }) => vue.VNodeChild) | undefined;
    } | ((arg: {
        isActive: Ref<boolean>;
    }) => vue.VNodeChild);
    'v-slots'?: {
        default?: false | ((arg: {
            isActive: Ref<boolean>;
        }) => vue.VNodeChild) | undefined;
        activator?: false | ((arg: {
            isActive: boolean;
            props: Record<string, any>;
            targetRef: TemplateRef;
        }) => vue.VNodeChild) | undefined;
    } | undefined;
} & {
    "v-slot:default"?: false | ((arg: {
        isActive: Ref<boolean>;
    }) => vue.VNodeChild) | undefined;
    "v-slot:activator"?: false | ((arg: {
        isActive: boolean;
        props: Record<string, any>;
        targetRef: TemplateRef;
    }) => vue.VNodeChild) | undefined;
} & {
    "onUpdate:modelValue"?: ((value: boolean) => any) | undefined;
    onAfterEnter?: (() => any) | undefined;
    onAfterLeave?: (() => any) | undefined;
    "onClick:outside"?: ((e: MouseEvent) => any) | undefined;
}, "target" | "activatorEl" | "scrimEl" | "animateClick" | "contentEl" | "globalTop" | "localTop" | "updateLocation"> & vue.ShallowUnwrapRef<{
    activatorEl: Ref<HTMLElement | undefined>;
    scrimEl: Ref<HTMLElement | undefined>;
    target: vue.ComputedRef<HTMLElement | [x: number, y: number] | undefined>;
    animateClick: () => void;
    contentEl: Ref<HTMLElement | undefined>;
    globalTop: Readonly<Ref<boolean>>;
    localTop: vue.ComputedRef<boolean>;
    updateLocation: Ref<((e: Event) => void) | undefined>;
}> & {} & vue.ComponentCustomProperties & {}, "class" | "width" | "height" | "theme" | "key" | "target" | "v-slot:default" | "$children" | "v-slots" | "ref" | "ref_for" | "ref_key" | "onVnodeBeforeMount" | "onVnodeMounted" | "onVnodeBeforeUpdate" | "onVnodeUpdated" | "onVnodeBeforeUnmount" | "onVnodeUnmounted" | "offset" | "onUpdate:modelValue" | "contentClass" | "opacity" | "maxHeight" | "maxWidth" | "minHeight" | "minWidth" | "onAfterEnter" | "onAfterLeave" | "activator" | "v-slot:activator" | "closeDelay" | "openDelay" | "contentProps" | "attach" | "onClick:outside" | ("style" | "disabled" | "absolute" | "transition" | "zIndex" | "modelValue" | "origin" | "eager" | "location" | "locationStrategy" | "scrollStrategy" | "activatorProps" | "openOnClick" | "openOnHover" | "openOnFocus" | "closeOnContentClick" | "closeOnBack" | "contained" | "noClickAnimation" | "persistent" | "scrim" | "_disableGlobalStack")>, `$${any}`>, unknown, {}, {}, vue.ComponentOptionsMixin, vue.ComponentOptionsMixin, {
    'update:modelValue': (v: boolean) => boolean;
}, string, {
    style: vue.StyleValue;
    disabled: boolean;
    absolute: boolean;
    transition: NonNullable<string | boolean | (vue.TransitionProps & {
        component?: vue.Component | undefined;
    })>;
    zIndex: string | number;
    modelValue: boolean;
    rounded: string | number | boolean;
    variant: "flat" | "text" | "elevated" | "tonal" | "outlined" | "plain";
    origin: Anchor | "auto" | "overlap";
    vertical: boolean;
    tile: boolean;
    eager: boolean;
    location: Anchor;
    locationStrategy: "static" | ((data: LocationStrategyData, props: StrategyProps$1, contentStyles: Ref<Record<string, string>>) => {
        updateLocation: (e: Event) => void;
    } | undefined) | "connected";
    activatorProps: Record<string, any>;
    openOnClick: boolean;
    openOnHover: boolean;
    openOnFocus: boolean;
    closeOnContentClick: boolean;
    closeOnBack: boolean;
    contained: boolean;
    multiLine: boolean;
    timeout: string | number;
}, {}, string, vue.SlotsType<Partial<{
    activator: (arg: {
        isActive: boolean;
        props: Record<string, any>;
    }) => vue.VNode<vue.RendererNode, vue.RendererElement, {
        [key: string]: any;
    }>[];
    default: () => vue.VNode<vue.RendererNode, vue.RendererElement, {
        [key: string]: any;
    }>[];
    actions: (arg: {
        isActive: Ref<boolean>;
    }) => vue.VNode<vue.RendererNode, vue.RendererElement, {
        [key: string]: any;
    }>[];
    text: () => vue.VNode<vue.RendererNode, vue.RendererElement, {
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
    offset: vue.PropType<string | number | number[] | undefined>;
    absolute: BooleanConstructor;
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
    minWidth: (StringConstructor | NumberConstructor)[];
    eager: BooleanConstructor;
    location: {
        type: vue.PropType<Anchor>;
        default: string;
    };
    activator: vue.PropType<Element | vue.ComponentPublicInstance | (string & {}) | "parent" | undefined>;
    locationStrategy: {
        type: vue.PropType<"static" | ((data: LocationStrategyData, props: StrategyProps$1, contentStyles: Ref<Record<string, string>>) => {
            updateLocation: (e: Event) => void;
        } | undefined) | "connected">;
        default: string;
        validator: (val: any) => boolean;
    };
    closeDelay: (StringConstructor | NumberConstructor)[];
    openDelay: (StringConstructor | NumberConstructor)[];
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
    closeOnContentClick: BooleanConstructor;
    closeOnBack: {
        type: BooleanConstructor;
        default: boolean;
    };
    contained: BooleanConstructor;
    contentProps: null;
    attach: vue.PropType<string | boolean | Element>;
    color: StringConstructor;
    variant: {
        type: vue.PropType<"flat" | "text" | "elevated" | "tonal" | "outlined" | "plain">;
        default: string;
        validator: (v: any) => boolean;
    };
    rounded: {
        type: (StringConstructor | NumberConstructor | BooleanConstructor)[];
        default: undefined;
    };
    tile: BooleanConstructor;
    position: {
        type: vue.PropType<"fixed" | "absolute" | "relative" | "static" | "sticky">;
        validator: (v: any) => boolean;
    };
    multiLine: BooleanConstructor;
    text: StringConstructor;
    timer: (StringConstructor | BooleanConstructor)[];
    timeout: {
        type: (StringConstructor | NumberConstructor)[];
        default: number;
    };
    vertical: BooleanConstructor;
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
    offset: vue.PropType<string | number | number[] | undefined>;
    absolute: BooleanConstructor;
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
    minWidth: (StringConstructor | NumberConstructor)[];
    eager: BooleanConstructor;
    location: {
        type: vue.PropType<Anchor>;
        default: string;
    };
    activator: vue.PropType<Element | vue.ComponentPublicInstance | (string & {}) | "parent" | undefined>;
    locationStrategy: {
        type: vue.PropType<"static" | ((data: LocationStrategyData, props: StrategyProps$1, contentStyles: Ref<Record<string, string>>) => {
            updateLocation: (e: Event) => void;
        } | undefined) | "connected">;
        default: string;
        validator: (val: any) => boolean;
    };
    closeDelay: (StringConstructor | NumberConstructor)[];
    openDelay: (StringConstructor | NumberConstructor)[];
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
    closeOnContentClick: BooleanConstructor;
    closeOnBack: {
        type: BooleanConstructor;
        default: boolean;
    };
    contained: BooleanConstructor;
    contentProps: null;
    attach: vue.PropType<string | boolean | Element>;
    color: StringConstructor;
    variant: {
        type: vue.PropType<"flat" | "text" | "elevated" | "tonal" | "outlined" | "plain">;
        default: string;
        validator: (v: any) => boolean;
    };
    rounded: {
        type: (StringConstructor | NumberConstructor | BooleanConstructor)[];
        default: undefined;
    };
    tile: BooleanConstructor;
    position: {
        type: vue.PropType<"fixed" | "absolute" | "relative" | "static" | "sticky">;
        validator: (v: any) => boolean;
    };
    multiLine: BooleanConstructor;
    text: StringConstructor;
    timer: (StringConstructor | BooleanConstructor)[];
    timeout: {
        type: (StringConstructor | NumberConstructor)[];
        default: number;
    };
    vertical: BooleanConstructor;
}>>;
type VSnackbar = InstanceType<typeof VSnackbar>;

type VSnackbarQueueSlots<T extends string | SnackbarMessage> = {
    default: {
        item: T;
    };
    text: {
        item: T;
    };
    actions: {
        item: T;
        props: {
            onClick: () => void;
        };
    };
};
type SnackbarMessage = Omit<VSnackbar['$props'], '$children' | 'modelValue' | 'onUpdate:modelValue' | 'activator' | 'activatorProps' | 'closeDelay' | 'openDelay' | 'openOnClick' | 'openOnFocus' | 'openOnHover'>;
declare const VSnackbarQueue: {
    new (...args: any[]): vue.CreateComponentPublicInstance<{
        style: vue.StyleValue;
        disabled: boolean;
        absolute: boolean;
        transition: NonNullable<string | boolean | (vue.TransitionProps & {
            component?: vue.Component | undefined;
        })>;
        zIndex: string | number;
        variant: "flat" | "text" | "elevated" | "tonal" | "outlined" | "plain";
        origin: Anchor | "auto" | "overlap";
        vertical: boolean;
        tile: boolean;
        eager: boolean;
        location: Anchor;
        locationStrategy: "static" | ((data: LocationStrategyData, props: StrategyProps$1, contentStyles: vue.Ref<Record<string, string>>) => {
            updateLocation: (e: Event) => void;
        } | undefined) | "connected";
        activatorProps: Record<string, any>;
        openOnHover: boolean;
        closeOnContentClick: boolean;
        closeOnBack: boolean;
        contained: boolean;
        closeText: string;
        multiLine: boolean;
        timeout: string | number;
    } & {
        class?: any;
        text?: string | undefined;
        width?: string | number | undefined;
        height?: string | number | undefined;
        theme?: string | undefined;
        target?: Element | vue.ComponentPublicInstance | (string & {}) | "parent" | "cursor" | [x: number, y: number] | undefined;
        color?: string | undefined;
        offset?: string | number | number[] | undefined;
        position?: "fixed" | "absolute" | "relative" | "static" | "sticky" | undefined;
        rounded?: string | number | boolean | undefined;
        contentClass?: any;
        opacity?: string | number | undefined;
        maxHeight?: string | number | undefined;
        maxWidth?: string | number | undefined;
        minHeight?: string | number | undefined;
        minWidth?: string | number | undefined;
        closable?: string | boolean | undefined;
        activator?: Element | vue.ComponentPublicInstance | (string & {}) | "parent" | undefined;
        closeDelay?: string | number | undefined;
        openDelay?: string | number | undefined;
        openOnClick?: boolean | undefined;
        openOnFocus?: boolean | undefined;
        contentProps?: any;
        attach?: string | boolean | Element | undefined;
        timer?: string | boolean | undefined;
    } & {}, void, unknown, {}, {}, vue.ComponentOptionsMixin, vue.ComponentOptionsMixin, Omit<{
        'update:modelValue': (val: (string | SnackbarMessage)[]) => true;
    }, "v-slot:default" | "$children" | "v-slots" | "modelValue" | "v-slot:text" | "update:modelValue" | "v-slot:actions">, vue.VNodeProps & vue.AllowedComponentProps & vue.ComponentCustomProps & {
        style: vue.StyleValue;
        disabled: boolean;
        absolute: boolean;
        transition: NonNullable<string | boolean | (vue.TransitionProps & {
            component?: vue.Component | undefined;
        })>;
        zIndex: string | number;
        variant: "flat" | "text" | "elevated" | "tonal" | "outlined" | "plain";
        origin: Anchor | "auto" | "overlap";
        vertical: boolean;
        tile: boolean;
        eager: boolean;
        location: Anchor;
        locationStrategy: "static" | ((data: LocationStrategyData, props: StrategyProps$1, contentStyles: vue.Ref<Record<string, string>>) => {
            updateLocation: (e: Event) => void;
        } | undefined) | "connected";
        activatorProps: Record<string, any>;
        openOnHover: boolean;
        closeOnContentClick: boolean;
        closeOnBack: boolean;
        contained: boolean;
        closeText: string;
        multiLine: boolean;
        timeout: string | number;
    } & {
        class?: any;
        text?: string | undefined;
        width?: string | number | undefined;
        height?: string | number | undefined;
        theme?: string | undefined;
        target?: Element | vue.ComponentPublicInstance | (string & {}) | "parent" | "cursor" | [x: number, y: number] | undefined;
        color?: string | undefined;
        offset?: string | number | number[] | undefined;
        position?: "fixed" | "absolute" | "relative" | "static" | "sticky" | undefined;
        rounded?: string | number | boolean | undefined;
        contentClass?: any;
        opacity?: string | number | undefined;
        maxHeight?: string | number | undefined;
        maxWidth?: string | number | undefined;
        minHeight?: string | number | undefined;
        minWidth?: string | number | undefined;
        closable?: string | boolean | undefined;
        activator?: Element | vue.ComponentPublicInstance | (string & {}) | "parent" | undefined;
        closeDelay?: string | number | undefined;
        openDelay?: string | number | undefined;
        openOnClick?: boolean | undefined;
        openOnFocus?: boolean | undefined;
        contentProps?: any;
        attach?: string | boolean | Element | undefined;
        timer?: string | boolean | undefined;
    } & {}, {
        style: vue.StyleValue;
        disabled: boolean;
        absolute: boolean;
        transition: NonNullable<string | boolean | (vue.TransitionProps & {
            component?: vue.Component | undefined;
        })>;
        zIndex: string | number;
        rounded: string | number | boolean;
        variant: "flat" | "text" | "elevated" | "tonal" | "outlined" | "plain";
        origin: Anchor | "auto" | "overlap";
        vertical: boolean;
        tile: boolean;
        eager: boolean;
        location: Anchor;
        locationStrategy: "static" | ((data: LocationStrategyData, props: StrategyProps$1, contentStyles: vue.Ref<Record<string, string>>) => {
            updateLocation: (e: Event) => void;
        } | undefined) | "connected";
        activatorProps: Record<string, any>;
        openOnClick: boolean;
        openOnHover: boolean;
        openOnFocus: boolean;
        closeOnContentClick: boolean;
        closeOnBack: boolean;
        contained: boolean;
        closeText: string;
        multiLine: boolean;
        timeout: string | number;
    }, true, {}, vue.SlotsType<Partial<{
        default: (arg: {
            item: string | SnackbarMessage;
        }) => vue.VNode<vue.RendererNode, vue.RendererElement, {
            [key: string]: any;
        }>[];
        text: (arg: {
            item: string | SnackbarMessage;
        }) => vue.VNode<vue.RendererNode, vue.RendererElement, {
            [key: string]: any;
        }>[];
        actions: (arg: {
            item: string | SnackbarMessage;
            props: {
                onClick: () => void;
            };
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
        absolute: boolean;
        transition: NonNullable<string | boolean | (vue.TransitionProps & {
            component?: vue.Component | undefined;
        })>;
        zIndex: string | number;
        variant: "flat" | "text" | "elevated" | "tonal" | "outlined" | "plain";
        origin: Anchor | "auto" | "overlap";
        vertical: boolean;
        tile: boolean;
        eager: boolean;
        location: Anchor;
        locationStrategy: "static" | ((data: LocationStrategyData, props: StrategyProps$1, contentStyles: vue.Ref<Record<string, string>>) => {
            updateLocation: (e: Event) => void;
        } | undefined) | "connected";
        activatorProps: Record<string, any>;
        openOnHover: boolean;
        closeOnContentClick: boolean;
        closeOnBack: boolean;
        contained: boolean;
        closeText: string;
        multiLine: boolean;
        timeout: string | number;
    } & {
        class?: any;
        text?: string | undefined;
        width?: string | number | undefined;
        height?: string | number | undefined;
        theme?: string | undefined;
        target?: Element | vue.ComponentPublicInstance | (string & {}) | "parent" | "cursor" | [x: number, y: number] | undefined;
        color?: string | undefined;
        offset?: string | number | number[] | undefined;
        position?: "fixed" | "absolute" | "relative" | "static" | "sticky" | undefined;
        rounded?: string | number | boolean | undefined;
        contentClass?: any;
        opacity?: string | number | undefined;
        maxHeight?: string | number | undefined;
        maxWidth?: string | number | undefined;
        minHeight?: string | number | undefined;
        minWidth?: string | number | undefined;
        closable?: string | boolean | undefined;
        activator?: Element | vue.ComponentPublicInstance | (string & {}) | "parent" | undefined;
        closeDelay?: string | number | undefined;
        openDelay?: string | number | undefined;
        openOnClick?: boolean | undefined;
        openOnFocus?: boolean | undefined;
        contentProps?: any;
        attach?: string | boolean | Element | undefined;
        timer?: string | boolean | undefined;
    } & {}, {}, {}, {}, {}, {
        style: vue.StyleValue;
        disabled: boolean;
        absolute: boolean;
        transition: NonNullable<string | boolean | (vue.TransitionProps & {
            component?: vue.Component | undefined;
        })>;
        zIndex: string | number;
        rounded: string | number | boolean;
        variant: "flat" | "text" | "elevated" | "tonal" | "outlined" | "plain";
        origin: Anchor | "auto" | "overlap";
        vertical: boolean;
        tile: boolean;
        eager: boolean;
        location: Anchor;
        locationStrategy: "static" | ((data: LocationStrategyData, props: StrategyProps$1, contentStyles: vue.Ref<Record<string, string>>) => {
            updateLocation: (e: Event) => void;
        } | undefined) | "connected";
        activatorProps: Record<string, any>;
        openOnClick: boolean;
        openOnHover: boolean;
        openOnFocus: boolean;
        closeOnContentClick: boolean;
        closeOnBack: boolean;
        contained: boolean;
        closeText: string;
        multiLine: boolean;
        timeout: string | number;
    }>;
    __isFragment?: undefined;
    __isTeleport?: undefined;
    __isSuspense?: undefined;
} & vue.ComponentOptionsBase<{
    style: vue.StyleValue;
    disabled: boolean;
    absolute: boolean;
    transition: NonNullable<string | boolean | (vue.TransitionProps & {
        component?: vue.Component | undefined;
    })>;
    zIndex: string | number;
    variant: "flat" | "text" | "elevated" | "tonal" | "outlined" | "plain";
    origin: Anchor | "auto" | "overlap";
    vertical: boolean;
    tile: boolean;
    eager: boolean;
    location: Anchor;
    locationStrategy: "static" | ((data: LocationStrategyData, props: StrategyProps$1, contentStyles: vue.Ref<Record<string, string>>) => {
        updateLocation: (e: Event) => void;
    } | undefined) | "connected";
    activatorProps: Record<string, any>;
    openOnHover: boolean;
    closeOnContentClick: boolean;
    closeOnBack: boolean;
    contained: boolean;
    closeText: string;
    multiLine: boolean;
    timeout: string | number;
} & {
    class?: any;
    text?: string | undefined;
    width?: string | number | undefined;
    height?: string | number | undefined;
    theme?: string | undefined;
    target?: Element | vue.ComponentPublicInstance | (string & {}) | "parent" | "cursor" | [x: number, y: number] | undefined;
    color?: string | undefined;
    offset?: string | number | number[] | undefined;
    position?: "fixed" | "absolute" | "relative" | "static" | "sticky" | undefined;
    rounded?: string | number | boolean | undefined;
    contentClass?: any;
    opacity?: string | number | undefined;
    maxHeight?: string | number | undefined;
    maxWidth?: string | number | undefined;
    minHeight?: string | number | undefined;
    minWidth?: string | number | undefined;
    closable?: string | boolean | undefined;
    activator?: Element | vue.ComponentPublicInstance | (string & {}) | "parent" | undefined;
    closeDelay?: string | number | undefined;
    openDelay?: string | number | undefined;
    openOnClick?: boolean | undefined;
    openOnFocus?: boolean | undefined;
    contentProps?: any;
    attach?: string | boolean | Element | undefined;
    timer?: string | boolean | undefined;
} & {}, void, unknown, {}, {}, vue.ComponentOptionsMixin, vue.ComponentOptionsMixin, Omit<{
    'update:modelValue': (val: (string | SnackbarMessage)[]) => true;
}, "v-slot:default" | "$children" | "v-slots" | "modelValue" | "v-slot:text" | "update:modelValue" | "v-slot:actions">, string, {
    style: vue.StyleValue;
    disabled: boolean;
    absolute: boolean;
    transition: NonNullable<string | boolean | (vue.TransitionProps & {
        component?: vue.Component | undefined;
    })>;
    zIndex: string | number;
    rounded: string | number | boolean;
    variant: "flat" | "text" | "elevated" | "tonal" | "outlined" | "plain";
    origin: Anchor | "auto" | "overlap";
    vertical: boolean;
    tile: boolean;
    eager: boolean;
    location: Anchor;
    locationStrategy: "static" | ((data: LocationStrategyData, props: StrategyProps$1, contentStyles: vue.Ref<Record<string, string>>) => {
        updateLocation: (e: Event) => void;
    } | undefined) | "connected";
    activatorProps: Record<string, any>;
    openOnClick: boolean;
    openOnHover: boolean;
    openOnFocus: boolean;
    closeOnContentClick: boolean;
    closeOnBack: boolean;
    contained: boolean;
    closeText: string;
    multiLine: boolean;
    timeout: string | number;
}, {}, string, vue.SlotsType<Partial<{
    default: (arg: {
        item: string | SnackbarMessage;
    }) => vue.VNode<vue.RendererNode, vue.RendererElement, {
        [key: string]: any;
    }>[];
    text: (arg: {
        item: string | SnackbarMessage;
    }) => vue.VNode<vue.RendererNode, vue.RendererElement, {
        [key: string]: any;
    }>[];
    actions: (arg: {
        item: string | SnackbarMessage;
        props: {
            onClick: () => void;
        };
    }) => vue.VNode<vue.RendererNode, vue.RendererElement, {
        [key: string]: any;
    }>[];
}>>> & vue.VNodeProps & vue.AllowedComponentProps & vue.ComponentCustomProps & (new <T extends readonly (string | SnackbarMessage)[]>(props: {
    modelValue?: T | undefined;
    'onUpdate:modelValue'?: ((val: T) => void) | undefined;
}, slots: VSnackbarQueueSlots<T[number]>) => GenericProps<{
    modelValue?: T | undefined;
    'onUpdate:modelValue'?: ((val: T) => void) | undefined;
}, VSnackbarQueueSlots<T[number]>>) & FilterPropsOptions<{
    class: PropType<any>;
    style: {
        type: PropType<vue.StyleValue>;
        default: null;
    };
    text: StringConstructor;
    width: (StringConstructor | NumberConstructor)[];
    height: (StringConstructor | NumberConstructor)[];
    theme: StringConstructor;
    target: PropType<Element | vue.ComponentPublicInstance | (string & {}) | "parent" | "cursor" | [x: number, y: number] | undefined>;
    color: StringConstructor;
    disabled: BooleanConstructor;
    offset: PropType<string | number | number[] | undefined>;
    absolute: BooleanConstructor;
    transition: Omit<{
        type: PropType<string | boolean | (vue.TransitionProps & {
            component?: vue.Component | undefined;
        })>;
        default: string;
        validator: (val: unknown) => boolean;
    }, "default" | "type"> & {
        type: PropType<NonNullable<string | boolean | (vue.TransitionProps & {
            component?: vue.Component | undefined;
        })>>;
        default: NonNullable<string | boolean | (vue.TransitionProps & {
            component?: vue.Component | undefined;
        })>;
    };
    position: {
        type: PropType<"fixed" | "absolute" | "relative" | "static" | "sticky">;
        validator: (v: any) => boolean;
    };
    zIndex: {
        type: (StringConstructor | NumberConstructor)[];
        default: number;
    };
    rounded: {
        type: (StringConstructor | NumberConstructor | BooleanConstructor)[];
        default: undefined;
    };
    variant: {
        type: PropType<"flat" | "text" | "elevated" | "tonal" | "outlined" | "plain">;
        default: string;
        validator: (v: any) => boolean;
    };
    contentClass: null;
    origin: {
        type: PropType<Anchor | "auto" | "overlap">;
        default: string;
    };
    opacity: (StringConstructor | NumberConstructor)[];
    maxHeight: (StringConstructor | NumberConstructor)[];
    maxWidth: (StringConstructor | NumberConstructor)[];
    minHeight: (StringConstructor | NumberConstructor)[];
    minWidth: (StringConstructor | NumberConstructor)[];
    vertical: BooleanConstructor;
    tile: BooleanConstructor;
    eager: BooleanConstructor;
    location: {
        type: PropType<Anchor>;
        default: string;
    };
    activator: PropType<Element | vue.ComponentPublicInstance | (string & {}) | "parent" | undefined>;
    locationStrategy: {
        type: PropType<"static" | ((data: LocationStrategyData, props: StrategyProps$1, contentStyles: vue.Ref<Record<string, string>>) => {
            updateLocation: (e: Event) => void;
        } | undefined) | "connected">;
        default: string;
        validator: (val: any) => boolean;
    };
    closeDelay: (StringConstructor | NumberConstructor)[];
    openDelay: (StringConstructor | NumberConstructor)[];
    activatorProps: {
        type: PropType<Record<string, any>>;
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
    closeOnContentClick: BooleanConstructor;
    closeOnBack: {
        type: BooleanConstructor;
        default: boolean;
    };
    contained: BooleanConstructor;
    contentProps: null;
    attach: PropType<string | boolean | Element>;
    multiLine: BooleanConstructor;
    timer: (StringConstructor | BooleanConstructor)[];
    timeout: {
        type: (StringConstructor | NumberConstructor)[];
        default: number;
    };
    closable: (StringConstructor | BooleanConstructor)[];
    closeText: {
        type: StringConstructor;
        default: string;
    };
    modelValue: {
        type: PropType<readonly (string | SnackbarMessage)[]>;
        default: () => never[];
    };
}, vue.ExtractPropTypes<{
    class: PropType<any>;
    style: {
        type: PropType<vue.StyleValue>;
        default: null;
    };
    text: StringConstructor;
    width: (StringConstructor | NumberConstructor)[];
    height: (StringConstructor | NumberConstructor)[];
    theme: StringConstructor;
    target: PropType<Element | vue.ComponentPublicInstance | (string & {}) | "parent" | "cursor" | [x: number, y: number] | undefined>;
    color: StringConstructor;
    disabled: BooleanConstructor;
    offset: PropType<string | number | number[] | undefined>;
    absolute: BooleanConstructor;
    transition: Omit<{
        type: PropType<string | boolean | (vue.TransitionProps & {
            component?: vue.Component | undefined;
        })>;
        default: string;
        validator: (val: unknown) => boolean;
    }, "default" | "type"> & {
        type: PropType<NonNullable<string | boolean | (vue.TransitionProps & {
            component?: vue.Component | undefined;
        })>>;
        default: NonNullable<string | boolean | (vue.TransitionProps & {
            component?: vue.Component | undefined;
        })>;
    };
    position: {
        type: PropType<"fixed" | "absolute" | "relative" | "static" | "sticky">;
        validator: (v: any) => boolean;
    };
    zIndex: {
        type: (StringConstructor | NumberConstructor)[];
        default: number;
    };
    rounded: {
        type: (StringConstructor | NumberConstructor | BooleanConstructor)[];
        default: undefined;
    };
    variant: {
        type: PropType<"flat" | "text" | "elevated" | "tonal" | "outlined" | "plain">;
        default: string;
        validator: (v: any) => boolean;
    };
    contentClass: null;
    origin: {
        type: PropType<Anchor | "auto" | "overlap">;
        default: string;
    };
    opacity: (StringConstructor | NumberConstructor)[];
    maxHeight: (StringConstructor | NumberConstructor)[];
    maxWidth: (StringConstructor | NumberConstructor)[];
    minHeight: (StringConstructor | NumberConstructor)[];
    minWidth: (StringConstructor | NumberConstructor)[];
    vertical: BooleanConstructor;
    tile: BooleanConstructor;
    eager: BooleanConstructor;
    location: {
        type: PropType<Anchor>;
        default: string;
    };
    activator: PropType<Element | vue.ComponentPublicInstance | (string & {}) | "parent" | undefined>;
    locationStrategy: {
        type: PropType<"static" | ((data: LocationStrategyData, props: StrategyProps$1, contentStyles: vue.Ref<Record<string, string>>) => {
            updateLocation: (e: Event) => void;
        } | undefined) | "connected">;
        default: string;
        validator: (val: any) => boolean;
    };
    closeDelay: (StringConstructor | NumberConstructor)[];
    openDelay: (StringConstructor | NumberConstructor)[];
    activatorProps: {
        type: PropType<Record<string, any>>;
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
    closeOnContentClick: BooleanConstructor;
    closeOnBack: {
        type: BooleanConstructor;
        default: boolean;
    };
    contained: BooleanConstructor;
    contentProps: null;
    attach: PropType<string | boolean | Element>;
    multiLine: BooleanConstructor;
    timer: (StringConstructor | BooleanConstructor)[];
    timeout: {
        type: (StringConstructor | NumberConstructor)[];
        default: number;
    };
    closable: (StringConstructor | BooleanConstructor)[];
    closeText: {
        type: StringConstructor;
        default: string;
    };
    modelValue: {
        type: PropType<readonly (string | SnackbarMessage)[]>;
        default: () => never[];
    };
}>>;
type VSnackbarQueue = InstanceType<typeof VSnackbarQueue>;

export { VSnackbarQueue };
