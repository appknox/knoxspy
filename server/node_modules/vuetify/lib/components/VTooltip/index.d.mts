import * as vue from 'vue';
import { Ref, EffectScope, ComponentPropsOptions, ExtractPropTypes, ComponentPublicInstance } from 'vue';

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

declare const VTooltip: {
    new (...args: any[]): vue.CreateComponentPublicInstance<{
        style: vue.StyleValue;
        disabled: boolean;
        offset: NonNullable<string | number | number[] | undefined>;
        transition: NonNullable<string | boolean | (vue.TransitionProps & {
            component?: vue.Component | undefined;
        })>;
        zIndex: string | number;
        modelValue: boolean;
        origin: NonNullable<Anchor | "auto" | "overlap">;
        minWidth: NonNullable<string | number>;
        eager: boolean;
        location: NonNullable<Anchor>;
        locationStrategy: NonNullable<"static" | ((data: LocationStrategyData, props: StrategyProps, contentStyles: vue.Ref<Record<string, string>>) => {
            updateLocation: (e: Event) => void;
        } | undefined) | "connected">;
        scrollStrategy: NonNullable<"close" | "none" | "block" | ((data: ScrollStrategyData, props: StrategyProps$1, scope: vue.EffectScope) => void) | "reposition">;
        activatorProps: Record<string, any>;
        openOnClick: boolean;
        openOnHover: boolean;
        closeOnContentClick: boolean;
        closeOnBack: boolean;
        contained: boolean;
        noClickAnimation: boolean;
        scrim: NonNullable<string | boolean>;
    } & {
        class?: any;
        id?: string | undefined;
        text?: string | undefined;
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
        closeDelay?: string | number | undefined;
        openDelay?: string | number | undefined;
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
            locationStrategy: "static" | ((data: LocationStrategyData, props: StrategyProps, contentStyles: vue.Ref<Record<string, string>>) => {
                updateLocation: (e: Event) => void;
            } | undefined) | "connected";
            scrollStrategy: "close" | "none" | "block" | ((data: ScrollStrategyData, props: StrategyProps$1, scope: vue.EffectScope) => void) | "reposition";
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
            locationStrategy: "static" | ((data: LocationStrategyData, props: StrategyProps, contentStyles: vue.Ref<Record<string, string>>) => {
                updateLocation: (e: Event) => void;
            } | undefined) | "connected";
            scrollStrategy: "close" | "none" | "block" | ((data: ScrollStrategyData, props: StrategyProps$1, scope: vue.EffectScope) => void) | "reposition";
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
            "v-slot:default"?: false | ((arg: {
                isActive: vue.Ref<boolean>;
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
            locationStrategy: "static" | ((data: LocationStrategyData, props: StrategyProps, contentStyles: vue.Ref<Record<string, string>>) => {
                updateLocation: (e: Event) => void;
            } | undefined) | "connected";
            scrollStrategy: "close" | "none" | "block" | ((data: ScrollStrategyData, props: StrategyProps$1, scope: vue.EffectScope) => void) | "reposition";
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
                isActive: vue.Ref<boolean>;
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
            locationStrategy: "static" | ((data: LocationStrategyData, props: StrategyProps, contentStyles: vue.Ref<Record<string, string>>) => {
                updateLocation: (e: Event) => void;
            } | undefined) | "connected";
            scrollStrategy: "close" | "none" | "block" | ((data: ScrollStrategyData, props: StrategyProps$1, scope: vue.EffectScope) => void) | "reposition";
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
            onAfterEnter?: (() => any) | undefined;
            onAfterLeave?: (() => any) | undefined;
            "onClick:outside"?: ((e: MouseEvent) => any) | undefined;
        }, {
            activatorEl: vue.Ref<HTMLElement | undefined>;
            scrimEl: vue.Ref<HTMLElement | undefined>;
            target: vue.ComputedRef<HTMLElement | [x: number, y: number] | undefined>;
            animateClick: () => void;
            contentEl: vue.Ref<HTMLElement | undefined>;
            globalTop: Readonly<vue.Ref<boolean>>;
            localTop: vue.ComputedRef<boolean>;
            updateLocation: vue.Ref<((e: Event) => void) | undefined>;
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
            locationStrategy: "static" | ((data: LocationStrategyData, props: StrategyProps, contentStyles: vue.Ref<Record<string, string>>) => {
                updateLocation: (e: Event) => void;
            } | undefined) | "connected";
            scrollStrategy: "close" | "none" | "block" | ((data: ScrollStrategyData, props: StrategyProps$1, scope: vue.EffectScope) => void) | "reposition";
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
        $nextTick: typeof vue.nextTick;
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
        locationStrategy: "static" | ((data: LocationStrategyData, props: StrategyProps, contentStyles: vue.Ref<Record<string, string>>) => {
            updateLocation: (e: Event) => void;
        } | undefined) | "connected";
        scrollStrategy: "close" | "none" | "block" | ((data: ScrollStrategyData, props: StrategyProps$1, scope: vue.EffectScope) => void) | "reposition";
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
        onAfterEnter?: (() => any) | undefined;
        onAfterLeave?: (() => any) | undefined;
        "onClick:outside"?: ((e: MouseEvent) => any) | undefined;
    }, "target" | "activatorEl" | "scrimEl" | "animateClick" | "contentEl" | "globalTop" | "localTop" | "updateLocation"> & vue.ShallowUnwrapRef<{
        activatorEl: vue.Ref<HTMLElement | undefined>;
        scrimEl: vue.Ref<HTMLElement | undefined>;
        target: vue.ComputedRef<HTMLElement | [x: number, y: number] | undefined>;
        animateClick: () => void;
        contentEl: vue.Ref<HTMLElement | undefined>;
        globalTop: Readonly<vue.Ref<boolean>>;
        localTop: vue.ComputedRef<boolean>;
        updateLocation: vue.Ref<((e: Event) => void) | undefined>;
    }> & {} & vue.ComponentCustomProperties & {}, "class" | "width" | "height" | "theme" | "key" | "target" | "v-slot:default" | "$children" | "v-slots" | "ref" | "ref_for" | "ref_key" | "onVnodeBeforeMount" | "onVnodeMounted" | "onVnodeBeforeUpdate" | "onVnodeUpdated" | "onVnodeBeforeUnmount" | "onVnodeUnmounted" | "offset" | "onUpdate:modelValue" | "contentClass" | "opacity" | "maxHeight" | "maxWidth" | "minHeight" | "minWidth" | "onAfterEnter" | "onAfterLeave" | "activator" | "v-slot:activator" | "closeDelay" | "openDelay" | "contentProps" | "attach" | "onClick:outside" | ("style" | "disabled" | "absolute" | "transition" | "zIndex" | "modelValue" | "origin" | "eager" | "location" | "locationStrategy" | "scrollStrategy" | "activatorProps" | "openOnClick" | "openOnHover" | "openOnFocus" | "closeOnContentClick" | "closeOnBack" | "contained" | "noClickAnimation" | "persistent" | "scrim" | "_disableGlobalStack")>, `$${any}`>, unknown, {}, {}, vue.ComponentOptionsMixin, vue.ComponentOptionsMixin, {
        'update:modelValue': (value: boolean) => boolean;
    }, vue.VNodeProps & vue.AllowedComponentProps & vue.ComponentCustomProps & {
        style: vue.StyleValue;
        disabled: boolean;
        offset: NonNullable<string | number | number[] | undefined>;
        transition: NonNullable<string | boolean | (vue.TransitionProps & {
            component?: vue.Component | undefined;
        })>;
        zIndex: string | number;
        modelValue: boolean;
        origin: NonNullable<Anchor | "auto" | "overlap">;
        minWidth: NonNullable<string | number>;
        eager: boolean;
        location: NonNullable<Anchor>;
        locationStrategy: NonNullable<"static" | ((data: LocationStrategyData, props: StrategyProps, contentStyles: vue.Ref<Record<string, string>>) => {
            updateLocation: (e: Event) => void;
        } | undefined) | "connected">;
        scrollStrategy: NonNullable<"close" | "none" | "block" | ((data: ScrollStrategyData, props: StrategyProps$1, scope: vue.EffectScope) => void) | "reposition">;
        activatorProps: Record<string, any>;
        openOnClick: boolean;
        openOnHover: boolean;
        closeOnContentClick: boolean;
        closeOnBack: boolean;
        contained: boolean;
        noClickAnimation: boolean;
        scrim: NonNullable<string | boolean>;
    } & {
        class?: any;
        id?: string | undefined;
        text?: string | undefined;
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
        closeDelay?: string | number | undefined;
        openDelay?: string | number | undefined;
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
        transition: NonNullable<string | boolean | (vue.TransitionProps & {
            component?: vue.Component | undefined;
        })>;
        zIndex: string | number;
        modelValue: boolean;
        origin: NonNullable<Anchor | "auto" | "overlap">;
        minWidth: NonNullable<string | number>;
        eager: boolean;
        location: NonNullable<Anchor>;
        locationStrategy: NonNullable<"static" | ((data: LocationStrategyData, props: StrategyProps, contentStyles: vue.Ref<Record<string, string>>) => {
            updateLocation: (e: Event) => void;
        } | undefined) | "connected">;
        scrollStrategy: NonNullable<"close" | "none" | "block" | ((data: ScrollStrategyData, props: StrategyProps$1, scope: vue.EffectScope) => void) | "reposition">;
        activatorProps: Record<string, any>;
        openOnClick: boolean;
        openOnHover: boolean;
        openOnFocus: boolean;
        closeOnContentClick: boolean;
        closeOnBack: boolean;
        contained: boolean;
        noClickAnimation: boolean;
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
        transition: NonNullable<string | boolean | (vue.TransitionProps & {
            component?: vue.Component | undefined;
        })>;
        zIndex: string | number;
        modelValue: boolean;
        origin: NonNullable<Anchor | "auto" | "overlap">;
        minWidth: NonNullable<string | number>;
        eager: boolean;
        location: NonNullable<Anchor>;
        locationStrategy: NonNullable<"static" | ((data: LocationStrategyData, props: StrategyProps, contentStyles: vue.Ref<Record<string, string>>) => {
            updateLocation: (e: Event) => void;
        } | undefined) | "connected">;
        scrollStrategy: NonNullable<"close" | "none" | "block" | ((data: ScrollStrategyData, props: StrategyProps$1, scope: vue.EffectScope) => void) | "reposition">;
        activatorProps: Record<string, any>;
        openOnClick: boolean;
        openOnHover: boolean;
        closeOnContentClick: boolean;
        closeOnBack: boolean;
        contained: boolean;
        noClickAnimation: boolean;
        scrim: NonNullable<string | boolean>;
    } & {
        class?: any;
        id?: string | undefined;
        text?: string | undefined;
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
        closeDelay?: string | number | undefined;
        openDelay?: string | number | undefined;
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
            locationStrategy: "static" | ((data: LocationStrategyData, props: StrategyProps, contentStyles: vue.Ref<Record<string, string>>) => {
                updateLocation: (e: Event) => void;
            } | undefined) | "connected";
            scrollStrategy: "close" | "none" | "block" | ((data: ScrollStrategyData, props: StrategyProps$1, scope: vue.EffectScope) => void) | "reposition";
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
            locationStrategy: "static" | ((data: LocationStrategyData, props: StrategyProps, contentStyles: vue.Ref<Record<string, string>>) => {
                updateLocation: (e: Event) => void;
            } | undefined) | "connected";
            scrollStrategy: "close" | "none" | "block" | ((data: ScrollStrategyData, props: StrategyProps$1, scope: vue.EffectScope) => void) | "reposition";
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
            "v-slot:default"?: false | ((arg: {
                isActive: vue.Ref<boolean>;
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
            locationStrategy: "static" | ((data: LocationStrategyData, props: StrategyProps, contentStyles: vue.Ref<Record<string, string>>) => {
                updateLocation: (e: Event) => void;
            } | undefined) | "connected";
            scrollStrategy: "close" | "none" | "block" | ((data: ScrollStrategyData, props: StrategyProps$1, scope: vue.EffectScope) => void) | "reposition";
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
                isActive: vue.Ref<boolean>;
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
            locationStrategy: "static" | ((data: LocationStrategyData, props: StrategyProps, contentStyles: vue.Ref<Record<string, string>>) => {
                updateLocation: (e: Event) => void;
            } | undefined) | "connected";
            scrollStrategy: "close" | "none" | "block" | ((data: ScrollStrategyData, props: StrategyProps$1, scope: vue.EffectScope) => void) | "reposition";
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
            onAfterEnter?: (() => any) | undefined;
            onAfterLeave?: (() => any) | undefined;
            "onClick:outside"?: ((e: MouseEvent) => any) | undefined;
        }, {
            activatorEl: vue.Ref<HTMLElement | undefined>;
            scrimEl: vue.Ref<HTMLElement | undefined>;
            target: vue.ComputedRef<HTMLElement | [x: number, y: number] | undefined>;
            animateClick: () => void;
            contentEl: vue.Ref<HTMLElement | undefined>;
            globalTop: Readonly<vue.Ref<boolean>>;
            localTop: vue.ComputedRef<boolean>;
            updateLocation: vue.Ref<((e: Event) => void) | undefined>;
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
            locationStrategy: "static" | ((data: LocationStrategyData, props: StrategyProps, contentStyles: vue.Ref<Record<string, string>>) => {
                updateLocation: (e: Event) => void;
            } | undefined) | "connected";
            scrollStrategy: "close" | "none" | "block" | ((data: ScrollStrategyData, props: StrategyProps$1, scope: vue.EffectScope) => void) | "reposition";
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
        $nextTick: typeof vue.nextTick;
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
        locationStrategy: "static" | ((data: LocationStrategyData, props: StrategyProps, contentStyles: vue.Ref<Record<string, string>>) => {
            updateLocation: (e: Event) => void;
        } | undefined) | "connected";
        scrollStrategy: "close" | "none" | "block" | ((data: ScrollStrategyData, props: StrategyProps$1, scope: vue.EffectScope) => void) | "reposition";
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
        onAfterEnter?: (() => any) | undefined;
        onAfterLeave?: (() => any) | undefined;
        "onClick:outside"?: ((e: MouseEvent) => any) | undefined;
    }, "target" | "activatorEl" | "scrimEl" | "animateClick" | "contentEl" | "globalTop" | "localTop" | "updateLocation"> & vue.ShallowUnwrapRef<{
        activatorEl: vue.Ref<HTMLElement | undefined>;
        scrimEl: vue.Ref<HTMLElement | undefined>;
        target: vue.ComputedRef<HTMLElement | [x: number, y: number] | undefined>;
        animateClick: () => void;
        contentEl: vue.Ref<HTMLElement | undefined>;
        globalTop: Readonly<vue.Ref<boolean>>;
        localTop: vue.ComputedRef<boolean>;
        updateLocation: vue.Ref<((e: Event) => void) | undefined>;
    }> & {} & vue.ComponentCustomProperties & {}, "class" | "width" | "height" | "theme" | "key" | "target" | "v-slot:default" | "$children" | "v-slots" | "ref" | "ref_for" | "ref_key" | "onVnodeBeforeMount" | "onVnodeMounted" | "onVnodeBeforeUpdate" | "onVnodeUpdated" | "onVnodeBeforeUnmount" | "onVnodeUnmounted" | "offset" | "onUpdate:modelValue" | "contentClass" | "opacity" | "maxHeight" | "maxWidth" | "minHeight" | "minWidth" | "onAfterEnter" | "onAfterLeave" | "activator" | "v-slot:activator" | "closeDelay" | "openDelay" | "contentProps" | "attach" | "onClick:outside" | ("style" | "disabled" | "absolute" | "transition" | "zIndex" | "modelValue" | "origin" | "eager" | "location" | "locationStrategy" | "scrollStrategy" | "activatorProps" | "openOnClick" | "openOnHover" | "openOnFocus" | "closeOnContentClick" | "closeOnBack" | "contained" | "noClickAnimation" | "persistent" | "scrim" | "_disableGlobalStack")>, `$${any}`>, {}, {}, {}, {
        style: vue.StyleValue;
        disabled: boolean;
        offset: NonNullable<string | number | number[] | undefined>;
        transition: NonNullable<string | boolean | (vue.TransitionProps & {
            component?: vue.Component | undefined;
        })>;
        zIndex: string | number;
        modelValue: boolean;
        origin: NonNullable<Anchor | "auto" | "overlap">;
        minWidth: NonNullable<string | number>;
        eager: boolean;
        location: NonNullable<Anchor>;
        locationStrategy: NonNullable<"static" | ((data: LocationStrategyData, props: StrategyProps, contentStyles: vue.Ref<Record<string, string>>) => {
            updateLocation: (e: Event) => void;
        } | undefined) | "connected">;
        scrollStrategy: NonNullable<"close" | "none" | "block" | ((data: ScrollStrategyData, props: StrategyProps$1, scope: vue.EffectScope) => void) | "reposition">;
        activatorProps: Record<string, any>;
        openOnClick: boolean;
        openOnHover: boolean;
        openOnFocus: boolean;
        closeOnContentClick: boolean;
        closeOnBack: boolean;
        contained: boolean;
        noClickAnimation: boolean;
        scrim: NonNullable<string | boolean>;
    }>;
    __isFragment?: undefined;
    __isTeleport?: undefined;
    __isSuspense?: undefined;
} & vue.ComponentOptionsBase<{
    style: vue.StyleValue;
    disabled: boolean;
    offset: NonNullable<string | number | number[] | undefined>;
    transition: NonNullable<string | boolean | (vue.TransitionProps & {
        component?: vue.Component | undefined;
    })>;
    zIndex: string | number;
    modelValue: boolean;
    origin: NonNullable<Anchor | "auto" | "overlap">;
    minWidth: NonNullable<string | number>;
    eager: boolean;
    location: NonNullable<Anchor>;
    locationStrategy: NonNullable<"static" | ((data: LocationStrategyData, props: StrategyProps, contentStyles: vue.Ref<Record<string, string>>) => {
        updateLocation: (e: Event) => void;
    } | undefined) | "connected">;
    scrollStrategy: NonNullable<"close" | "none" | "block" | ((data: ScrollStrategyData, props: StrategyProps$1, scope: vue.EffectScope) => void) | "reposition">;
    activatorProps: Record<string, any>;
    openOnClick: boolean;
    openOnHover: boolean;
    closeOnContentClick: boolean;
    closeOnBack: boolean;
    contained: boolean;
    noClickAnimation: boolean;
    scrim: NonNullable<string | boolean>;
} & {
    class?: any;
    id?: string | undefined;
    text?: string | undefined;
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
    closeDelay?: string | number | undefined;
    openDelay?: string | number | undefined;
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
        locationStrategy: "static" | ((data: LocationStrategyData, props: StrategyProps, contentStyles: vue.Ref<Record<string, string>>) => {
            updateLocation: (e: Event) => void;
        } | undefined) | "connected";
        scrollStrategy: "close" | "none" | "block" | ((data: ScrollStrategyData, props: StrategyProps$1, scope: vue.EffectScope) => void) | "reposition";
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
        locationStrategy: "static" | ((data: LocationStrategyData, props: StrategyProps, contentStyles: vue.Ref<Record<string, string>>) => {
            updateLocation: (e: Event) => void;
        } | undefined) | "connected";
        scrollStrategy: "close" | "none" | "block" | ((data: ScrollStrategyData, props: StrategyProps$1, scope: vue.EffectScope) => void) | "reposition";
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
        "v-slot:default"?: false | ((arg: {
            isActive: vue.Ref<boolean>;
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
        locationStrategy: "static" | ((data: LocationStrategyData, props: StrategyProps, contentStyles: vue.Ref<Record<string, string>>) => {
            updateLocation: (e: Event) => void;
        } | undefined) | "connected";
        scrollStrategy: "close" | "none" | "block" | ((data: ScrollStrategyData, props: StrategyProps$1, scope: vue.EffectScope) => void) | "reposition";
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
            isActive: vue.Ref<boolean>;
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
        locationStrategy: "static" | ((data: LocationStrategyData, props: StrategyProps, contentStyles: vue.Ref<Record<string, string>>) => {
            updateLocation: (e: Event) => void;
        } | undefined) | "connected";
        scrollStrategy: "close" | "none" | "block" | ((data: ScrollStrategyData, props: StrategyProps$1, scope: vue.EffectScope) => void) | "reposition";
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
        onAfterEnter?: (() => any) | undefined;
        onAfterLeave?: (() => any) | undefined;
        "onClick:outside"?: ((e: MouseEvent) => any) | undefined;
    }, {
        activatorEl: vue.Ref<HTMLElement | undefined>;
        scrimEl: vue.Ref<HTMLElement | undefined>;
        target: vue.ComputedRef<HTMLElement | [x: number, y: number] | undefined>;
        animateClick: () => void;
        contentEl: vue.Ref<HTMLElement | undefined>;
        globalTop: Readonly<vue.Ref<boolean>>;
        localTop: vue.ComputedRef<boolean>;
        updateLocation: vue.Ref<((e: Event) => void) | undefined>;
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
        locationStrategy: "static" | ((data: LocationStrategyData, props: StrategyProps, contentStyles: vue.Ref<Record<string, string>>) => {
            updateLocation: (e: Event) => void;
        } | undefined) | "connected";
        scrollStrategy: "close" | "none" | "block" | ((data: ScrollStrategyData, props: StrategyProps$1, scope: vue.EffectScope) => void) | "reposition";
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
    $nextTick: typeof vue.nextTick;
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
    locationStrategy: "static" | ((data: LocationStrategyData, props: StrategyProps, contentStyles: vue.Ref<Record<string, string>>) => {
        updateLocation: (e: Event) => void;
    } | undefined) | "connected";
    scrollStrategy: "close" | "none" | "block" | ((data: ScrollStrategyData, props: StrategyProps$1, scope: vue.EffectScope) => void) | "reposition";
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
    onAfterEnter?: (() => any) | undefined;
    onAfterLeave?: (() => any) | undefined;
    "onClick:outside"?: ((e: MouseEvent) => any) | undefined;
}, "target" | "activatorEl" | "scrimEl" | "animateClick" | "contentEl" | "globalTop" | "localTop" | "updateLocation"> & vue.ShallowUnwrapRef<{
    activatorEl: vue.Ref<HTMLElement | undefined>;
    scrimEl: vue.Ref<HTMLElement | undefined>;
    target: vue.ComputedRef<HTMLElement | [x: number, y: number] | undefined>;
    animateClick: () => void;
    contentEl: vue.Ref<HTMLElement | undefined>;
    globalTop: Readonly<vue.Ref<boolean>>;
    localTop: vue.ComputedRef<boolean>;
    updateLocation: vue.Ref<((e: Event) => void) | undefined>;
}> & {} & vue.ComponentCustomProperties & {}, "class" | "width" | "height" | "theme" | "key" | "target" | "v-slot:default" | "$children" | "v-slots" | "ref" | "ref_for" | "ref_key" | "onVnodeBeforeMount" | "onVnodeMounted" | "onVnodeBeforeUpdate" | "onVnodeUpdated" | "onVnodeBeforeUnmount" | "onVnodeUnmounted" | "offset" | "onUpdate:modelValue" | "contentClass" | "opacity" | "maxHeight" | "maxWidth" | "minHeight" | "minWidth" | "onAfterEnter" | "onAfterLeave" | "activator" | "v-slot:activator" | "closeDelay" | "openDelay" | "contentProps" | "attach" | "onClick:outside" | ("style" | "disabled" | "absolute" | "transition" | "zIndex" | "modelValue" | "origin" | "eager" | "location" | "locationStrategy" | "scrollStrategy" | "activatorProps" | "openOnClick" | "openOnHover" | "openOnFocus" | "closeOnContentClick" | "closeOnBack" | "contained" | "noClickAnimation" | "persistent" | "scrim" | "_disableGlobalStack")>, `$${any}`>, unknown, {}, {}, vue.ComponentOptionsMixin, vue.ComponentOptionsMixin, {
    'update:modelValue': (value: boolean) => boolean;
}, string, {
    style: vue.StyleValue;
    disabled: boolean;
    offset: NonNullable<string | number | number[] | undefined>;
    transition: NonNullable<string | boolean | (vue.TransitionProps & {
        component?: vue.Component | undefined;
    })>;
    zIndex: string | number;
    modelValue: boolean;
    origin: NonNullable<Anchor | "auto" | "overlap">;
    minWidth: NonNullable<string | number>;
    eager: boolean;
    location: NonNullable<Anchor>;
    locationStrategy: NonNullable<"static" | ((data: LocationStrategyData, props: StrategyProps, contentStyles: vue.Ref<Record<string, string>>) => {
        updateLocation: (e: Event) => void;
    } | undefined) | "connected">;
    scrollStrategy: NonNullable<"close" | "none" | "block" | ((data: ScrollStrategyData, props: StrategyProps$1, scope: vue.EffectScope) => void) | "reposition">;
    activatorProps: Record<string, any>;
    openOnClick: boolean;
    openOnHover: boolean;
    openOnFocus: boolean;
    closeOnContentClick: boolean;
    closeOnBack: boolean;
    contained: boolean;
    noClickAnimation: boolean;
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
    origin: Omit<{
        type: vue.PropType<Anchor | "auto" | "overlap">;
        default: string;
    }, "default" | "type"> & {
        type: vue.PropType<NonNullable<Anchor | "auto" | "overlap">>;
        default: NonNullable<Anchor | "auto" | "overlap">;
    };
    opacity: (StringConstructor | NumberConstructor)[];
    maxHeight: (StringConstructor | NumberConstructor)[];
    maxWidth: (StringConstructor | NumberConstructor)[];
    minHeight: (StringConstructor | NumberConstructor)[];
    minWidth: {
        type: vue.PropType<NonNullable<string | number>>;
        default: NonNullable<string | number>;
    };
    eager: {
        type: vue.PropType<boolean>;
        default: boolean;
    };
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
    closeDelay: (StringConstructor | NumberConstructor)[];
    openDelay: (StringConstructor | NumberConstructor)[];
    activatorProps: {
        type: vue.PropType<Record<string, any>>;
        default: () => {};
    };
    openOnClick: Omit<{
        type: BooleanConstructor;
        default: undefined;
    }, "default" | "type"> & {
        type: vue.PropType<boolean>;
        default: boolean;
    };
    openOnHover: {
        type: vue.PropType<boolean>;
        default: boolean;
    };
    openOnFocus: {
        type: BooleanConstructor;
        default: undefined;
    };
    closeOnContentClick: BooleanConstructor;
    closeOnBack: Omit<{
        type: BooleanConstructor;
        default: boolean;
    }, "default" | "type"> & {
        type: vue.PropType<boolean>;
        default: boolean;
    };
    contained: BooleanConstructor;
    contentProps: null;
    noClickAnimation: BooleanConstructor;
    scrim: Omit<{
        type: (StringConstructor | BooleanConstructor)[];
        default: boolean;
    }, "default" | "type"> & {
        type: vue.PropType<NonNullable<string | boolean>>;
        default: NonNullable<string | boolean>;
    };
    attach: vue.PropType<string | boolean | Element>;
    id: StringConstructor;
    text: StringConstructor;
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
    origin: Omit<{
        type: vue.PropType<Anchor | "auto" | "overlap">;
        default: string;
    }, "default" | "type"> & {
        type: vue.PropType<NonNullable<Anchor | "auto" | "overlap">>;
        default: NonNullable<Anchor | "auto" | "overlap">;
    };
    opacity: (StringConstructor | NumberConstructor)[];
    maxHeight: (StringConstructor | NumberConstructor)[];
    maxWidth: (StringConstructor | NumberConstructor)[];
    minHeight: (StringConstructor | NumberConstructor)[];
    minWidth: {
        type: vue.PropType<NonNullable<string | number>>;
        default: NonNullable<string | number>;
    };
    eager: {
        type: vue.PropType<boolean>;
        default: boolean;
    };
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
    closeDelay: (StringConstructor | NumberConstructor)[];
    openDelay: (StringConstructor | NumberConstructor)[];
    activatorProps: {
        type: vue.PropType<Record<string, any>>;
        default: () => {};
    };
    openOnClick: Omit<{
        type: BooleanConstructor;
        default: undefined;
    }, "default" | "type"> & {
        type: vue.PropType<boolean>;
        default: boolean;
    };
    openOnHover: {
        type: vue.PropType<boolean>;
        default: boolean;
    };
    openOnFocus: {
        type: BooleanConstructor;
        default: undefined;
    };
    closeOnContentClick: BooleanConstructor;
    closeOnBack: Omit<{
        type: BooleanConstructor;
        default: boolean;
    }, "default" | "type"> & {
        type: vue.PropType<boolean>;
        default: boolean;
    };
    contained: BooleanConstructor;
    contentProps: null;
    noClickAnimation: BooleanConstructor;
    scrim: Omit<{
        type: (StringConstructor | BooleanConstructor)[];
        default: boolean;
    }, "default" | "type"> & {
        type: vue.PropType<NonNullable<string | boolean>>;
        default: NonNullable<string | boolean>;
    };
    attach: vue.PropType<string | boolean | Element>;
    id: StringConstructor;
    text: StringConstructor;
}>>;
type VTooltip = InstanceType<typeof VTooltip>;

export { VTooltip };
