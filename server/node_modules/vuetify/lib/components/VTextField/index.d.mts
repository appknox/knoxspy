import * as vue from 'vue';
import { ComponentPropsOptions, ExtractPropTypes, VNodeChild, VNode, JSXComponent, PropType, ComputedRef, Ref, nextTick } from 'vue';

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

interface LoaderSlotProps {
    color: string | undefined;
    isActive: boolean;
}

type VMessageSlot = {
    message: string;
};

type Density = null | 'default' | 'comfortable' | 'compact';

type ValidationResult = string | boolean;
type ValidationRule = ValidationResult | PromiseLike<ValidationResult> | ((value: any) => ValidationResult) | ((value: any) => PromiseLike<ValidationResult>);

type IconValue = string | (string | [path: string, opacity: number])[] | JSXComponent;
declare const IconValue: PropType<IconValue>;

interface VInputSlot {
    id: ComputedRef<string>;
    messagesId: ComputedRef<string>;
    isDirty: ComputedRef<boolean>;
    isDisabled: ComputedRef<boolean>;
    isReadonly: ComputedRef<boolean>;
    isPristine: Ref<boolean>;
    isValid: ComputedRef<boolean | null>;
    isValidating: Ref<boolean>;
    reset: () => void;
    resetValidation: () => void;
    validate: () => void;
}
type VInputSlots = {
    default: VInputSlot;
    prepend: VInputSlot;
    append: VInputSlot;
    details: VInputSlot;
    message: VMessageSlot;
};

interface DefaultInputSlot {
    isActive: Ref<boolean>;
    isFocused: Ref<boolean>;
    controlRef: Ref<HTMLElement | undefined>;
    focus: () => void;
    blur: () => void;
}
interface VFieldSlot extends DefaultInputSlot {
    props: Record<string, unknown>;
}
type VFieldSlots = {
    clear: DefaultInputSlot & {
        props: Record<string, any>;
    };
    'prepend-inner': DefaultInputSlot;
    'append-inner': DefaultInputSlot;
    label: DefaultInputSlot & {
        label: string | undefined;
        props: Record<string, any>;
    };
    loader: LoaderSlotProps;
    default: VFieldSlot;
};

type VCounterSlot = {
    counter: string;
    max: string | number | undefined;
    value: string | number | undefined;
};

declare const VTextField: {
    new (...args: any[]): vue.CreateComponentPublicInstance<{
        reverse: boolean;
        flat: boolean;
        style: vue.StyleValue;
        type: string;
        active: boolean;
        error: boolean;
        disabled: boolean;
        messages: string | readonly string[];
        focused: boolean;
        errorMessages: string | readonly string[] | null;
        maxErrors: string | number;
        readonly: boolean | null;
        rules: readonly ValidationRule[];
        variant: "underlined" | "filled" | "outlined" | "plain" | "solo" | "solo-inverted" | "solo-filled";
        tile: boolean;
        density: Density;
        direction: "horizontal" | "vertical";
        clearIcon: IconValue;
        hideSpinButtons: boolean;
        persistentHint: boolean;
        autofocus: boolean;
        clearable: boolean;
        dirty: boolean;
        persistentClear: boolean;
        singleLine: boolean;
        persistentPlaceholder: boolean;
        persistentCounter: boolean;
    } & {
        class?: any;
        id?: string | undefined;
        label?: string | undefined;
        width?: string | number | undefined;
        theme?: string | undefined;
        color?: string | undefined;
        name?: string | undefined;
        prefix?: string | undefined;
        loading?: string | boolean | undefined;
        placeholder?: string | undefined;
        counter?: string | number | boolean | undefined;
        'onUpdate:focused'?: ((args_0: boolean) => void) | undefined;
        modelValue?: any;
        validateOn?: ("input" | "blur" | "submit") | "input lazy" | "blur lazy" | "submit lazy" | "lazy input" | "lazy blur" | "lazy submit" | "lazy" | undefined;
        validationValue?: any;
        rounded?: string | number | boolean | undefined;
        maxWidth?: string | number | undefined;
        minWidth?: string | number | undefined;
        role?: string | undefined;
        baseColor?: string | undefined;
        bgColor?: string | undefined;
        prependIcon?: IconValue | undefined;
        appendIcon?: IconValue | undefined;
        appendInnerIcon?: IconValue | undefined;
        prependInnerIcon?: IconValue | undefined;
        'onClick:clear'?: ((args_0: MouseEvent) => void) | undefined;
        'onClick:prepend'?: ((args_0: MouseEvent) => void) | undefined;
        'onClick:append'?: ((args_0: MouseEvent) => void) | undefined;
        'onClick:appendInner'?: ((args_0: MouseEvent) => void) | undefined;
        'onClick:prependInner'?: ((args_0: MouseEvent) => void) | undefined;
        centerAffix?: boolean | undefined;
        hint?: string | undefined;
        hideDetails?: boolean | "auto" | undefined;
        suffix?: string | undefined;
        counterValue?: number | ((value: any) => number) | undefined;
        modelModifiers?: Record<string, boolean> | undefined;
    } & {
        $children?: vue.VNodeChild | (() => vue.VNodeChild) | {
            clear?: ((arg: DefaultInputSlot & {
                props: Record<string, any>;
            }) => vue.VNodeChild) | undefined;
            details?: ((arg: VInputSlot) => vue.VNodeChild) | undefined;
            label?: ((arg: DefaultInputSlot & {
                label: string | undefined;
                props: Record<string, any>;
            }) => vue.VNodeChild) | undefined;
            message?: ((arg: VMessageSlot) => vue.VNodeChild) | undefined;
            prepend?: ((arg: VInputSlot) => vue.VNodeChild) | undefined;
            append?: ((arg: VInputSlot) => vue.VNodeChild) | undefined;
            loader?: ((arg: LoaderSlotProps) => vue.VNodeChild) | undefined;
            'prepend-inner'?: ((arg: DefaultInputSlot) => vue.VNodeChild) | undefined;
            'append-inner'?: ((arg: DefaultInputSlot) => vue.VNodeChild) | undefined;
            default?: (() => vue.VNodeChild) | undefined;
            counter?: ((arg: VCounterSlot) => vue.VNodeChild) | undefined;
        };
        'v-slots'?: {
            clear?: false | ((arg: DefaultInputSlot & {
                props: Record<string, any>;
            }) => vue.VNodeChild) | undefined;
            details?: false | ((arg: VInputSlot) => vue.VNodeChild) | undefined;
            label?: false | ((arg: DefaultInputSlot & {
                label: string | undefined;
                props: Record<string, any>;
            }) => vue.VNodeChild) | undefined;
            message?: false | ((arg: VMessageSlot) => vue.VNodeChild) | undefined;
            prepend?: false | ((arg: VInputSlot) => vue.VNodeChild) | undefined;
            append?: false | ((arg: VInputSlot) => vue.VNodeChild) | undefined;
            loader?: false | ((arg: LoaderSlotProps) => vue.VNodeChild) | undefined;
            'prepend-inner'?: false | ((arg: DefaultInputSlot) => vue.VNodeChild) | undefined;
            'append-inner'?: false | ((arg: DefaultInputSlot) => vue.VNodeChild) | undefined;
            default?: false | (() => vue.VNodeChild) | undefined;
            counter?: false | ((arg: VCounterSlot) => vue.VNodeChild) | undefined;
        } | undefined;
    } & {
        "v-slot:clear"?: false | ((arg: DefaultInputSlot & {
            props: Record<string, any>;
        }) => vue.VNodeChild) | undefined;
        "v-slot:details"?: false | ((arg: VInputSlot) => vue.VNodeChild) | undefined;
        "v-slot:label"?: false | ((arg: DefaultInputSlot & {
            label: string | undefined;
            props: Record<string, any>;
        }) => vue.VNodeChild) | undefined;
        "v-slot:message"?: false | ((arg: VMessageSlot) => vue.VNodeChild) | undefined;
        "v-slot:prepend"?: false | ((arg: VInputSlot) => vue.VNodeChild) | undefined;
        "v-slot:append"?: false | ((arg: VInputSlot) => vue.VNodeChild) | undefined;
        "v-slot:loader"?: false | ((arg: LoaderSlotProps) => vue.VNodeChild) | undefined;
        "v-slot:prepend-inner"?: false | ((arg: DefaultInputSlot) => vue.VNodeChild) | undefined;
        "v-slot:append-inner"?: false | ((arg: DefaultInputSlot) => vue.VNodeChild) | undefined;
        "v-slot:default"?: false | (() => vue.VNodeChild) | undefined;
        "v-slot:counter"?: false | ((arg: VCounterSlot) => vue.VNodeChild) | undefined;
    } & {
        "onUpdate:focused"?: ((focused: boolean) => any) | undefined;
        "onUpdate:modelValue"?: ((val: string) => any) | undefined;
        "onClick:control"?: ((e: MouseEvent) => any) | undefined;
        "onMousedown:control"?: ((e: MouseEvent) => any) | undefined;
    }, HTMLInputElement & Omit<Omit<{
        $: vue.ComponentInternalInstance;
        $data: {};
        $props: Partial<{
            style: vue.StyleValue;
            error: boolean;
            disabled: boolean | null;
            messages: string | readonly string[];
            focused: boolean;
            errorMessages: string | readonly string[] | null;
            maxErrors: string | number;
            readonly: boolean | null;
            rules: readonly ValidationRule[];
            density: Density;
            direction: "horizontal" | "vertical";
            centerAffix: boolean;
            hideSpinButtons: boolean;
            persistentHint: boolean;
        }> & Omit<{
            style: vue.StyleValue;
            error: boolean;
            disabled: boolean | null;
            messages: string | readonly string[];
            focused: boolean;
            errorMessages: string | readonly string[] | null;
            maxErrors: string | number;
            readonly: boolean | null;
            rules: readonly ValidationRule[];
            density: Density;
            direction: "horizontal" | "vertical";
            centerAffix: boolean;
            hideSpinButtons: boolean;
            persistentHint: boolean;
            class?: any;
            id?: string | undefined;
            label?: string | undefined;
            width?: string | number | undefined;
            theme?: string | undefined;
            name?: string | undefined;
            'onUpdate:focused'?: ((args_0: boolean) => void) | undefined;
            validateOn?: ("input" | "blur" | "submit") | "input lazy" | "blur lazy" | "submit lazy" | "lazy input" | "lazy blur" | "lazy submit" | "lazy" | undefined;
            validationValue?: any;
            maxWidth?: string | number | undefined;
            minWidth?: string | number | undefined;
            prependIcon?: IconValue | undefined;
            appendIcon?: IconValue | undefined;
            'onClick:prepend'?: ((args_0: MouseEvent) => void) | undefined;
            'onClick:append'?: ((args_0: MouseEvent) => void) | undefined;
            hint?: string | undefined;
            hideDetails?: boolean | "auto" | undefined;
        } & vue.VNodeProps & vue.AllowedComponentProps & vue.ComponentCustomProps & {
            style: vue.StyleValue;
            error: boolean;
            disabled: boolean | null;
            messages: string | readonly string[];
            focused: boolean;
            errorMessages: string | readonly string[] | null;
            maxErrors: string | number;
            readonly: boolean | null;
            rules: readonly ValidationRule[];
            density: Density;
            direction: "horizontal" | "vertical";
            centerAffix: boolean;
            hideSpinButtons: boolean;
            persistentHint: boolean;
        } & {
            class?: any;
            id?: string | undefined;
            label?: string | undefined;
            width?: string | number | undefined;
            theme?: string | undefined;
            name?: string | undefined;
            'onUpdate:focused'?: ((args_0: boolean) => void) | undefined;
            validateOn?: ("input" | "blur" | "submit") | "input lazy" | "blur lazy" | "submit lazy" | "lazy input" | "lazy blur" | "lazy submit" | "lazy" | undefined;
            validationValue?: any;
            maxWidth?: string | number | undefined;
            minWidth?: string | number | undefined;
            prependIcon?: IconValue | undefined;
            appendIcon?: IconValue | undefined;
            'onClick:prepend'?: ((args_0: MouseEvent) => void) | undefined;
            'onClick:append'?: ((args_0: MouseEvent) => void) | undefined;
            hint?: string | undefined;
            hideDetails?: boolean | "auto" | undefined;
        } & {}, "style" | "error" | "disabled" | "messages" | "focused" | "errorMessages" | "maxErrors" | "readonly" | "rules" | "density" | "direction" | "centerAffix" | "hideSpinButtons" | "persistentHint">;
        $attrs: {
            [x: string]: unknown;
        };
        $refs: {
            [x: string]: unknown;
        };
        $slots: Readonly<{
            default?: ((arg: VInputSlot) => vue.VNode<vue.RendererNode, vue.RendererElement, {
                [key: string]: any;
            }>[]) | undefined;
            prepend?: ((arg: VInputSlot) => vue.VNode<vue.RendererNode, vue.RendererElement, {
                [key: string]: any;
            }>[]) | undefined;
            append?: ((arg: VInputSlot) => vue.VNode<vue.RendererNode, vue.RendererElement, {
                [key: string]: any;
            }>[]) | undefined;
            details?: ((arg: VInputSlot) => vue.VNode<vue.RendererNode, vue.RendererElement, {
                [key: string]: any;
            }>[]) | undefined;
            message?: ((arg: VMessageSlot) => vue.VNode<vue.RendererNode, vue.RendererElement, {
                [key: string]: any;
            }>[]) | undefined;
        }>;
        $root: vue.ComponentPublicInstance<{}, {}, {}, {}, {}, {}, {}, {}, false, vue.ComponentOptionsBase<any, any, any, any, any, any, any, any, any, {}, {}, string, {}>, {}, {}> | null;
        $parent: vue.ComponentPublicInstance<{}, {}, {}, {}, {}, {}, {}, {}, false, vue.ComponentOptionsBase<any, any, any, any, any, any, any, any, any, {}, {}, string, {}>, {}, {}> | null;
        $emit: (event: string, ...args: any[]) => void;
        $el: any;
        $options: vue.ComponentOptionsBase<{
            style: vue.StyleValue;
            error: boolean;
            disabled: boolean | null;
            messages: string | readonly string[];
            focused: boolean;
            errorMessages: string | readonly string[] | null;
            maxErrors: string | number;
            readonly: boolean | null;
            rules: readonly ValidationRule[];
            density: Density;
            direction: "horizontal" | "vertical";
            centerAffix: boolean;
            hideSpinButtons: boolean;
            persistentHint: boolean;
        } & {
            class?: any;
            id?: string | undefined;
            label?: string | undefined;
            width?: string | number | undefined;
            theme?: string | undefined;
            name?: string | undefined;
            'onUpdate:focused'?: ((args_0: boolean) => void) | undefined;
            validateOn?: ("input" | "blur" | "submit") | "input lazy" | "blur lazy" | "submit lazy" | "lazy input" | "lazy blur" | "lazy submit" | "lazy" | undefined;
            validationValue?: any;
            maxWidth?: string | number | undefined;
            minWidth?: string | number | undefined;
            prependIcon?: IconValue | undefined;
            appendIcon?: IconValue | undefined;
            'onClick:prepend'?: ((args_0: MouseEvent) => void) | undefined;
            'onClick:append'?: ((args_0: MouseEvent) => void) | undefined;
            hint?: string | undefined;
            hideDetails?: boolean | "auto" | undefined;
        } & {}, {
            reset: () => Promise<void>;
            resetValidation: () => Promise<void>;
            validate: (silent?: boolean) => Promise<string[]>;
            isValid: vue.ComputedRef<boolean | null>;
            errorMessages: vue.ComputedRef<string[]>;
        }, unknown, {}, {}, vue.ComponentOptionsMixin, vue.ComponentOptionsMixin, Omit<{
            'update:modelValue': (value: any) => true;
        }, "v-slot:default" | "$children" | "v-slots" | "modelValue" | "v-slot:prepend" | "v-slot:append" | "update:modelValue" | "v-slot:message" | "v-slot:details">, string, {
            style: vue.StyleValue;
            error: boolean;
            disabled: boolean | null;
            messages: string | readonly string[];
            focused: boolean;
            errorMessages: string | readonly string[] | null;
            maxErrors: string | number;
            readonly: boolean | null;
            rules: readonly ValidationRule[];
            density: Density;
            direction: "horizontal" | "vertical";
            centerAffix: boolean;
            hideSpinButtons: boolean;
            persistentHint: boolean;
        }, {}, string, vue.SlotsType<Partial<{
            default: (arg: VInputSlot) => vue.VNode<vue.RendererNode, vue.RendererElement, {
                [key: string]: any;
            }>[];
            prepend: (arg: VInputSlot) => vue.VNode<vue.RendererNode, vue.RendererElement, {
                [key: string]: any;
            }>[];
            append: (arg: VInputSlot) => vue.VNode<vue.RendererNode, vue.RendererElement, {
                [key: string]: any;
            }>[];
            details: (arg: VInputSlot) => vue.VNode<vue.RendererNode, vue.RendererElement, {
                [key: string]: any;
            }>[];
            message: (arg: VMessageSlot) => vue.VNode<vue.RendererNode, vue.RendererElement, {
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
        error: boolean;
        disabled: boolean | null;
        messages: string | readonly string[];
        focused: boolean;
        errorMessages: string | readonly string[] | null;
        maxErrors: string | number;
        readonly: boolean | null;
        rules: readonly ValidationRule[];
        density: Density;
        direction: "horizontal" | "vertical";
        centerAffix: boolean;
        hideSpinButtons: boolean;
        persistentHint: boolean;
    } & {
        class?: any;
        id?: string | undefined;
        label?: string | undefined;
        width?: string | number | undefined;
        theme?: string | undefined;
        name?: string | undefined;
        'onUpdate:focused'?: ((args_0: boolean) => void) | undefined;
        validateOn?: ("input" | "blur" | "submit") | "input lazy" | "blur lazy" | "submit lazy" | "lazy input" | "lazy blur" | "lazy submit" | "lazy" | undefined;
        validationValue?: any;
        maxWidth?: string | number | undefined;
        minWidth?: string | number | undefined;
        prependIcon?: IconValue | undefined;
        appendIcon?: IconValue | undefined;
        'onClick:prepend'?: ((args_0: MouseEvent) => void) | undefined;
        'onClick:append'?: ((args_0: MouseEvent) => void) | undefined;
        hint?: string | undefined;
        hideDetails?: boolean | "auto" | undefined;
    } & {}, "reset" | "isValid" | "errorMessages" | "validate" | "resetValidation"> & vue.ShallowUnwrapRef<{
        reset: () => Promise<void>;
        resetValidation: () => Promise<void>;
        validate: (silent?: boolean) => Promise<string[]>;
        isValid: vue.ComputedRef<boolean | null>;
        errorMessages: vue.ComputedRef<string[]>;
    }> & {} & vue.ComponentCustomProperties & {} & GenericProps<{
        modelValue?: unknown;
        'onUpdate:modelValue'?: ((value: unknown) => void) | undefined;
    }, VInputSlots>, "class" | "id" | "label" | "width" | "theme" | "key" | "name" | "v-slot:default" | "$children" | "v-slots" | "ref" | "ref_for" | "ref_key" | "onVnodeBeforeMount" | "onVnodeMounted" | "onVnodeBeforeUpdate" | "onVnodeUpdated" | "onVnodeBeforeUnmount" | "onVnodeUnmounted" | "onUpdate:focused" | "modelValue" | "validateOn" | "validationValue" | "onUpdate:modelValue" | "maxWidth" | "minWidth" | "v-slot:prepend" | "v-slot:append" | "prependIcon" | "appendIcon" | "onClick:prepend" | "onClick:append" | "v-slot:message" | "hint" | "hideDetails" | "v-slot:details" | ("style" | "error" | "disabled" | "messages" | "focused" | "errorMessages" | "maxErrors" | "readonly" | "rules" | "density" | "direction" | "centerAffix" | "hideSpinButtons" | "persistentHint")>, `$${any}`> & Omit<Omit<{
        $: vue.ComponentInternalInstance;
        $data: {};
        $props: Partial<{
            reverse: boolean;
            flat: boolean;
            style: vue.StyleValue;
            active: boolean;
            error: boolean;
            disabled: boolean;
            focused: boolean;
            rounded: string | number | boolean;
            variant: "underlined" | "filled" | "outlined" | "plain" | "solo" | "solo-inverted" | "solo-filled";
            tile: boolean;
            clearIcon: IconValue;
            centerAffix: boolean;
            clearable: boolean;
            dirty: boolean;
            persistentClear: boolean;
            singleLine: boolean;
        }> & Omit<{
            reverse: boolean;
            flat: boolean;
            style: vue.StyleValue;
            active: boolean;
            error: boolean;
            disabled: boolean;
            focused: boolean;
            variant: "underlined" | "filled" | "outlined" | "plain" | "solo" | "solo-inverted" | "solo-filled";
            tile: boolean;
            clearIcon: IconValue;
            clearable: boolean;
            dirty: boolean;
            persistentClear: boolean;
            singleLine: boolean;
            class?: any;
            id?: string | undefined;
            label?: string | undefined;
            theme?: string | undefined;
            color?: string | undefined;
            loading?: string | boolean | undefined;
            'onUpdate:focused'?: (((args_0: boolean) => void) & ((focused: boolean) => any)) | undefined;
            rounded?: string | number | boolean | undefined;
            baseColor?: string | undefined;
            bgColor?: string | undefined;
            appendInnerIcon?: IconValue | undefined;
            prependInnerIcon?: IconValue | undefined;
            'onClick:clear'?: ((args_0: MouseEvent) => void) | undefined;
            'onClick:appendInner'?: ((args_0: MouseEvent) => void) | undefined;
            'onClick:prependInner'?: ((args_0: MouseEvent) => void) | undefined;
            centerAffix?: boolean | undefined;
        } & vue.VNodeProps & vue.AllowedComponentProps & vue.ComponentCustomProps & {
            reverse: boolean;
            flat: boolean;
            style: vue.StyleValue;
            active: boolean;
            error: boolean;
            disabled: boolean;
            focused: boolean;
            variant: "underlined" | "filled" | "outlined" | "plain" | "solo" | "solo-inverted" | "solo-filled";
            tile: boolean;
            clearIcon: IconValue;
            clearable: boolean;
            dirty: boolean;
            persistentClear: boolean;
            singleLine: boolean;
        } & {
            class?: any;
            id?: string | undefined;
            label?: string | undefined;
            theme?: string | undefined;
            color?: string | undefined;
            loading?: string | boolean | undefined;
            'onUpdate:focused'?: ((args_0: boolean) => void) | undefined;
            rounded?: string | number | boolean | undefined;
            baseColor?: string | undefined;
            bgColor?: string | undefined;
            appendInnerIcon?: IconValue | undefined;
            prependInnerIcon?: IconValue | undefined;
            'onClick:clear'?: ((args_0: MouseEvent) => void) | undefined;
            'onClick:appendInner'?: ((args_0: MouseEvent) => void) | undefined;
            'onClick:prependInner'?: ((args_0: MouseEvent) => void) | undefined;
            centerAffix?: boolean | undefined;
        } & {
            "onUpdate:focused"?: ((focused: boolean) => any) | undefined;
        }, "reverse" | "flat" | "style" | "active" | "error" | "disabled" | "focused" | "rounded" | "variant" | "tile" | "clearIcon" | "centerAffix" | "clearable" | "dirty" | "persistentClear" | "singleLine">;
        $attrs: {
            [x: string]: unknown;
        };
        $refs: {
            [x: string]: unknown;
        };
        $slots: Readonly<{
            clear?: ((arg: DefaultInputSlot & {
                props: Record<string, any>;
            }) => vue.VNode<vue.RendererNode, vue.RendererElement, {
                [key: string]: any;
            }>[]) | undefined;
            'prepend-inner'?: ((arg: DefaultInputSlot) => vue.VNode<vue.RendererNode, vue.RendererElement, {
                [key: string]: any;
            }>[]) | undefined;
            'append-inner'?: ((arg: DefaultInputSlot) => vue.VNode<vue.RendererNode, vue.RendererElement, {
                [key: string]: any;
            }>[]) | undefined;
            label?: ((arg: DefaultInputSlot & {
                label: string | undefined;
                props: Record<string, any>;
            }) => vue.VNode<vue.RendererNode, vue.RendererElement, {
                [key: string]: any;
            }>[]) | undefined;
            loader?: ((arg: LoaderSlotProps) => vue.VNode<vue.RendererNode, vue.RendererElement, {
                [key: string]: any;
            }>[]) | undefined;
            default?: ((arg: VFieldSlot) => vue.VNode<vue.RendererNode, vue.RendererElement, {
                [key: string]: any;
            }>[]) | undefined;
        }>;
        $root: vue.ComponentPublicInstance<{}, {}, {}, {}, {}, {}, {}, {}, false, vue.ComponentOptionsBase<any, any, any, any, any, any, any, any, any, {}, {}, string, {}>, {}, {}> | null;
        $parent: vue.ComponentPublicInstance<{}, {}, {}, {}, {}, {}, {}, {}, false, vue.ComponentOptionsBase<any, any, any, any, any, any, any, any, any, {}, {}, string, {}>, {}, {}> | null;
        $emit: (event: "update:focused", focused: boolean) => void;
        $el: any;
        $options: vue.ComponentOptionsBase<{
            reverse: boolean;
            flat: boolean;
            style: vue.StyleValue;
            active: boolean;
            error: boolean;
            disabled: boolean;
            focused: boolean;
            variant: "underlined" | "filled" | "outlined" | "plain" | "solo" | "solo-inverted" | "solo-filled";
            tile: boolean;
            clearIcon: IconValue;
            clearable: boolean;
            dirty: boolean;
            persistentClear: boolean;
            singleLine: boolean;
        } & {
            class?: any;
            id?: string | undefined;
            label?: string | undefined;
            theme?: string | undefined;
            color?: string | undefined;
            loading?: string | boolean | undefined;
            'onUpdate:focused'?: ((args_0: boolean) => void) | undefined;
            rounded?: string | number | boolean | undefined;
            baseColor?: string | undefined;
            bgColor?: string | undefined;
            appendInnerIcon?: IconValue | undefined;
            prependInnerIcon?: IconValue | undefined;
            'onClick:clear'?: ((args_0: MouseEvent) => void) | undefined;
            'onClick:appendInner'?: ((args_0: MouseEvent) => void) | undefined;
            'onClick:prependInner'?: ((args_0: MouseEvent) => void) | undefined;
            centerAffix?: boolean | undefined;
        } & {
            "onUpdate:focused"?: ((focused: boolean) => any) | undefined;
        }, {
            controlRef: vue.Ref<HTMLElement | undefined>;
        }, unknown, {}, {}, vue.ComponentOptionsMixin, vue.ComponentOptionsMixin, Omit<{
            'update:focused': (focused: boolean) => true;
            'update:modelValue': (value: any) => true;
        }, "v-slot:default" | "$children" | "v-slots" | "modelValue" | "update:modelValue" | "v-slot:loader" | "v-slot:label" | "v-slot:clear" | "v-slot:prepend-inner" | "v-slot:append-inner">, string, {
            reverse: boolean;
            flat: boolean;
            style: vue.StyleValue;
            active: boolean;
            error: boolean;
            disabled: boolean;
            focused: boolean;
            rounded: string | number | boolean;
            variant: "underlined" | "filled" | "outlined" | "plain" | "solo" | "solo-inverted" | "solo-filled";
            tile: boolean;
            clearIcon: IconValue;
            centerAffix: boolean;
            clearable: boolean;
            dirty: boolean;
            persistentClear: boolean;
            singleLine: boolean;
        }, {}, string, vue.SlotsType<Partial<{
            clear: (arg: DefaultInputSlot & {
                props: Record<string, any>;
            }) => vue.VNode<vue.RendererNode, vue.RendererElement, {
                [key: string]: any;
            }>[];
            'prepend-inner': (arg: DefaultInputSlot) => vue.VNode<vue.RendererNode, vue.RendererElement, {
                [key: string]: any;
            }>[];
            'append-inner': (arg: DefaultInputSlot) => vue.VNode<vue.RendererNode, vue.RendererElement, {
                [key: string]: any;
            }>[];
            label: (arg: DefaultInputSlot & {
                label: string | undefined;
                props: Record<string, any>;
            }) => vue.VNode<vue.RendererNode, vue.RendererElement, {
                [key: string]: any;
            }>[];
            loader: (arg: LoaderSlotProps) => vue.VNode<vue.RendererNode, vue.RendererElement, {
                [key: string]: any;
            }>[];
            default: (arg: VFieldSlot) => vue.VNode<vue.RendererNode, vue.RendererElement, {
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
        reverse: boolean;
        flat: boolean;
        style: vue.StyleValue;
        active: boolean;
        error: boolean;
        disabled: boolean;
        focused: boolean;
        variant: "underlined" | "filled" | "outlined" | "plain" | "solo" | "solo-inverted" | "solo-filled";
        tile: boolean;
        clearIcon: IconValue;
        clearable: boolean;
        dirty: boolean;
        persistentClear: boolean;
        singleLine: boolean;
    } & {
        class?: any;
        id?: string | undefined;
        label?: string | undefined;
        theme?: string | undefined;
        color?: string | undefined;
        loading?: string | boolean | undefined;
        'onUpdate:focused'?: ((args_0: boolean) => void) | undefined;
        rounded?: string | number | boolean | undefined;
        baseColor?: string | undefined;
        bgColor?: string | undefined;
        appendInnerIcon?: IconValue | undefined;
        prependInnerIcon?: IconValue | undefined;
        'onClick:clear'?: ((args_0: MouseEvent) => void) | undefined;
        'onClick:appendInner'?: ((args_0: MouseEvent) => void) | undefined;
        'onClick:prependInner'?: ((args_0: MouseEvent) => void) | undefined;
        centerAffix?: boolean | undefined;
    } & {
        "onUpdate:focused"?: ((focused: boolean) => any) | undefined;
    }, "controlRef"> & vue.ShallowUnwrapRef<{
        controlRef: vue.Ref<HTMLElement | undefined>;
    }> & {} & vue.ComponentCustomProperties & {} & GenericProps<{
        modelValue?: unknown;
        'onUpdate:modelValue'?: ((value: unknown) => void) | undefined;
    }, VFieldSlots>, "class" | "id" | "label" | "theme" | "key" | "color" | "v-slot:default" | "$children" | "v-slots" | "loading" | "ref" | "ref_for" | "ref_key" | "onVnodeBeforeMount" | "onVnodeMounted" | "onVnodeBeforeUpdate" | "onVnodeUpdated" | "onVnodeBeforeUnmount" | "onVnodeUnmounted" | "onUpdate:focused" | "modelValue" | "onUpdate:modelValue" | "baseColor" | "bgColor" | "v-slot:loader" | "v-slot:label" | "appendInnerIcon" | "prependInnerIcon" | "onClick:clear" | "onClick:appendInner" | "onClick:prependInner" | "v-slot:clear" | "v-slot:prepend-inner" | "v-slot:append-inner" | ("reverse" | "flat" | "style" | "active" | "error" | "disabled" | "focused" | "rounded" | "variant" | "tile" | "clearIcon" | "centerAffix" | "clearable" | "dirty" | "persistentClear" | "singleLine")>, `$${any}`>, unknown, {}, {}, vue.ComponentOptionsMixin, vue.ComponentOptionsMixin, {
        'click:control': (e: MouseEvent) => true;
        'mousedown:control': (e: MouseEvent) => true;
        'update:focused': (focused: boolean) => true;
        'update:modelValue': (val: string) => true;
    }, vue.VNodeProps & vue.AllowedComponentProps & vue.ComponentCustomProps & {
        reverse: boolean;
        flat: boolean;
        style: vue.StyleValue;
        type: string;
        active: boolean;
        error: boolean;
        disabled: boolean;
        messages: string | readonly string[];
        focused: boolean;
        errorMessages: string | readonly string[] | null;
        maxErrors: string | number;
        readonly: boolean | null;
        rules: readonly ValidationRule[];
        variant: "underlined" | "filled" | "outlined" | "plain" | "solo" | "solo-inverted" | "solo-filled";
        tile: boolean;
        density: Density;
        direction: "horizontal" | "vertical";
        clearIcon: IconValue;
        hideSpinButtons: boolean;
        persistentHint: boolean;
        autofocus: boolean;
        clearable: boolean;
        dirty: boolean;
        persistentClear: boolean;
        singleLine: boolean;
        persistentPlaceholder: boolean;
        persistentCounter: boolean;
    } & {
        class?: any;
        id?: string | undefined;
        label?: string | undefined;
        width?: string | number | undefined;
        theme?: string | undefined;
        color?: string | undefined;
        name?: string | undefined;
        prefix?: string | undefined;
        loading?: string | boolean | undefined;
        placeholder?: string | undefined;
        counter?: string | number | boolean | undefined;
        'onUpdate:focused'?: ((args_0: boolean) => void) | undefined;
        modelValue?: any;
        validateOn?: ("input" | "blur" | "submit") | "input lazy" | "blur lazy" | "submit lazy" | "lazy input" | "lazy blur" | "lazy submit" | "lazy" | undefined;
        validationValue?: any;
        rounded?: string | number | boolean | undefined;
        maxWidth?: string | number | undefined;
        minWidth?: string | number | undefined;
        role?: string | undefined;
        baseColor?: string | undefined;
        bgColor?: string | undefined;
        prependIcon?: IconValue | undefined;
        appendIcon?: IconValue | undefined;
        appendInnerIcon?: IconValue | undefined;
        prependInnerIcon?: IconValue | undefined;
        'onClick:clear'?: ((args_0: MouseEvent) => void) | undefined;
        'onClick:prepend'?: ((args_0: MouseEvent) => void) | undefined;
        'onClick:append'?: ((args_0: MouseEvent) => void) | undefined;
        'onClick:appendInner'?: ((args_0: MouseEvent) => void) | undefined;
        'onClick:prependInner'?: ((args_0: MouseEvent) => void) | undefined;
        centerAffix?: boolean | undefined;
        hint?: string | undefined;
        hideDetails?: boolean | "auto" | undefined;
        suffix?: string | undefined;
        counterValue?: number | ((value: any) => number) | undefined;
        modelModifiers?: Record<string, boolean> | undefined;
    } & {
        $children?: vue.VNodeChild | (() => vue.VNodeChild) | {
            clear?: ((arg: DefaultInputSlot & {
                props: Record<string, any>;
            }) => vue.VNodeChild) | undefined;
            details?: ((arg: VInputSlot) => vue.VNodeChild) | undefined;
            label?: ((arg: DefaultInputSlot & {
                label: string | undefined;
                props: Record<string, any>;
            }) => vue.VNodeChild) | undefined;
            message?: ((arg: VMessageSlot) => vue.VNodeChild) | undefined;
            prepend?: ((arg: VInputSlot) => vue.VNodeChild) | undefined;
            append?: ((arg: VInputSlot) => vue.VNodeChild) | undefined;
            loader?: ((arg: LoaderSlotProps) => vue.VNodeChild) | undefined;
            'prepend-inner'?: ((arg: DefaultInputSlot) => vue.VNodeChild) | undefined;
            'append-inner'?: ((arg: DefaultInputSlot) => vue.VNodeChild) | undefined;
            default?: (() => vue.VNodeChild) | undefined;
            counter?: ((arg: VCounterSlot) => vue.VNodeChild) | undefined;
        };
        'v-slots'?: {
            clear?: false | ((arg: DefaultInputSlot & {
                props: Record<string, any>;
            }) => vue.VNodeChild) | undefined;
            details?: false | ((arg: VInputSlot) => vue.VNodeChild) | undefined;
            label?: false | ((arg: DefaultInputSlot & {
                label: string | undefined;
                props: Record<string, any>;
            }) => vue.VNodeChild) | undefined;
            message?: false | ((arg: VMessageSlot) => vue.VNodeChild) | undefined;
            prepend?: false | ((arg: VInputSlot) => vue.VNodeChild) | undefined;
            append?: false | ((arg: VInputSlot) => vue.VNodeChild) | undefined;
            loader?: false | ((arg: LoaderSlotProps) => vue.VNodeChild) | undefined;
            'prepend-inner'?: false | ((arg: DefaultInputSlot) => vue.VNodeChild) | undefined;
            'append-inner'?: false | ((arg: DefaultInputSlot) => vue.VNodeChild) | undefined;
            default?: false | (() => vue.VNodeChild) | undefined;
            counter?: false | ((arg: VCounterSlot) => vue.VNodeChild) | undefined;
        } | undefined;
    } & {
        "v-slot:clear"?: false | ((arg: DefaultInputSlot & {
            props: Record<string, any>;
        }) => vue.VNodeChild) | undefined;
        "v-slot:details"?: false | ((arg: VInputSlot) => vue.VNodeChild) | undefined;
        "v-slot:label"?: false | ((arg: DefaultInputSlot & {
            label: string | undefined;
            props: Record<string, any>;
        }) => vue.VNodeChild) | undefined;
        "v-slot:message"?: false | ((arg: VMessageSlot) => vue.VNodeChild) | undefined;
        "v-slot:prepend"?: false | ((arg: VInputSlot) => vue.VNodeChild) | undefined;
        "v-slot:append"?: false | ((arg: VInputSlot) => vue.VNodeChild) | undefined;
        "v-slot:loader"?: false | ((arg: LoaderSlotProps) => vue.VNodeChild) | undefined;
        "v-slot:prepend-inner"?: false | ((arg: DefaultInputSlot) => vue.VNodeChild) | undefined;
        "v-slot:append-inner"?: false | ((arg: DefaultInputSlot) => vue.VNodeChild) | undefined;
        "v-slot:default"?: false | (() => vue.VNodeChild) | undefined;
        "v-slot:counter"?: false | ((arg: VCounterSlot) => vue.VNodeChild) | undefined;
    } & {
        "onUpdate:focused"?: ((focused: boolean) => any) | undefined;
        "onUpdate:modelValue"?: ((val: string) => any) | undefined;
        "onClick:control"?: ((e: MouseEvent) => any) | undefined;
        "onMousedown:control"?: ((e: MouseEvent) => any) | undefined;
    }, {
        reverse: boolean;
        flat: boolean;
        style: vue.StyleValue;
        type: string;
        active: boolean;
        error: boolean;
        disabled: boolean;
        messages: string | readonly string[];
        focused: boolean;
        errorMessages: string | readonly string[] | null;
        maxErrors: string | number;
        readonly: boolean | null;
        rules: readonly ValidationRule[];
        rounded: string | number | boolean;
        variant: "underlined" | "filled" | "outlined" | "plain" | "solo" | "solo-inverted" | "solo-filled";
        tile: boolean;
        density: Density;
        direction: "horizontal" | "vertical";
        clearIcon: IconValue;
        centerAffix: boolean;
        hideSpinButtons: boolean;
        persistentHint: boolean;
        autofocus: boolean;
        clearable: boolean;
        dirty: boolean;
        persistentClear: boolean;
        singleLine: boolean;
        persistentPlaceholder: boolean;
        persistentCounter: boolean;
    }, true, {}, vue.SlotsType<Partial<{
        clear: (arg: DefaultInputSlot & {
            props: Record<string, any>;
        }) => vue.VNode<vue.RendererNode, vue.RendererElement, {
            [key: string]: any;
        }>[];
        details: (arg: VInputSlot) => vue.VNode<vue.RendererNode, vue.RendererElement, {
            [key: string]: any;
        }>[];
        label: (arg: DefaultInputSlot & {
            label: string | undefined;
            props: Record<string, any>;
        }) => vue.VNode<vue.RendererNode, vue.RendererElement, {
            [key: string]: any;
        }>[];
        message: (arg: VMessageSlot) => vue.VNode<vue.RendererNode, vue.RendererElement, {
            [key: string]: any;
        }>[];
        prepend: (arg: VInputSlot) => vue.VNode<vue.RendererNode, vue.RendererElement, {
            [key: string]: any;
        }>[];
        append: (arg: VInputSlot) => vue.VNode<vue.RendererNode, vue.RendererElement, {
            [key: string]: any;
        }>[];
        loader: (arg: LoaderSlotProps) => vue.VNode<vue.RendererNode, vue.RendererElement, {
            [key: string]: any;
        }>[];
        'prepend-inner': (arg: DefaultInputSlot) => vue.VNode<vue.RendererNode, vue.RendererElement, {
            [key: string]: any;
        }>[];
        'append-inner': (arg: DefaultInputSlot) => vue.VNode<vue.RendererNode, vue.RendererElement, {
            [key: string]: any;
        }>[];
        default: () => vue.VNode<vue.RendererNode, vue.RendererElement, {
            [key: string]: any;
        }>[];
        counter: (arg: VCounterSlot) => vue.VNode<vue.RendererNode, vue.RendererElement, {
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
        reverse: boolean;
        flat: boolean;
        style: vue.StyleValue;
        type: string;
        active: boolean;
        error: boolean;
        disabled: boolean;
        messages: string | readonly string[];
        focused: boolean;
        errorMessages: string | readonly string[] | null;
        maxErrors: string | number;
        readonly: boolean | null;
        rules: readonly ValidationRule[];
        variant: "underlined" | "filled" | "outlined" | "plain" | "solo" | "solo-inverted" | "solo-filled";
        tile: boolean;
        density: Density;
        direction: "horizontal" | "vertical";
        clearIcon: IconValue;
        hideSpinButtons: boolean;
        persistentHint: boolean;
        autofocus: boolean;
        clearable: boolean;
        dirty: boolean;
        persistentClear: boolean;
        singleLine: boolean;
        persistentPlaceholder: boolean;
        persistentCounter: boolean;
    } & {
        class?: any;
        id?: string | undefined;
        label?: string | undefined;
        width?: string | number | undefined;
        theme?: string | undefined;
        color?: string | undefined;
        name?: string | undefined;
        prefix?: string | undefined;
        loading?: string | boolean | undefined;
        placeholder?: string | undefined;
        counter?: string | number | boolean | undefined;
        'onUpdate:focused'?: ((args_0: boolean) => void) | undefined;
        modelValue?: any;
        validateOn?: ("input" | "blur" | "submit") | "input lazy" | "blur lazy" | "submit lazy" | "lazy input" | "lazy blur" | "lazy submit" | "lazy" | undefined;
        validationValue?: any;
        rounded?: string | number | boolean | undefined;
        maxWidth?: string | number | undefined;
        minWidth?: string | number | undefined;
        role?: string | undefined;
        baseColor?: string | undefined;
        bgColor?: string | undefined;
        prependIcon?: IconValue | undefined;
        appendIcon?: IconValue | undefined;
        appendInnerIcon?: IconValue | undefined;
        prependInnerIcon?: IconValue | undefined;
        'onClick:clear'?: ((args_0: MouseEvent) => void) | undefined;
        'onClick:prepend'?: ((args_0: MouseEvent) => void) | undefined;
        'onClick:append'?: ((args_0: MouseEvent) => void) | undefined;
        'onClick:appendInner'?: ((args_0: MouseEvent) => void) | undefined;
        'onClick:prependInner'?: ((args_0: MouseEvent) => void) | undefined;
        centerAffix?: boolean | undefined;
        hint?: string | undefined;
        hideDetails?: boolean | "auto" | undefined;
        suffix?: string | undefined;
        counterValue?: number | ((value: any) => number) | undefined;
        modelModifiers?: Record<string, boolean> | undefined;
    } & {
        $children?: vue.VNodeChild | (() => vue.VNodeChild) | {
            clear?: ((arg: DefaultInputSlot & {
                props: Record<string, any>;
            }) => vue.VNodeChild) | undefined;
            details?: ((arg: VInputSlot) => vue.VNodeChild) | undefined;
            label?: ((arg: DefaultInputSlot & {
                label: string | undefined;
                props: Record<string, any>;
            }) => vue.VNodeChild) | undefined;
            message?: ((arg: VMessageSlot) => vue.VNodeChild) | undefined;
            prepend?: ((arg: VInputSlot) => vue.VNodeChild) | undefined;
            append?: ((arg: VInputSlot) => vue.VNodeChild) | undefined;
            loader?: ((arg: LoaderSlotProps) => vue.VNodeChild) | undefined;
            'prepend-inner'?: ((arg: DefaultInputSlot) => vue.VNodeChild) | undefined;
            'append-inner'?: ((arg: DefaultInputSlot) => vue.VNodeChild) | undefined;
            default?: (() => vue.VNodeChild) | undefined;
            counter?: ((arg: VCounterSlot) => vue.VNodeChild) | undefined;
        };
        'v-slots'?: {
            clear?: false | ((arg: DefaultInputSlot & {
                props: Record<string, any>;
            }) => vue.VNodeChild) | undefined;
            details?: false | ((arg: VInputSlot) => vue.VNodeChild) | undefined;
            label?: false | ((arg: DefaultInputSlot & {
                label: string | undefined;
                props: Record<string, any>;
            }) => vue.VNodeChild) | undefined;
            message?: false | ((arg: VMessageSlot) => vue.VNodeChild) | undefined;
            prepend?: false | ((arg: VInputSlot) => vue.VNodeChild) | undefined;
            append?: false | ((arg: VInputSlot) => vue.VNodeChild) | undefined;
            loader?: false | ((arg: LoaderSlotProps) => vue.VNodeChild) | undefined;
            'prepend-inner'?: false | ((arg: DefaultInputSlot) => vue.VNodeChild) | undefined;
            'append-inner'?: false | ((arg: DefaultInputSlot) => vue.VNodeChild) | undefined;
            default?: false | (() => vue.VNodeChild) | undefined;
            counter?: false | ((arg: VCounterSlot) => vue.VNodeChild) | undefined;
        } | undefined;
    } & {
        "v-slot:clear"?: false | ((arg: DefaultInputSlot & {
            props: Record<string, any>;
        }) => vue.VNodeChild) | undefined;
        "v-slot:details"?: false | ((arg: VInputSlot) => vue.VNodeChild) | undefined;
        "v-slot:label"?: false | ((arg: DefaultInputSlot & {
            label: string | undefined;
            props: Record<string, any>;
        }) => vue.VNodeChild) | undefined;
        "v-slot:message"?: false | ((arg: VMessageSlot) => vue.VNodeChild) | undefined;
        "v-slot:prepend"?: false | ((arg: VInputSlot) => vue.VNodeChild) | undefined;
        "v-slot:append"?: false | ((arg: VInputSlot) => vue.VNodeChild) | undefined;
        "v-slot:loader"?: false | ((arg: LoaderSlotProps) => vue.VNodeChild) | undefined;
        "v-slot:prepend-inner"?: false | ((arg: DefaultInputSlot) => vue.VNodeChild) | undefined;
        "v-slot:append-inner"?: false | ((arg: DefaultInputSlot) => vue.VNodeChild) | undefined;
        "v-slot:default"?: false | (() => vue.VNodeChild) | undefined;
        "v-slot:counter"?: false | ((arg: VCounterSlot) => vue.VNodeChild) | undefined;
    } & {
        "onUpdate:focused"?: ((focused: boolean) => any) | undefined;
        "onUpdate:modelValue"?: ((val: string) => any) | undefined;
        "onClick:control"?: ((e: MouseEvent) => any) | undefined;
        "onMousedown:control"?: ((e: MouseEvent) => any) | undefined;
    }, HTMLInputElement & Omit<Omit<{
        $: vue.ComponentInternalInstance;
        $data: {};
        $props: Partial<{
            style: vue.StyleValue;
            error: boolean;
            disabled: boolean | null;
            messages: string | readonly string[];
            focused: boolean;
            errorMessages: string | readonly string[] | null;
            maxErrors: string | number;
            readonly: boolean | null;
            rules: readonly ValidationRule[];
            density: Density;
            direction: "horizontal" | "vertical";
            centerAffix: boolean;
            hideSpinButtons: boolean;
            persistentHint: boolean;
        }> & Omit<{
            style: vue.StyleValue;
            error: boolean;
            disabled: boolean | null;
            messages: string | readonly string[];
            focused: boolean;
            errorMessages: string | readonly string[] | null;
            maxErrors: string | number;
            readonly: boolean | null;
            rules: readonly ValidationRule[];
            density: Density;
            direction: "horizontal" | "vertical";
            centerAffix: boolean;
            hideSpinButtons: boolean;
            persistentHint: boolean;
            class?: any;
            id?: string | undefined;
            label?: string | undefined;
            width?: string | number | undefined;
            theme?: string | undefined;
            name?: string | undefined;
            'onUpdate:focused'?: ((args_0: boolean) => void) | undefined;
            validateOn?: ("input" | "blur" | "submit") | "input lazy" | "blur lazy" | "submit lazy" | "lazy input" | "lazy blur" | "lazy submit" | "lazy" | undefined;
            validationValue?: any;
            maxWidth?: string | number | undefined;
            minWidth?: string | number | undefined;
            prependIcon?: IconValue | undefined;
            appendIcon?: IconValue | undefined;
            'onClick:prepend'?: ((args_0: MouseEvent) => void) | undefined;
            'onClick:append'?: ((args_0: MouseEvent) => void) | undefined;
            hint?: string | undefined;
            hideDetails?: boolean | "auto" | undefined;
        } & vue.VNodeProps & vue.AllowedComponentProps & vue.ComponentCustomProps & {
            style: vue.StyleValue;
            error: boolean;
            disabled: boolean | null;
            messages: string | readonly string[];
            focused: boolean;
            errorMessages: string | readonly string[] | null;
            maxErrors: string | number;
            readonly: boolean | null;
            rules: readonly ValidationRule[];
            density: Density;
            direction: "horizontal" | "vertical";
            centerAffix: boolean;
            hideSpinButtons: boolean;
            persistentHint: boolean;
        } & {
            class?: any;
            id?: string | undefined;
            label?: string | undefined;
            width?: string | number | undefined;
            theme?: string | undefined;
            name?: string | undefined;
            'onUpdate:focused'?: ((args_0: boolean) => void) | undefined;
            validateOn?: ("input" | "blur" | "submit") | "input lazy" | "blur lazy" | "submit lazy" | "lazy input" | "lazy blur" | "lazy submit" | "lazy" | undefined;
            validationValue?: any;
            maxWidth?: string | number | undefined;
            minWidth?: string | number | undefined;
            prependIcon?: IconValue | undefined;
            appendIcon?: IconValue | undefined;
            'onClick:prepend'?: ((args_0: MouseEvent) => void) | undefined;
            'onClick:append'?: ((args_0: MouseEvent) => void) | undefined;
            hint?: string | undefined;
            hideDetails?: boolean | "auto" | undefined;
        } & {}, "style" | "error" | "disabled" | "messages" | "focused" | "errorMessages" | "maxErrors" | "readonly" | "rules" | "density" | "direction" | "centerAffix" | "hideSpinButtons" | "persistentHint">;
        $attrs: {
            [x: string]: unknown;
        };
        $refs: {
            [x: string]: unknown;
        };
        $slots: Readonly<{
            default?: ((arg: VInputSlot) => vue.VNode<vue.RendererNode, vue.RendererElement, {
                [key: string]: any;
            }>[]) | undefined;
            prepend?: ((arg: VInputSlot) => vue.VNode<vue.RendererNode, vue.RendererElement, {
                [key: string]: any;
            }>[]) | undefined;
            append?: ((arg: VInputSlot) => vue.VNode<vue.RendererNode, vue.RendererElement, {
                [key: string]: any;
            }>[]) | undefined;
            details?: ((arg: VInputSlot) => vue.VNode<vue.RendererNode, vue.RendererElement, {
                [key: string]: any;
            }>[]) | undefined;
            message?: ((arg: VMessageSlot) => vue.VNode<vue.RendererNode, vue.RendererElement, {
                [key: string]: any;
            }>[]) | undefined;
        }>;
        $root: vue.ComponentPublicInstance<{}, {}, {}, {}, {}, {}, {}, {}, false, vue.ComponentOptionsBase<any, any, any, any, any, any, any, any, any, {}, {}, string, {}>, {}, {}> | null;
        $parent: vue.ComponentPublicInstance<{}, {}, {}, {}, {}, {}, {}, {}, false, vue.ComponentOptionsBase<any, any, any, any, any, any, any, any, any, {}, {}, string, {}>, {}, {}> | null;
        $emit: (event: string, ...args: any[]) => void;
        $el: any;
        $options: vue.ComponentOptionsBase<{
            style: vue.StyleValue;
            error: boolean;
            disabled: boolean | null;
            messages: string | readonly string[];
            focused: boolean;
            errorMessages: string | readonly string[] | null;
            maxErrors: string | number;
            readonly: boolean | null;
            rules: readonly ValidationRule[];
            density: Density;
            direction: "horizontal" | "vertical";
            centerAffix: boolean;
            hideSpinButtons: boolean;
            persistentHint: boolean;
        } & {
            class?: any;
            id?: string | undefined;
            label?: string | undefined;
            width?: string | number | undefined;
            theme?: string | undefined;
            name?: string | undefined;
            'onUpdate:focused'?: ((args_0: boolean) => void) | undefined;
            validateOn?: ("input" | "blur" | "submit") | "input lazy" | "blur lazy" | "submit lazy" | "lazy input" | "lazy blur" | "lazy submit" | "lazy" | undefined;
            validationValue?: any;
            maxWidth?: string | number | undefined;
            minWidth?: string | number | undefined;
            prependIcon?: IconValue | undefined;
            appendIcon?: IconValue | undefined;
            'onClick:prepend'?: ((args_0: MouseEvent) => void) | undefined;
            'onClick:append'?: ((args_0: MouseEvent) => void) | undefined;
            hint?: string | undefined;
            hideDetails?: boolean | "auto" | undefined;
        } & {}, {
            reset: () => Promise<void>;
            resetValidation: () => Promise<void>;
            validate: (silent?: boolean) => Promise<string[]>;
            isValid: vue.ComputedRef<boolean | null>;
            errorMessages: vue.ComputedRef<string[]>;
        }, unknown, {}, {}, vue.ComponentOptionsMixin, vue.ComponentOptionsMixin, Omit<{
            'update:modelValue': (value: any) => true;
        }, "v-slot:default" | "$children" | "v-slots" | "modelValue" | "v-slot:prepend" | "v-slot:append" | "update:modelValue" | "v-slot:message" | "v-slot:details">, string, {
            style: vue.StyleValue;
            error: boolean;
            disabled: boolean | null;
            messages: string | readonly string[];
            focused: boolean;
            errorMessages: string | readonly string[] | null;
            maxErrors: string | number;
            readonly: boolean | null;
            rules: readonly ValidationRule[];
            density: Density;
            direction: "horizontal" | "vertical";
            centerAffix: boolean;
            hideSpinButtons: boolean;
            persistentHint: boolean;
        }, {}, string, vue.SlotsType<Partial<{
            default: (arg: VInputSlot) => vue.VNode<vue.RendererNode, vue.RendererElement, {
                [key: string]: any;
            }>[];
            prepend: (arg: VInputSlot) => vue.VNode<vue.RendererNode, vue.RendererElement, {
                [key: string]: any;
            }>[];
            append: (arg: VInputSlot) => vue.VNode<vue.RendererNode, vue.RendererElement, {
                [key: string]: any;
            }>[];
            details: (arg: VInputSlot) => vue.VNode<vue.RendererNode, vue.RendererElement, {
                [key: string]: any;
            }>[];
            message: (arg: VMessageSlot) => vue.VNode<vue.RendererNode, vue.RendererElement, {
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
        error: boolean;
        disabled: boolean | null;
        messages: string | readonly string[];
        focused: boolean;
        errorMessages: string | readonly string[] | null;
        maxErrors: string | number;
        readonly: boolean | null;
        rules: readonly ValidationRule[];
        density: Density;
        direction: "horizontal" | "vertical";
        centerAffix: boolean;
        hideSpinButtons: boolean;
        persistentHint: boolean;
    } & {
        class?: any;
        id?: string | undefined;
        label?: string | undefined;
        width?: string | number | undefined;
        theme?: string | undefined;
        name?: string | undefined;
        'onUpdate:focused'?: ((args_0: boolean) => void) | undefined;
        validateOn?: ("input" | "blur" | "submit") | "input lazy" | "blur lazy" | "submit lazy" | "lazy input" | "lazy blur" | "lazy submit" | "lazy" | undefined;
        validationValue?: any;
        maxWidth?: string | number | undefined;
        minWidth?: string | number | undefined;
        prependIcon?: IconValue | undefined;
        appendIcon?: IconValue | undefined;
        'onClick:prepend'?: ((args_0: MouseEvent) => void) | undefined;
        'onClick:append'?: ((args_0: MouseEvent) => void) | undefined;
        hint?: string | undefined;
        hideDetails?: boolean | "auto" | undefined;
    } & {}, "reset" | "isValid" | "errorMessages" | "validate" | "resetValidation"> & vue.ShallowUnwrapRef<{
        reset: () => Promise<void>;
        resetValidation: () => Promise<void>;
        validate: (silent?: boolean) => Promise<string[]>;
        isValid: vue.ComputedRef<boolean | null>;
        errorMessages: vue.ComputedRef<string[]>;
    }> & {} & vue.ComponentCustomProperties & {} & GenericProps<{
        modelValue?: unknown;
        'onUpdate:modelValue'?: ((value: unknown) => void) | undefined;
    }, VInputSlots>, "class" | "id" | "label" | "width" | "theme" | "key" | "name" | "v-slot:default" | "$children" | "v-slots" | "ref" | "ref_for" | "ref_key" | "onVnodeBeforeMount" | "onVnodeMounted" | "onVnodeBeforeUpdate" | "onVnodeUpdated" | "onVnodeBeforeUnmount" | "onVnodeUnmounted" | "onUpdate:focused" | "modelValue" | "validateOn" | "validationValue" | "onUpdate:modelValue" | "maxWidth" | "minWidth" | "v-slot:prepend" | "v-slot:append" | "prependIcon" | "appendIcon" | "onClick:prepend" | "onClick:append" | "v-slot:message" | "hint" | "hideDetails" | "v-slot:details" | ("style" | "error" | "disabled" | "messages" | "focused" | "errorMessages" | "maxErrors" | "readonly" | "rules" | "density" | "direction" | "centerAffix" | "hideSpinButtons" | "persistentHint")>, `$${any}`> & Omit<Omit<{
        $: vue.ComponentInternalInstance;
        $data: {};
        $props: Partial<{
            reverse: boolean;
            flat: boolean;
            style: vue.StyleValue;
            active: boolean;
            error: boolean;
            disabled: boolean;
            focused: boolean;
            rounded: string | number | boolean;
            variant: "underlined" | "filled" | "outlined" | "plain" | "solo" | "solo-inverted" | "solo-filled";
            tile: boolean;
            clearIcon: IconValue;
            centerAffix: boolean;
            clearable: boolean;
            dirty: boolean;
            persistentClear: boolean;
            singleLine: boolean;
        }> & Omit<{
            reverse: boolean;
            flat: boolean;
            style: vue.StyleValue;
            active: boolean;
            error: boolean;
            disabled: boolean;
            focused: boolean;
            variant: "underlined" | "filled" | "outlined" | "plain" | "solo" | "solo-inverted" | "solo-filled";
            tile: boolean;
            clearIcon: IconValue;
            clearable: boolean;
            dirty: boolean;
            persistentClear: boolean;
            singleLine: boolean;
            class?: any;
            id?: string | undefined;
            label?: string | undefined;
            theme?: string | undefined;
            color?: string | undefined;
            loading?: string | boolean | undefined;
            'onUpdate:focused'?: (((args_0: boolean) => void) & ((focused: boolean) => any)) | undefined;
            rounded?: string | number | boolean | undefined;
            baseColor?: string | undefined;
            bgColor?: string | undefined;
            appendInnerIcon?: IconValue | undefined;
            prependInnerIcon?: IconValue | undefined;
            'onClick:clear'?: ((args_0: MouseEvent) => void) | undefined;
            'onClick:appendInner'?: ((args_0: MouseEvent) => void) | undefined;
            'onClick:prependInner'?: ((args_0: MouseEvent) => void) | undefined;
            centerAffix?: boolean | undefined;
        } & vue.VNodeProps & vue.AllowedComponentProps & vue.ComponentCustomProps & {
            reverse: boolean;
            flat: boolean;
            style: vue.StyleValue;
            active: boolean;
            error: boolean;
            disabled: boolean;
            focused: boolean;
            variant: "underlined" | "filled" | "outlined" | "plain" | "solo" | "solo-inverted" | "solo-filled";
            tile: boolean;
            clearIcon: IconValue;
            clearable: boolean;
            dirty: boolean;
            persistentClear: boolean;
            singleLine: boolean;
        } & {
            class?: any;
            id?: string | undefined;
            label?: string | undefined;
            theme?: string | undefined;
            color?: string | undefined;
            loading?: string | boolean | undefined;
            'onUpdate:focused'?: ((args_0: boolean) => void) | undefined;
            rounded?: string | number | boolean | undefined;
            baseColor?: string | undefined;
            bgColor?: string | undefined;
            appendInnerIcon?: IconValue | undefined;
            prependInnerIcon?: IconValue | undefined;
            'onClick:clear'?: ((args_0: MouseEvent) => void) | undefined;
            'onClick:appendInner'?: ((args_0: MouseEvent) => void) | undefined;
            'onClick:prependInner'?: ((args_0: MouseEvent) => void) | undefined;
            centerAffix?: boolean | undefined;
        } & {
            "onUpdate:focused"?: ((focused: boolean) => any) | undefined;
        }, "reverse" | "flat" | "style" | "active" | "error" | "disabled" | "focused" | "rounded" | "variant" | "tile" | "clearIcon" | "centerAffix" | "clearable" | "dirty" | "persistentClear" | "singleLine">;
        $attrs: {
            [x: string]: unknown;
        };
        $refs: {
            [x: string]: unknown;
        };
        $slots: Readonly<{
            clear?: ((arg: DefaultInputSlot & {
                props: Record<string, any>;
            }) => vue.VNode<vue.RendererNode, vue.RendererElement, {
                [key: string]: any;
            }>[]) | undefined;
            'prepend-inner'?: ((arg: DefaultInputSlot) => vue.VNode<vue.RendererNode, vue.RendererElement, {
                [key: string]: any;
            }>[]) | undefined;
            'append-inner'?: ((arg: DefaultInputSlot) => vue.VNode<vue.RendererNode, vue.RendererElement, {
                [key: string]: any;
            }>[]) | undefined;
            label?: ((arg: DefaultInputSlot & {
                label: string | undefined;
                props: Record<string, any>;
            }) => vue.VNode<vue.RendererNode, vue.RendererElement, {
                [key: string]: any;
            }>[]) | undefined;
            loader?: ((arg: LoaderSlotProps) => vue.VNode<vue.RendererNode, vue.RendererElement, {
                [key: string]: any;
            }>[]) | undefined;
            default?: ((arg: VFieldSlot) => vue.VNode<vue.RendererNode, vue.RendererElement, {
                [key: string]: any;
            }>[]) | undefined;
        }>;
        $root: vue.ComponentPublicInstance<{}, {}, {}, {}, {}, {}, {}, {}, false, vue.ComponentOptionsBase<any, any, any, any, any, any, any, any, any, {}, {}, string, {}>, {}, {}> | null;
        $parent: vue.ComponentPublicInstance<{}, {}, {}, {}, {}, {}, {}, {}, false, vue.ComponentOptionsBase<any, any, any, any, any, any, any, any, any, {}, {}, string, {}>, {}, {}> | null;
        $emit: (event: "update:focused", focused: boolean) => void;
        $el: any;
        $options: vue.ComponentOptionsBase<{
            reverse: boolean;
            flat: boolean;
            style: vue.StyleValue;
            active: boolean;
            error: boolean;
            disabled: boolean;
            focused: boolean;
            variant: "underlined" | "filled" | "outlined" | "plain" | "solo" | "solo-inverted" | "solo-filled";
            tile: boolean;
            clearIcon: IconValue;
            clearable: boolean;
            dirty: boolean;
            persistentClear: boolean;
            singleLine: boolean;
        } & {
            class?: any;
            id?: string | undefined;
            label?: string | undefined;
            theme?: string | undefined;
            color?: string | undefined;
            loading?: string | boolean | undefined;
            'onUpdate:focused'?: ((args_0: boolean) => void) | undefined;
            rounded?: string | number | boolean | undefined;
            baseColor?: string | undefined;
            bgColor?: string | undefined;
            appendInnerIcon?: IconValue | undefined;
            prependInnerIcon?: IconValue | undefined;
            'onClick:clear'?: ((args_0: MouseEvent) => void) | undefined;
            'onClick:appendInner'?: ((args_0: MouseEvent) => void) | undefined;
            'onClick:prependInner'?: ((args_0: MouseEvent) => void) | undefined;
            centerAffix?: boolean | undefined;
        } & {
            "onUpdate:focused"?: ((focused: boolean) => any) | undefined;
        }, {
            controlRef: vue.Ref<HTMLElement | undefined>;
        }, unknown, {}, {}, vue.ComponentOptionsMixin, vue.ComponentOptionsMixin, Omit<{
            'update:focused': (focused: boolean) => true;
            'update:modelValue': (value: any) => true;
        }, "v-slot:default" | "$children" | "v-slots" | "modelValue" | "update:modelValue" | "v-slot:loader" | "v-slot:label" | "v-slot:clear" | "v-slot:prepend-inner" | "v-slot:append-inner">, string, {
            reverse: boolean;
            flat: boolean;
            style: vue.StyleValue;
            active: boolean;
            error: boolean;
            disabled: boolean;
            focused: boolean;
            rounded: string | number | boolean;
            variant: "underlined" | "filled" | "outlined" | "plain" | "solo" | "solo-inverted" | "solo-filled";
            tile: boolean;
            clearIcon: IconValue;
            centerAffix: boolean;
            clearable: boolean;
            dirty: boolean;
            persistentClear: boolean;
            singleLine: boolean;
        }, {}, string, vue.SlotsType<Partial<{
            clear: (arg: DefaultInputSlot & {
                props: Record<string, any>;
            }) => vue.VNode<vue.RendererNode, vue.RendererElement, {
                [key: string]: any;
            }>[];
            'prepend-inner': (arg: DefaultInputSlot) => vue.VNode<vue.RendererNode, vue.RendererElement, {
                [key: string]: any;
            }>[];
            'append-inner': (arg: DefaultInputSlot) => vue.VNode<vue.RendererNode, vue.RendererElement, {
                [key: string]: any;
            }>[];
            label: (arg: DefaultInputSlot & {
                label: string | undefined;
                props: Record<string, any>;
            }) => vue.VNode<vue.RendererNode, vue.RendererElement, {
                [key: string]: any;
            }>[];
            loader: (arg: LoaderSlotProps) => vue.VNode<vue.RendererNode, vue.RendererElement, {
                [key: string]: any;
            }>[];
            default: (arg: VFieldSlot) => vue.VNode<vue.RendererNode, vue.RendererElement, {
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
        reverse: boolean;
        flat: boolean;
        style: vue.StyleValue;
        active: boolean;
        error: boolean;
        disabled: boolean;
        focused: boolean;
        variant: "underlined" | "filled" | "outlined" | "plain" | "solo" | "solo-inverted" | "solo-filled";
        tile: boolean;
        clearIcon: IconValue;
        clearable: boolean;
        dirty: boolean;
        persistentClear: boolean;
        singleLine: boolean;
    } & {
        class?: any;
        id?: string | undefined;
        label?: string | undefined;
        theme?: string | undefined;
        color?: string | undefined;
        loading?: string | boolean | undefined;
        'onUpdate:focused'?: ((args_0: boolean) => void) | undefined;
        rounded?: string | number | boolean | undefined;
        baseColor?: string | undefined;
        bgColor?: string | undefined;
        appendInnerIcon?: IconValue | undefined;
        prependInnerIcon?: IconValue | undefined;
        'onClick:clear'?: ((args_0: MouseEvent) => void) | undefined;
        'onClick:appendInner'?: ((args_0: MouseEvent) => void) | undefined;
        'onClick:prependInner'?: ((args_0: MouseEvent) => void) | undefined;
        centerAffix?: boolean | undefined;
    } & {
        "onUpdate:focused"?: ((focused: boolean) => any) | undefined;
    }, "controlRef"> & vue.ShallowUnwrapRef<{
        controlRef: vue.Ref<HTMLElement | undefined>;
    }> & {} & vue.ComponentCustomProperties & {} & GenericProps<{
        modelValue?: unknown;
        'onUpdate:modelValue'?: ((value: unknown) => void) | undefined;
    }, VFieldSlots>, "class" | "id" | "label" | "theme" | "key" | "color" | "v-slot:default" | "$children" | "v-slots" | "loading" | "ref" | "ref_for" | "ref_key" | "onVnodeBeforeMount" | "onVnodeMounted" | "onVnodeBeforeUpdate" | "onVnodeUpdated" | "onVnodeBeforeUnmount" | "onVnodeUnmounted" | "onUpdate:focused" | "modelValue" | "onUpdate:modelValue" | "baseColor" | "bgColor" | "v-slot:loader" | "v-slot:label" | "appendInnerIcon" | "prependInnerIcon" | "onClick:clear" | "onClick:appendInner" | "onClick:prependInner" | "v-slot:clear" | "v-slot:prepend-inner" | "v-slot:append-inner" | ("reverse" | "flat" | "style" | "active" | "error" | "disabled" | "focused" | "rounded" | "variant" | "tile" | "clearIcon" | "centerAffix" | "clearable" | "dirty" | "persistentClear" | "singleLine")>, `$${any}`>, {}, {}, {}, {
        reverse: boolean;
        flat: boolean;
        style: vue.StyleValue;
        type: string;
        active: boolean;
        error: boolean;
        disabled: boolean;
        messages: string | readonly string[];
        focused: boolean;
        errorMessages: string | readonly string[] | null;
        maxErrors: string | number;
        readonly: boolean | null;
        rules: readonly ValidationRule[];
        rounded: string | number | boolean;
        variant: "underlined" | "filled" | "outlined" | "plain" | "solo" | "solo-inverted" | "solo-filled";
        tile: boolean;
        density: Density;
        direction: "horizontal" | "vertical";
        clearIcon: IconValue;
        centerAffix: boolean;
        hideSpinButtons: boolean;
        persistentHint: boolean;
        autofocus: boolean;
        clearable: boolean;
        dirty: boolean;
        persistentClear: boolean;
        singleLine: boolean;
        persistentPlaceholder: boolean;
        persistentCounter: boolean;
    }>;
    __isFragment?: undefined;
    __isTeleport?: undefined;
    __isSuspense?: undefined;
} & vue.ComponentOptionsBase<{
    reverse: boolean;
    flat: boolean;
    style: vue.StyleValue;
    type: string;
    active: boolean;
    error: boolean;
    disabled: boolean;
    messages: string | readonly string[];
    focused: boolean;
    errorMessages: string | readonly string[] | null;
    maxErrors: string | number;
    readonly: boolean | null;
    rules: readonly ValidationRule[];
    variant: "underlined" | "filled" | "outlined" | "plain" | "solo" | "solo-inverted" | "solo-filled";
    tile: boolean;
    density: Density;
    direction: "horizontal" | "vertical";
    clearIcon: IconValue;
    hideSpinButtons: boolean;
    persistentHint: boolean;
    autofocus: boolean;
    clearable: boolean;
    dirty: boolean;
    persistentClear: boolean;
    singleLine: boolean;
    persistentPlaceholder: boolean;
    persistentCounter: boolean;
} & {
    class?: any;
    id?: string | undefined;
    label?: string | undefined;
    width?: string | number | undefined;
    theme?: string | undefined;
    color?: string | undefined;
    name?: string | undefined;
    prefix?: string | undefined;
    loading?: string | boolean | undefined;
    placeholder?: string | undefined;
    counter?: string | number | boolean | undefined;
    'onUpdate:focused'?: ((args_0: boolean) => void) | undefined;
    modelValue?: any;
    validateOn?: ("input" | "blur" | "submit") | "input lazy" | "blur lazy" | "submit lazy" | "lazy input" | "lazy blur" | "lazy submit" | "lazy" | undefined;
    validationValue?: any;
    rounded?: string | number | boolean | undefined;
    maxWidth?: string | number | undefined;
    minWidth?: string | number | undefined;
    role?: string | undefined;
    baseColor?: string | undefined;
    bgColor?: string | undefined;
    prependIcon?: IconValue | undefined;
    appendIcon?: IconValue | undefined;
    appendInnerIcon?: IconValue | undefined;
    prependInnerIcon?: IconValue | undefined;
    'onClick:clear'?: ((args_0: MouseEvent) => void) | undefined;
    'onClick:prepend'?: ((args_0: MouseEvent) => void) | undefined;
    'onClick:append'?: ((args_0: MouseEvent) => void) | undefined;
    'onClick:appendInner'?: ((args_0: MouseEvent) => void) | undefined;
    'onClick:prependInner'?: ((args_0: MouseEvent) => void) | undefined;
    centerAffix?: boolean | undefined;
    hint?: string | undefined;
    hideDetails?: boolean | "auto" | undefined;
    suffix?: string | undefined;
    counterValue?: number | ((value: any) => number) | undefined;
    modelModifiers?: Record<string, boolean> | undefined;
} & {
    $children?: vue.VNodeChild | (() => vue.VNodeChild) | {
        clear?: ((arg: DefaultInputSlot & {
            props: Record<string, any>;
        }) => vue.VNodeChild) | undefined;
        details?: ((arg: VInputSlot) => vue.VNodeChild) | undefined;
        label?: ((arg: DefaultInputSlot & {
            label: string | undefined;
            props: Record<string, any>;
        }) => vue.VNodeChild) | undefined;
        message?: ((arg: VMessageSlot) => vue.VNodeChild) | undefined;
        prepend?: ((arg: VInputSlot) => vue.VNodeChild) | undefined;
        append?: ((arg: VInputSlot) => vue.VNodeChild) | undefined;
        loader?: ((arg: LoaderSlotProps) => vue.VNodeChild) | undefined;
        'prepend-inner'?: ((arg: DefaultInputSlot) => vue.VNodeChild) | undefined;
        'append-inner'?: ((arg: DefaultInputSlot) => vue.VNodeChild) | undefined;
        default?: (() => vue.VNodeChild) | undefined;
        counter?: ((arg: VCounterSlot) => vue.VNodeChild) | undefined;
    };
    'v-slots'?: {
        clear?: false | ((arg: DefaultInputSlot & {
            props: Record<string, any>;
        }) => vue.VNodeChild) | undefined;
        details?: false | ((arg: VInputSlot) => vue.VNodeChild) | undefined;
        label?: false | ((arg: DefaultInputSlot & {
            label: string | undefined;
            props: Record<string, any>;
        }) => vue.VNodeChild) | undefined;
        message?: false | ((arg: VMessageSlot) => vue.VNodeChild) | undefined;
        prepend?: false | ((arg: VInputSlot) => vue.VNodeChild) | undefined;
        append?: false | ((arg: VInputSlot) => vue.VNodeChild) | undefined;
        loader?: false | ((arg: LoaderSlotProps) => vue.VNodeChild) | undefined;
        'prepend-inner'?: false | ((arg: DefaultInputSlot) => vue.VNodeChild) | undefined;
        'append-inner'?: false | ((arg: DefaultInputSlot) => vue.VNodeChild) | undefined;
        default?: false | (() => vue.VNodeChild) | undefined;
        counter?: false | ((arg: VCounterSlot) => vue.VNodeChild) | undefined;
    } | undefined;
} & {
    "v-slot:clear"?: false | ((arg: DefaultInputSlot & {
        props: Record<string, any>;
    }) => vue.VNodeChild) | undefined;
    "v-slot:details"?: false | ((arg: VInputSlot) => vue.VNodeChild) | undefined;
    "v-slot:label"?: false | ((arg: DefaultInputSlot & {
        label: string | undefined;
        props: Record<string, any>;
    }) => vue.VNodeChild) | undefined;
    "v-slot:message"?: false | ((arg: VMessageSlot) => vue.VNodeChild) | undefined;
    "v-slot:prepend"?: false | ((arg: VInputSlot) => vue.VNodeChild) | undefined;
    "v-slot:append"?: false | ((arg: VInputSlot) => vue.VNodeChild) | undefined;
    "v-slot:loader"?: false | ((arg: LoaderSlotProps) => vue.VNodeChild) | undefined;
    "v-slot:prepend-inner"?: false | ((arg: DefaultInputSlot) => vue.VNodeChild) | undefined;
    "v-slot:append-inner"?: false | ((arg: DefaultInputSlot) => vue.VNodeChild) | undefined;
    "v-slot:default"?: false | (() => vue.VNodeChild) | undefined;
    "v-slot:counter"?: false | ((arg: VCounterSlot) => vue.VNodeChild) | undefined;
} & {
    "onUpdate:focused"?: ((focused: boolean) => any) | undefined;
    "onUpdate:modelValue"?: ((val: string) => any) | undefined;
    "onClick:control"?: ((e: MouseEvent) => any) | undefined;
    "onMousedown:control"?: ((e: MouseEvent) => any) | undefined;
}, HTMLInputElement & Omit<Omit<{
    $: vue.ComponentInternalInstance;
    $data: {};
    $props: Partial<{
        style: vue.StyleValue;
        error: boolean;
        disabled: boolean | null;
        messages: string | readonly string[];
        focused: boolean;
        errorMessages: string | readonly string[] | null;
        maxErrors: string | number;
        readonly: boolean | null;
        rules: readonly ValidationRule[];
        density: Density;
        direction: "horizontal" | "vertical";
        centerAffix: boolean;
        hideSpinButtons: boolean;
        persistentHint: boolean;
    }> & Omit<{
        style: vue.StyleValue;
        error: boolean;
        disabled: boolean | null;
        messages: string | readonly string[];
        focused: boolean;
        errorMessages: string | readonly string[] | null;
        maxErrors: string | number;
        readonly: boolean | null;
        rules: readonly ValidationRule[];
        density: Density;
        direction: "horizontal" | "vertical";
        centerAffix: boolean;
        hideSpinButtons: boolean;
        persistentHint: boolean;
        class?: any;
        id?: string | undefined;
        label?: string | undefined;
        width?: string | number | undefined;
        theme?: string | undefined;
        name?: string | undefined;
        'onUpdate:focused'?: ((args_0: boolean) => void) | undefined;
        validateOn?: ("input" | "blur" | "submit") | "input lazy" | "blur lazy" | "submit lazy" | "lazy input" | "lazy blur" | "lazy submit" | "lazy" | undefined;
        validationValue?: any;
        maxWidth?: string | number | undefined;
        minWidth?: string | number | undefined;
        prependIcon?: IconValue | undefined;
        appendIcon?: IconValue | undefined;
        'onClick:prepend'?: ((args_0: MouseEvent) => void) | undefined;
        'onClick:append'?: ((args_0: MouseEvent) => void) | undefined;
        hint?: string | undefined;
        hideDetails?: boolean | "auto" | undefined;
    } & vue.VNodeProps & vue.AllowedComponentProps & vue.ComponentCustomProps & {
        style: vue.StyleValue;
        error: boolean;
        disabled: boolean | null;
        messages: string | readonly string[];
        focused: boolean;
        errorMessages: string | readonly string[] | null;
        maxErrors: string | number;
        readonly: boolean | null;
        rules: readonly ValidationRule[];
        density: Density;
        direction: "horizontal" | "vertical";
        centerAffix: boolean;
        hideSpinButtons: boolean;
        persistentHint: boolean;
    } & {
        class?: any;
        id?: string | undefined;
        label?: string | undefined;
        width?: string | number | undefined;
        theme?: string | undefined;
        name?: string | undefined;
        'onUpdate:focused'?: ((args_0: boolean) => void) | undefined;
        validateOn?: ("input" | "blur" | "submit") | "input lazy" | "blur lazy" | "submit lazy" | "lazy input" | "lazy blur" | "lazy submit" | "lazy" | undefined;
        validationValue?: any;
        maxWidth?: string | number | undefined;
        minWidth?: string | number | undefined;
        prependIcon?: IconValue | undefined;
        appendIcon?: IconValue | undefined;
        'onClick:prepend'?: ((args_0: MouseEvent) => void) | undefined;
        'onClick:append'?: ((args_0: MouseEvent) => void) | undefined;
        hint?: string | undefined;
        hideDetails?: boolean | "auto" | undefined;
    } & {}, "style" | "error" | "disabled" | "messages" | "focused" | "errorMessages" | "maxErrors" | "readonly" | "rules" | "density" | "direction" | "centerAffix" | "hideSpinButtons" | "persistentHint">;
    $attrs: {
        [x: string]: unknown;
    };
    $refs: {
        [x: string]: unknown;
    };
    $slots: Readonly<{
        default?: ((arg: VInputSlot) => vue.VNode<vue.RendererNode, vue.RendererElement, {
            [key: string]: any;
        }>[]) | undefined;
        prepend?: ((arg: VInputSlot) => vue.VNode<vue.RendererNode, vue.RendererElement, {
            [key: string]: any;
        }>[]) | undefined;
        append?: ((arg: VInputSlot) => vue.VNode<vue.RendererNode, vue.RendererElement, {
            [key: string]: any;
        }>[]) | undefined;
        details?: ((arg: VInputSlot) => vue.VNode<vue.RendererNode, vue.RendererElement, {
            [key: string]: any;
        }>[]) | undefined;
        message?: ((arg: VMessageSlot) => vue.VNode<vue.RendererNode, vue.RendererElement, {
            [key: string]: any;
        }>[]) | undefined;
    }>;
    $root: vue.ComponentPublicInstance<{}, {}, {}, {}, {}, {}, {}, {}, false, vue.ComponentOptionsBase<any, any, any, any, any, any, any, any, any, {}, {}, string, {}>, {}, {}> | null;
    $parent: vue.ComponentPublicInstance<{}, {}, {}, {}, {}, {}, {}, {}, false, vue.ComponentOptionsBase<any, any, any, any, any, any, any, any, any, {}, {}, string, {}>, {}, {}> | null;
    $emit: (event: string, ...args: any[]) => void;
    $el: any;
    $options: vue.ComponentOptionsBase<{
        style: vue.StyleValue;
        error: boolean;
        disabled: boolean | null;
        messages: string | readonly string[];
        focused: boolean;
        errorMessages: string | readonly string[] | null;
        maxErrors: string | number;
        readonly: boolean | null;
        rules: readonly ValidationRule[];
        density: Density;
        direction: "horizontal" | "vertical";
        centerAffix: boolean;
        hideSpinButtons: boolean;
        persistentHint: boolean;
    } & {
        class?: any;
        id?: string | undefined;
        label?: string | undefined;
        width?: string | number | undefined;
        theme?: string | undefined;
        name?: string | undefined;
        'onUpdate:focused'?: ((args_0: boolean) => void) | undefined;
        validateOn?: ("input" | "blur" | "submit") | "input lazy" | "blur lazy" | "submit lazy" | "lazy input" | "lazy blur" | "lazy submit" | "lazy" | undefined;
        validationValue?: any;
        maxWidth?: string | number | undefined;
        minWidth?: string | number | undefined;
        prependIcon?: IconValue | undefined;
        appendIcon?: IconValue | undefined;
        'onClick:prepend'?: ((args_0: MouseEvent) => void) | undefined;
        'onClick:append'?: ((args_0: MouseEvent) => void) | undefined;
        hint?: string | undefined;
        hideDetails?: boolean | "auto" | undefined;
    } & {}, {
        reset: () => Promise<void>;
        resetValidation: () => Promise<void>;
        validate: (silent?: boolean) => Promise<string[]>;
        isValid: vue.ComputedRef<boolean | null>;
        errorMessages: vue.ComputedRef<string[]>;
    }, unknown, {}, {}, vue.ComponentOptionsMixin, vue.ComponentOptionsMixin, Omit<{
        'update:modelValue': (value: any) => true;
    }, "v-slot:default" | "$children" | "v-slots" | "modelValue" | "v-slot:prepend" | "v-slot:append" | "update:modelValue" | "v-slot:message" | "v-slot:details">, string, {
        style: vue.StyleValue;
        error: boolean;
        disabled: boolean | null;
        messages: string | readonly string[];
        focused: boolean;
        errorMessages: string | readonly string[] | null;
        maxErrors: string | number;
        readonly: boolean | null;
        rules: readonly ValidationRule[];
        density: Density;
        direction: "horizontal" | "vertical";
        centerAffix: boolean;
        hideSpinButtons: boolean;
        persistentHint: boolean;
    }, {}, string, vue.SlotsType<Partial<{
        default: (arg: VInputSlot) => vue.VNode<vue.RendererNode, vue.RendererElement, {
            [key: string]: any;
        }>[];
        prepend: (arg: VInputSlot) => vue.VNode<vue.RendererNode, vue.RendererElement, {
            [key: string]: any;
        }>[];
        append: (arg: VInputSlot) => vue.VNode<vue.RendererNode, vue.RendererElement, {
            [key: string]: any;
        }>[];
        details: (arg: VInputSlot) => vue.VNode<vue.RendererNode, vue.RendererElement, {
            [key: string]: any;
        }>[];
        message: (arg: VMessageSlot) => vue.VNode<vue.RendererNode, vue.RendererElement, {
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
    error: boolean;
    disabled: boolean | null;
    messages: string | readonly string[];
    focused: boolean;
    errorMessages: string | readonly string[] | null;
    maxErrors: string | number;
    readonly: boolean | null;
    rules: readonly ValidationRule[];
    density: Density;
    direction: "horizontal" | "vertical";
    centerAffix: boolean;
    hideSpinButtons: boolean;
    persistentHint: boolean;
} & {
    class?: any;
    id?: string | undefined;
    label?: string | undefined;
    width?: string | number | undefined;
    theme?: string | undefined;
    name?: string | undefined;
    'onUpdate:focused'?: ((args_0: boolean) => void) | undefined;
    validateOn?: ("input" | "blur" | "submit") | "input lazy" | "blur lazy" | "submit lazy" | "lazy input" | "lazy blur" | "lazy submit" | "lazy" | undefined;
    validationValue?: any;
    maxWidth?: string | number | undefined;
    minWidth?: string | number | undefined;
    prependIcon?: IconValue | undefined;
    appendIcon?: IconValue | undefined;
    'onClick:prepend'?: ((args_0: MouseEvent) => void) | undefined;
    'onClick:append'?: ((args_0: MouseEvent) => void) | undefined;
    hint?: string | undefined;
    hideDetails?: boolean | "auto" | undefined;
} & {}, "reset" | "isValid" | "errorMessages" | "validate" | "resetValidation"> & vue.ShallowUnwrapRef<{
    reset: () => Promise<void>;
    resetValidation: () => Promise<void>;
    validate: (silent?: boolean) => Promise<string[]>;
    isValid: vue.ComputedRef<boolean | null>;
    errorMessages: vue.ComputedRef<string[]>;
}> & {} & vue.ComponentCustomProperties & {} & GenericProps<{
    modelValue?: unknown;
    'onUpdate:modelValue'?: ((value: unknown) => void) | undefined;
}, VInputSlots>, "class" | "id" | "label" | "width" | "theme" | "key" | "name" | "v-slot:default" | "$children" | "v-slots" | "ref" | "ref_for" | "ref_key" | "onVnodeBeforeMount" | "onVnodeMounted" | "onVnodeBeforeUpdate" | "onVnodeUpdated" | "onVnodeBeforeUnmount" | "onVnodeUnmounted" | "onUpdate:focused" | "modelValue" | "validateOn" | "validationValue" | "onUpdate:modelValue" | "maxWidth" | "minWidth" | "v-slot:prepend" | "v-slot:append" | "prependIcon" | "appendIcon" | "onClick:prepend" | "onClick:append" | "v-slot:message" | "hint" | "hideDetails" | "v-slot:details" | ("style" | "error" | "disabled" | "messages" | "focused" | "errorMessages" | "maxErrors" | "readonly" | "rules" | "density" | "direction" | "centerAffix" | "hideSpinButtons" | "persistentHint")>, `$${any}`> & Omit<Omit<{
    $: vue.ComponentInternalInstance;
    $data: {};
    $props: Partial<{
        reverse: boolean;
        flat: boolean;
        style: vue.StyleValue;
        active: boolean;
        error: boolean;
        disabled: boolean;
        focused: boolean;
        rounded: string | number | boolean;
        variant: "underlined" | "filled" | "outlined" | "plain" | "solo" | "solo-inverted" | "solo-filled";
        tile: boolean;
        clearIcon: IconValue;
        centerAffix: boolean;
        clearable: boolean;
        dirty: boolean;
        persistentClear: boolean;
        singleLine: boolean;
    }> & Omit<{
        reverse: boolean;
        flat: boolean;
        style: vue.StyleValue;
        active: boolean;
        error: boolean;
        disabled: boolean;
        focused: boolean;
        variant: "underlined" | "filled" | "outlined" | "plain" | "solo" | "solo-inverted" | "solo-filled";
        tile: boolean;
        clearIcon: IconValue;
        clearable: boolean;
        dirty: boolean;
        persistentClear: boolean;
        singleLine: boolean;
        class?: any;
        id?: string | undefined;
        label?: string | undefined;
        theme?: string | undefined;
        color?: string | undefined;
        loading?: string | boolean | undefined;
        'onUpdate:focused'?: (((args_0: boolean) => void) & ((focused: boolean) => any)) | undefined;
        rounded?: string | number | boolean | undefined;
        baseColor?: string | undefined;
        bgColor?: string | undefined;
        appendInnerIcon?: IconValue | undefined;
        prependInnerIcon?: IconValue | undefined;
        'onClick:clear'?: ((args_0: MouseEvent) => void) | undefined;
        'onClick:appendInner'?: ((args_0: MouseEvent) => void) | undefined;
        'onClick:prependInner'?: ((args_0: MouseEvent) => void) | undefined;
        centerAffix?: boolean | undefined;
    } & vue.VNodeProps & vue.AllowedComponentProps & vue.ComponentCustomProps & {
        reverse: boolean;
        flat: boolean;
        style: vue.StyleValue;
        active: boolean;
        error: boolean;
        disabled: boolean;
        focused: boolean;
        variant: "underlined" | "filled" | "outlined" | "plain" | "solo" | "solo-inverted" | "solo-filled";
        tile: boolean;
        clearIcon: IconValue;
        clearable: boolean;
        dirty: boolean;
        persistentClear: boolean;
        singleLine: boolean;
    } & {
        class?: any;
        id?: string | undefined;
        label?: string | undefined;
        theme?: string | undefined;
        color?: string | undefined;
        loading?: string | boolean | undefined;
        'onUpdate:focused'?: ((args_0: boolean) => void) | undefined;
        rounded?: string | number | boolean | undefined;
        baseColor?: string | undefined;
        bgColor?: string | undefined;
        appendInnerIcon?: IconValue | undefined;
        prependInnerIcon?: IconValue | undefined;
        'onClick:clear'?: ((args_0: MouseEvent) => void) | undefined;
        'onClick:appendInner'?: ((args_0: MouseEvent) => void) | undefined;
        'onClick:prependInner'?: ((args_0: MouseEvent) => void) | undefined;
        centerAffix?: boolean | undefined;
    } & {
        "onUpdate:focused"?: ((focused: boolean) => any) | undefined;
    }, "reverse" | "flat" | "style" | "active" | "error" | "disabled" | "focused" | "rounded" | "variant" | "tile" | "clearIcon" | "centerAffix" | "clearable" | "dirty" | "persistentClear" | "singleLine">;
    $attrs: {
        [x: string]: unknown;
    };
    $refs: {
        [x: string]: unknown;
    };
    $slots: Readonly<{
        clear?: ((arg: DefaultInputSlot & {
            props: Record<string, any>;
        }) => vue.VNode<vue.RendererNode, vue.RendererElement, {
            [key: string]: any;
        }>[]) | undefined;
        'prepend-inner'?: ((arg: DefaultInputSlot) => vue.VNode<vue.RendererNode, vue.RendererElement, {
            [key: string]: any;
        }>[]) | undefined;
        'append-inner'?: ((arg: DefaultInputSlot) => vue.VNode<vue.RendererNode, vue.RendererElement, {
            [key: string]: any;
        }>[]) | undefined;
        label?: ((arg: DefaultInputSlot & {
            label: string | undefined;
            props: Record<string, any>;
        }) => vue.VNode<vue.RendererNode, vue.RendererElement, {
            [key: string]: any;
        }>[]) | undefined;
        loader?: ((arg: LoaderSlotProps) => vue.VNode<vue.RendererNode, vue.RendererElement, {
            [key: string]: any;
        }>[]) | undefined;
        default?: ((arg: VFieldSlot) => vue.VNode<vue.RendererNode, vue.RendererElement, {
            [key: string]: any;
        }>[]) | undefined;
    }>;
    $root: vue.ComponentPublicInstance<{}, {}, {}, {}, {}, {}, {}, {}, false, vue.ComponentOptionsBase<any, any, any, any, any, any, any, any, any, {}, {}, string, {}>, {}, {}> | null;
    $parent: vue.ComponentPublicInstance<{}, {}, {}, {}, {}, {}, {}, {}, false, vue.ComponentOptionsBase<any, any, any, any, any, any, any, any, any, {}, {}, string, {}>, {}, {}> | null;
    $emit: (event: "update:focused", focused: boolean) => void;
    $el: any;
    $options: vue.ComponentOptionsBase<{
        reverse: boolean;
        flat: boolean;
        style: vue.StyleValue;
        active: boolean;
        error: boolean;
        disabled: boolean;
        focused: boolean;
        variant: "underlined" | "filled" | "outlined" | "plain" | "solo" | "solo-inverted" | "solo-filled";
        tile: boolean;
        clearIcon: IconValue;
        clearable: boolean;
        dirty: boolean;
        persistentClear: boolean;
        singleLine: boolean;
    } & {
        class?: any;
        id?: string | undefined;
        label?: string | undefined;
        theme?: string | undefined;
        color?: string | undefined;
        loading?: string | boolean | undefined;
        'onUpdate:focused'?: ((args_0: boolean) => void) | undefined;
        rounded?: string | number | boolean | undefined;
        baseColor?: string | undefined;
        bgColor?: string | undefined;
        appendInnerIcon?: IconValue | undefined;
        prependInnerIcon?: IconValue | undefined;
        'onClick:clear'?: ((args_0: MouseEvent) => void) | undefined;
        'onClick:appendInner'?: ((args_0: MouseEvent) => void) | undefined;
        'onClick:prependInner'?: ((args_0: MouseEvent) => void) | undefined;
        centerAffix?: boolean | undefined;
    } & {
        "onUpdate:focused"?: ((focused: boolean) => any) | undefined;
    }, {
        controlRef: vue.Ref<HTMLElement | undefined>;
    }, unknown, {}, {}, vue.ComponentOptionsMixin, vue.ComponentOptionsMixin, Omit<{
        'update:focused': (focused: boolean) => true;
        'update:modelValue': (value: any) => true;
    }, "v-slot:default" | "$children" | "v-slots" | "modelValue" | "update:modelValue" | "v-slot:loader" | "v-slot:label" | "v-slot:clear" | "v-slot:prepend-inner" | "v-slot:append-inner">, string, {
        reverse: boolean;
        flat: boolean;
        style: vue.StyleValue;
        active: boolean;
        error: boolean;
        disabled: boolean;
        focused: boolean;
        rounded: string | number | boolean;
        variant: "underlined" | "filled" | "outlined" | "plain" | "solo" | "solo-inverted" | "solo-filled";
        tile: boolean;
        clearIcon: IconValue;
        centerAffix: boolean;
        clearable: boolean;
        dirty: boolean;
        persistentClear: boolean;
        singleLine: boolean;
    }, {}, string, vue.SlotsType<Partial<{
        clear: (arg: DefaultInputSlot & {
            props: Record<string, any>;
        }) => vue.VNode<vue.RendererNode, vue.RendererElement, {
            [key: string]: any;
        }>[];
        'prepend-inner': (arg: DefaultInputSlot) => vue.VNode<vue.RendererNode, vue.RendererElement, {
            [key: string]: any;
        }>[];
        'append-inner': (arg: DefaultInputSlot) => vue.VNode<vue.RendererNode, vue.RendererElement, {
            [key: string]: any;
        }>[];
        label: (arg: DefaultInputSlot & {
            label: string | undefined;
            props: Record<string, any>;
        }) => vue.VNode<vue.RendererNode, vue.RendererElement, {
            [key: string]: any;
        }>[];
        loader: (arg: LoaderSlotProps) => vue.VNode<vue.RendererNode, vue.RendererElement, {
            [key: string]: any;
        }>[];
        default: (arg: VFieldSlot) => vue.VNode<vue.RendererNode, vue.RendererElement, {
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
    reverse: boolean;
    flat: boolean;
    style: vue.StyleValue;
    active: boolean;
    error: boolean;
    disabled: boolean;
    focused: boolean;
    variant: "underlined" | "filled" | "outlined" | "plain" | "solo" | "solo-inverted" | "solo-filled";
    tile: boolean;
    clearIcon: IconValue;
    clearable: boolean;
    dirty: boolean;
    persistentClear: boolean;
    singleLine: boolean;
} & {
    class?: any;
    id?: string | undefined;
    label?: string | undefined;
    theme?: string | undefined;
    color?: string | undefined;
    loading?: string | boolean | undefined;
    'onUpdate:focused'?: ((args_0: boolean) => void) | undefined;
    rounded?: string | number | boolean | undefined;
    baseColor?: string | undefined;
    bgColor?: string | undefined;
    appendInnerIcon?: IconValue | undefined;
    prependInnerIcon?: IconValue | undefined;
    'onClick:clear'?: ((args_0: MouseEvent) => void) | undefined;
    'onClick:appendInner'?: ((args_0: MouseEvent) => void) | undefined;
    'onClick:prependInner'?: ((args_0: MouseEvent) => void) | undefined;
    centerAffix?: boolean | undefined;
} & {
    "onUpdate:focused"?: ((focused: boolean) => any) | undefined;
}, "controlRef"> & vue.ShallowUnwrapRef<{
    controlRef: vue.Ref<HTMLElement | undefined>;
}> & {} & vue.ComponentCustomProperties & {} & GenericProps<{
    modelValue?: unknown;
    'onUpdate:modelValue'?: ((value: unknown) => void) | undefined;
}, VFieldSlots>, "class" | "id" | "label" | "theme" | "key" | "color" | "v-slot:default" | "$children" | "v-slots" | "loading" | "ref" | "ref_for" | "ref_key" | "onVnodeBeforeMount" | "onVnodeMounted" | "onVnodeBeforeUpdate" | "onVnodeUpdated" | "onVnodeBeforeUnmount" | "onVnodeUnmounted" | "onUpdate:focused" | "modelValue" | "onUpdate:modelValue" | "baseColor" | "bgColor" | "v-slot:loader" | "v-slot:label" | "appendInnerIcon" | "prependInnerIcon" | "onClick:clear" | "onClick:appendInner" | "onClick:prependInner" | "v-slot:clear" | "v-slot:prepend-inner" | "v-slot:append-inner" | ("reverse" | "flat" | "style" | "active" | "error" | "disabled" | "focused" | "rounded" | "variant" | "tile" | "clearIcon" | "centerAffix" | "clearable" | "dirty" | "persistentClear" | "singleLine")>, `$${any}`>, unknown, {}, {}, vue.ComponentOptionsMixin, vue.ComponentOptionsMixin, {
    'click:control': (e: MouseEvent) => true;
    'mousedown:control': (e: MouseEvent) => true;
    'update:focused': (focused: boolean) => true;
    'update:modelValue': (val: string) => true;
}, string, {
    reverse: boolean;
    flat: boolean;
    style: vue.StyleValue;
    type: string;
    active: boolean;
    error: boolean;
    disabled: boolean;
    messages: string | readonly string[];
    focused: boolean;
    errorMessages: string | readonly string[] | null;
    maxErrors: string | number;
    readonly: boolean | null;
    rules: readonly ValidationRule[];
    rounded: string | number | boolean;
    variant: "underlined" | "filled" | "outlined" | "plain" | "solo" | "solo-inverted" | "solo-filled";
    tile: boolean;
    density: Density;
    direction: "horizontal" | "vertical";
    clearIcon: IconValue;
    centerAffix: boolean;
    hideSpinButtons: boolean;
    persistentHint: boolean;
    autofocus: boolean;
    clearable: boolean;
    dirty: boolean;
    persistentClear: boolean;
    singleLine: boolean;
    persistentPlaceholder: boolean;
    persistentCounter: boolean;
}, {}, string, vue.SlotsType<Partial<{
    clear: (arg: DefaultInputSlot & {
        props: Record<string, any>;
    }) => vue.VNode<vue.RendererNode, vue.RendererElement, {
        [key: string]: any;
    }>[];
    details: (arg: VInputSlot) => vue.VNode<vue.RendererNode, vue.RendererElement, {
        [key: string]: any;
    }>[];
    label: (arg: DefaultInputSlot & {
        label: string | undefined;
        props: Record<string, any>;
    }) => vue.VNode<vue.RendererNode, vue.RendererElement, {
        [key: string]: any;
    }>[];
    message: (arg: VMessageSlot) => vue.VNode<vue.RendererNode, vue.RendererElement, {
        [key: string]: any;
    }>[];
    prepend: (arg: VInputSlot) => vue.VNode<vue.RendererNode, vue.RendererElement, {
        [key: string]: any;
    }>[];
    append: (arg: VInputSlot) => vue.VNode<vue.RendererNode, vue.RendererElement, {
        [key: string]: any;
    }>[];
    loader: (arg: LoaderSlotProps) => vue.VNode<vue.RendererNode, vue.RendererElement, {
        [key: string]: any;
    }>[];
    'prepend-inner': (arg: DefaultInputSlot) => vue.VNode<vue.RendererNode, vue.RendererElement, {
        [key: string]: any;
    }>[];
    'append-inner': (arg: DefaultInputSlot) => vue.VNode<vue.RendererNode, vue.RendererElement, {
        [key: string]: any;
    }>[];
    default: () => vue.VNode<vue.RendererNode, vue.RendererElement, {
        [key: string]: any;
    }>[];
    counter: (arg: VCounterSlot) => vue.VNode<vue.RendererNode, vue.RendererElement, {
        [key: string]: any;
    }>[];
}>>> & vue.VNodeProps & vue.AllowedComponentProps & vue.ComponentCustomProps & FilterPropsOptions<{
    theme: StringConstructor;
    rounded: {
        type: (StringConstructor | NumberConstructor | BooleanConstructor)[];
        default: undefined;
    };
    tile: BooleanConstructor;
    loading: (StringConstructor | BooleanConstructor)[];
    class: PropType<any>;
    style: {
        type: PropType<vue.StyleValue>;
        default: null;
    };
    appendInnerIcon: PropType<IconValue>;
    bgColor: StringConstructor;
    clearable: BooleanConstructor;
    clearIcon: {
        type: PropType<IconValue>;
        default: string;
    };
    active: BooleanConstructor;
    centerAffix: {
        type: BooleanConstructor;
        default: undefined;
    };
    color: StringConstructor;
    baseColor: StringConstructor;
    dirty: BooleanConstructor;
    disabled: {
        type: BooleanConstructor;
        default: null;
    };
    error: BooleanConstructor;
    flat: BooleanConstructor;
    label: StringConstructor;
    persistentClear: BooleanConstructor;
    prependInnerIcon: PropType<IconValue>;
    reverse: BooleanConstructor;
    singleLine: BooleanConstructor;
    variant: {
        type: PropType<"underlined" | "filled" | "outlined" | "plain" | "solo" | "solo-inverted" | "solo-filled">;
        default: string;
        validator: (v: any) => boolean;
    };
    'onClick:clear': PropType<(args_0: MouseEvent) => void>;
    'onClick:appendInner': PropType<(args_0: MouseEvent) => void>;
    'onClick:prependInner': PropType<(args_0: MouseEvent) => void>;
    focused: BooleanConstructor;
    'onUpdate:focused': PropType<(args_0: boolean) => void>;
    errorMessages: {
        type: PropType<string | readonly string[] | null>;
        default: () => never[];
    };
    maxErrors: {
        type: (StringConstructor | NumberConstructor)[];
        default: number;
    };
    name: StringConstructor;
    readonly: {
        type: PropType<boolean | null>;
        default: null;
    };
    rules: {
        type: PropType<readonly ValidationRule[]>;
        default: () => never[];
    };
    modelValue: null;
    validateOn: PropType<("input" | "blur" | "submit") | "input lazy" | "blur lazy" | "submit lazy" | "lazy input" | "lazy blur" | "lazy submit" | "lazy" | undefined>;
    validationValue: null;
    width: (StringConstructor | NumberConstructor)[];
    maxWidth: (StringConstructor | NumberConstructor)[];
    minWidth: (StringConstructor | NumberConstructor)[];
    density: {
        type: PropType<Density>;
        default: string;
        validator: (v: any) => boolean;
    };
    id: StringConstructor;
    appendIcon: PropType<IconValue>;
    prependIcon: PropType<IconValue>;
    hideDetails: PropType<boolean | "auto">;
    hideSpinButtons: BooleanConstructor;
    hint: StringConstructor;
    persistentHint: BooleanConstructor;
    messages: {
        type: PropType<string | readonly string[]>;
        default: () => never[];
    };
    direction: {
        type: PropType<"horizontal" | "vertical">;
        default: string;
        validator: (v: any) => boolean;
    };
    'onClick:prepend': PropType<(args_0: MouseEvent) => void>;
    'onClick:append': PropType<(args_0: MouseEvent) => void>;
    autofocus: BooleanConstructor;
    counter: (StringConstructor | NumberConstructor | BooleanConstructor)[];
    counterValue: PropType<number | ((value: any) => number)>;
    prefix: StringConstructor;
    placeholder: StringConstructor;
    persistentPlaceholder: BooleanConstructor;
    persistentCounter: BooleanConstructor;
    suffix: StringConstructor;
    role: StringConstructor;
    type: {
        type: StringConstructor;
        default: string;
    };
    modelModifiers: PropType<Record<string, boolean>>;
}, vue.ExtractPropTypes<{
    theme: StringConstructor;
    rounded: {
        type: (StringConstructor | NumberConstructor | BooleanConstructor)[];
        default: undefined;
    };
    tile: BooleanConstructor;
    loading: (StringConstructor | BooleanConstructor)[];
    class: PropType<any>;
    style: {
        type: PropType<vue.StyleValue>;
        default: null;
    };
    appendInnerIcon: PropType<IconValue>;
    bgColor: StringConstructor;
    clearable: BooleanConstructor;
    clearIcon: {
        type: PropType<IconValue>;
        default: string;
    };
    active: BooleanConstructor;
    centerAffix: {
        type: BooleanConstructor;
        default: undefined;
    };
    color: StringConstructor;
    baseColor: StringConstructor;
    dirty: BooleanConstructor;
    disabled: {
        type: BooleanConstructor;
        default: null;
    };
    error: BooleanConstructor;
    flat: BooleanConstructor;
    label: StringConstructor;
    persistentClear: BooleanConstructor;
    prependInnerIcon: PropType<IconValue>;
    reverse: BooleanConstructor;
    singleLine: BooleanConstructor;
    variant: {
        type: PropType<"underlined" | "filled" | "outlined" | "plain" | "solo" | "solo-inverted" | "solo-filled">;
        default: string;
        validator: (v: any) => boolean;
    };
    'onClick:clear': PropType<(args_0: MouseEvent) => void>;
    'onClick:appendInner': PropType<(args_0: MouseEvent) => void>;
    'onClick:prependInner': PropType<(args_0: MouseEvent) => void>;
    focused: BooleanConstructor;
    'onUpdate:focused': PropType<(args_0: boolean) => void>;
    errorMessages: {
        type: PropType<string | readonly string[] | null>;
        default: () => never[];
    };
    maxErrors: {
        type: (StringConstructor | NumberConstructor)[];
        default: number;
    };
    name: StringConstructor;
    readonly: {
        type: PropType<boolean | null>;
        default: null;
    };
    rules: {
        type: PropType<readonly ValidationRule[]>;
        default: () => never[];
    };
    modelValue: null;
    validateOn: PropType<("input" | "blur" | "submit") | "input lazy" | "blur lazy" | "submit lazy" | "lazy input" | "lazy blur" | "lazy submit" | "lazy" | undefined>;
    validationValue: null;
    width: (StringConstructor | NumberConstructor)[];
    maxWidth: (StringConstructor | NumberConstructor)[];
    minWidth: (StringConstructor | NumberConstructor)[];
    density: {
        type: PropType<Density>;
        default: string;
        validator: (v: any) => boolean;
    };
    id: StringConstructor;
    appendIcon: PropType<IconValue>;
    prependIcon: PropType<IconValue>;
    hideDetails: PropType<boolean | "auto">;
    hideSpinButtons: BooleanConstructor;
    hint: StringConstructor;
    persistentHint: BooleanConstructor;
    messages: {
        type: PropType<string | readonly string[]>;
        default: () => never[];
    };
    direction: {
        type: PropType<"horizontal" | "vertical">;
        default: string;
        validator: (v: any) => boolean;
    };
    'onClick:prepend': PropType<(args_0: MouseEvent) => void>;
    'onClick:append': PropType<(args_0: MouseEvent) => void>;
    autofocus: BooleanConstructor;
    counter: (StringConstructor | NumberConstructor | BooleanConstructor)[];
    counterValue: PropType<number | ((value: any) => number)>;
    prefix: StringConstructor;
    placeholder: StringConstructor;
    persistentPlaceholder: BooleanConstructor;
    persistentCounter: BooleanConstructor;
    suffix: StringConstructor;
    role: StringConstructor;
    type: {
        type: StringConstructor;
        default: string;
    };
    modelModifiers: PropType<Record<string, boolean>>;
}>>;
type VTextField = InstanceType<typeof VTextField>;

export { VTextField };
