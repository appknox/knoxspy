import * as vue from 'vue';
import { ComponentPropsOptions, ExtractPropTypes, VNodeChild, VNode, JSXComponent, PropType, WritableComputedRef, Ref, CSSProperties, ComputedRef } from 'vue';

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

declare function deepEqual(a: any, b: any): boolean;

type Density = null | 'default' | 'comfortable' | 'compact';

type IconValue = string | (string | [path: string, opacity: number])[] | JSXComponent;
declare const IconValue: PropType<IconValue>;

type SelectionControlSlot = {
    model: WritableComputedRef<boolean>;
    textColorClasses: Ref<string[]>;
    textColorStyles: Ref<CSSProperties>;
    backgroundColorClasses: Ref<string[]>;
    backgroundColorStyles: Ref<CSSProperties>;
    inputNode: VNode;
    icon: IconValue | undefined;
    props: {
        onBlur: (e: Event) => void;
        onFocus: (e: FocusEvent) => void;
        id: string;
    };
};
type VSelectionControlSlots = {
    default: {
        backgroundColorClasses: Ref<string[]>;
        backgroundColorStyles: Ref<CSSProperties>;
    };
    label: {
        label: string | undefined;
        props: Record<string, unknown>;
    };
    input: SelectionControlSlot;
};

type VMessageSlot = {
    message: string;
};

type ValidationResult = string | boolean;
type ValidationRule = ValidationResult | PromiseLike<ValidationResult> | ((value: any) => ValidationResult) | ((value: any) => PromiseLike<ValidationResult>);

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

interface LoaderSlotProps {
    color: string | undefined;
    isActive: boolean;
}

type VSwitchSlot = {
    model: Ref<boolean>;
    isValid: ComputedRef<boolean | null>;
};
type VSwitchSlots = VInputSlots & VSelectionControlSlots & {
    loader: LoaderSlotProps;
    thumb: {
        icon: IconValue | undefined;
    } & VSwitchSlot;
    'track-false': VSwitchSlot;
    'track-true': VSwitchSlot;
};
declare const VSwitch: {
    new (...args: any[]): vue.CreateComponentPublicInstance<{
        flat: boolean;
        style: vue.StyleValue;
        error: boolean;
        disabled: boolean | null;
        loading: string | boolean;
        messages: string | readonly string[];
        focused: boolean;
        errorMessages: string | readonly string[] | null;
        maxErrors: string | number;
        readonly: boolean | null;
        rules: readonly ValidationRule[];
        inset: boolean;
        inline: boolean;
        multiple: boolean | null;
        density: Density;
        direction: "horizontal" | "vertical";
        indeterminate: boolean;
        ripple: boolean | {
            class: string;
        } | undefined;
        valueComparator: typeof deepEqual;
        centerAffix: boolean;
        hideSpinButtons: boolean;
        persistentHint: boolean;
    } & {
        class?: any;
        id?: string | undefined;
        label?: string | undefined;
        type?: string | undefined;
        value?: any;
        width?: string | number | undefined;
        theme?: string | undefined;
        color?: string | undefined;
        name?: string | undefined;
        'onUpdate:focused'?: ((args_0: boolean) => void) | undefined;
        validateOn?: ("input" | "blur" | "submit") | "input lazy" | "blur lazy" | "submit lazy" | "lazy input" | "lazy blur" | "lazy submit" | "lazy" | undefined;
        validationValue?: any;
        maxWidth?: string | number | undefined;
        minWidth?: string | number | undefined;
        baseColor?: string | undefined;
        prependIcon?: IconValue | undefined;
        appendIcon?: IconValue | undefined;
        defaultsTarget?: string | undefined;
        falseIcon?: IconValue | undefined;
        trueIcon?: IconValue | undefined;
        trueValue?: any;
        falseValue?: any;
        'onClick:prepend'?: ((args_0: MouseEvent) => void) | undefined;
        'onClick:append'?: ((args_0: MouseEvent) => void) | undefined;
        hint?: string | undefined;
        hideDetails?: boolean | "auto" | undefined;
    } & {
        "onUpdate:focused"?: ((focused: boolean) => any) | undefined;
        "onUpdate:indeterminate"?: ((value: boolean) => any) | undefined;
    }, {}, unknown, {}, {}, vue.ComponentOptionsMixin, vue.ComponentOptionsMixin, Omit<{
        'update:focused': (focused: boolean) => boolean;
        'update:modelValue': (value: any) => boolean;
        'update:indeterminate': (value: boolean) => boolean;
    }, "v-slot:default" | "$children" | "v-slots" | "modelValue" | "v-slot:prepend" | "v-slot:append" | "update:modelValue" | "v-slot:loader" | "v-slot:input" | "v-slot:label" | "v-slot:message" | "v-slot:details" | "v-slot:thumb" | "v-slot:track-false" | "v-slot:track-true">, vue.VNodeProps & vue.AllowedComponentProps & vue.ComponentCustomProps & {
        flat: boolean;
        style: vue.StyleValue;
        error: boolean;
        disabled: boolean | null;
        loading: string | boolean;
        messages: string | readonly string[];
        focused: boolean;
        errorMessages: string | readonly string[] | null;
        maxErrors: string | number;
        readonly: boolean | null;
        rules: readonly ValidationRule[];
        inset: boolean;
        inline: boolean;
        multiple: boolean | null;
        density: Density;
        direction: "horizontal" | "vertical";
        indeterminate: boolean;
        ripple: boolean | {
            class: string;
        } | undefined;
        valueComparator: typeof deepEqual;
        centerAffix: boolean;
        hideSpinButtons: boolean;
        persistentHint: boolean;
    } & {
        class?: any;
        id?: string | undefined;
        label?: string | undefined;
        type?: string | undefined;
        value?: any;
        width?: string | number | undefined;
        theme?: string | undefined;
        color?: string | undefined;
        name?: string | undefined;
        'onUpdate:focused'?: ((args_0: boolean) => void) | undefined;
        validateOn?: ("input" | "blur" | "submit") | "input lazy" | "blur lazy" | "submit lazy" | "lazy input" | "lazy blur" | "lazy submit" | "lazy" | undefined;
        validationValue?: any;
        maxWidth?: string | number | undefined;
        minWidth?: string | number | undefined;
        baseColor?: string | undefined;
        prependIcon?: IconValue | undefined;
        appendIcon?: IconValue | undefined;
        defaultsTarget?: string | undefined;
        falseIcon?: IconValue | undefined;
        trueIcon?: IconValue | undefined;
        trueValue?: any;
        falseValue?: any;
        'onClick:prepend'?: ((args_0: MouseEvent) => void) | undefined;
        'onClick:append'?: ((args_0: MouseEvent) => void) | undefined;
        hint?: string | undefined;
        hideDetails?: boolean | "auto" | undefined;
    } & {
        "onUpdate:focused"?: ((focused: boolean) => any) | undefined;
        "onUpdate:indeterminate"?: ((value: boolean) => any) | undefined;
    }, {
        flat: boolean;
        style: vue.StyleValue;
        error: boolean;
        disabled: boolean | null;
        loading: string | boolean;
        messages: string | readonly string[];
        focused: boolean;
        errorMessages: string | readonly string[] | null;
        maxErrors: string | number;
        readonly: boolean | null;
        rules: readonly ValidationRule[];
        inset: boolean;
        inline: boolean;
        multiple: boolean | null;
        density: Density;
        direction: "horizontal" | "vertical";
        indeterminate: boolean;
        ripple: boolean | {
            class: string;
        } | undefined;
        valueComparator: typeof deepEqual;
        centerAffix: boolean;
        hideSpinButtons: boolean;
        persistentHint: boolean;
    }, true, {}, vue.SlotsType<Partial<{
        default: (arg: VInputSlot & {
            backgroundColorClasses: Ref<string[]>;
            backgroundColorStyles: Ref<vue.CSSProperties>;
        }) => vue.VNode<vue.RendererNode, vue.RendererElement, {
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
        label: (arg: {
            label: string | undefined;
            props: Record<string, unknown>;
        }) => vue.VNode<vue.RendererNode, vue.RendererElement, {
            [key: string]: any;
        }>[];
        input: (arg: SelectionControlSlot) => vue.VNode<vue.RendererNode, vue.RendererElement, {
            [key: string]: any;
        }>[];
        loader: (arg: LoaderSlotProps) => vue.VNode<vue.RendererNode, vue.RendererElement, {
            [key: string]: any;
        }>[];
        thumb: (arg: {
            icon: IconValue | undefined;
        } & VSwitchSlot) => vue.VNode<vue.RendererNode, vue.RendererElement, {
            [key: string]: any;
        }>[];
        'track-false': (arg: VSwitchSlot) => vue.VNode<vue.RendererNode, vue.RendererElement, {
            [key: string]: any;
        }>[];
        'track-true': (arg: VSwitchSlot) => vue.VNode<vue.RendererNode, vue.RendererElement, {
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
        flat: boolean;
        style: vue.StyleValue;
        error: boolean;
        disabled: boolean | null;
        loading: string | boolean;
        messages: string | readonly string[];
        focused: boolean;
        errorMessages: string | readonly string[] | null;
        maxErrors: string | number;
        readonly: boolean | null;
        rules: readonly ValidationRule[];
        inset: boolean;
        inline: boolean;
        multiple: boolean | null;
        density: Density;
        direction: "horizontal" | "vertical";
        indeterminate: boolean;
        ripple: boolean | {
            class: string;
        } | undefined;
        valueComparator: typeof deepEqual;
        centerAffix: boolean;
        hideSpinButtons: boolean;
        persistentHint: boolean;
    } & {
        class?: any;
        id?: string | undefined;
        label?: string | undefined;
        type?: string | undefined;
        value?: any;
        width?: string | number | undefined;
        theme?: string | undefined;
        color?: string | undefined;
        name?: string | undefined;
        'onUpdate:focused'?: ((args_0: boolean) => void) | undefined;
        validateOn?: ("input" | "blur" | "submit") | "input lazy" | "blur lazy" | "submit lazy" | "lazy input" | "lazy blur" | "lazy submit" | "lazy" | undefined;
        validationValue?: any;
        maxWidth?: string | number | undefined;
        minWidth?: string | number | undefined;
        baseColor?: string | undefined;
        prependIcon?: IconValue | undefined;
        appendIcon?: IconValue | undefined;
        defaultsTarget?: string | undefined;
        falseIcon?: IconValue | undefined;
        trueIcon?: IconValue | undefined;
        trueValue?: any;
        falseValue?: any;
        'onClick:prepend'?: ((args_0: MouseEvent) => void) | undefined;
        'onClick:append'?: ((args_0: MouseEvent) => void) | undefined;
        hint?: string | undefined;
        hideDetails?: boolean | "auto" | undefined;
    } & {
        "onUpdate:focused"?: ((focused: boolean) => any) | undefined;
        "onUpdate:indeterminate"?: ((value: boolean) => any) | undefined;
    }, {}, {}, {}, {}, {
        flat: boolean;
        style: vue.StyleValue;
        error: boolean;
        disabled: boolean | null;
        loading: string | boolean;
        messages: string | readonly string[];
        focused: boolean;
        errorMessages: string | readonly string[] | null;
        maxErrors: string | number;
        readonly: boolean | null;
        rules: readonly ValidationRule[];
        inset: boolean;
        inline: boolean;
        multiple: boolean | null;
        density: Density;
        direction: "horizontal" | "vertical";
        indeterminate: boolean;
        ripple: boolean | {
            class: string;
        } | undefined;
        valueComparator: typeof deepEqual;
        centerAffix: boolean;
        hideSpinButtons: boolean;
        persistentHint: boolean;
    }>;
    __isFragment?: undefined;
    __isTeleport?: undefined;
    __isSuspense?: undefined;
} & vue.ComponentOptionsBase<{
    flat: boolean;
    style: vue.StyleValue;
    error: boolean;
    disabled: boolean | null;
    loading: string | boolean;
    messages: string | readonly string[];
    focused: boolean;
    errorMessages: string | readonly string[] | null;
    maxErrors: string | number;
    readonly: boolean | null;
    rules: readonly ValidationRule[];
    inset: boolean;
    inline: boolean;
    multiple: boolean | null;
    density: Density;
    direction: "horizontal" | "vertical";
    indeterminate: boolean;
    ripple: boolean | {
        class: string;
    } | undefined;
    valueComparator: typeof deepEqual;
    centerAffix: boolean;
    hideSpinButtons: boolean;
    persistentHint: boolean;
} & {
    class?: any;
    id?: string | undefined;
    label?: string | undefined;
    type?: string | undefined;
    value?: any;
    width?: string | number | undefined;
    theme?: string | undefined;
    color?: string | undefined;
    name?: string | undefined;
    'onUpdate:focused'?: ((args_0: boolean) => void) | undefined;
    validateOn?: ("input" | "blur" | "submit") | "input lazy" | "blur lazy" | "submit lazy" | "lazy input" | "lazy blur" | "lazy submit" | "lazy" | undefined;
    validationValue?: any;
    maxWidth?: string | number | undefined;
    minWidth?: string | number | undefined;
    baseColor?: string | undefined;
    prependIcon?: IconValue | undefined;
    appendIcon?: IconValue | undefined;
    defaultsTarget?: string | undefined;
    falseIcon?: IconValue | undefined;
    trueIcon?: IconValue | undefined;
    trueValue?: any;
    falseValue?: any;
    'onClick:prepend'?: ((args_0: MouseEvent) => void) | undefined;
    'onClick:append'?: ((args_0: MouseEvent) => void) | undefined;
    hint?: string | undefined;
    hideDetails?: boolean | "auto" | undefined;
} & {
    "onUpdate:focused"?: ((focused: boolean) => any) | undefined;
    "onUpdate:indeterminate"?: ((value: boolean) => any) | undefined;
}, {}, unknown, {}, {}, vue.ComponentOptionsMixin, vue.ComponentOptionsMixin, Omit<{
    'update:focused': (focused: boolean) => boolean;
    'update:modelValue': (value: any) => boolean;
    'update:indeterminate': (value: boolean) => boolean;
}, "v-slot:default" | "$children" | "v-slots" | "modelValue" | "v-slot:prepend" | "v-slot:append" | "update:modelValue" | "v-slot:loader" | "v-slot:input" | "v-slot:label" | "v-slot:message" | "v-slot:details" | "v-slot:thumb" | "v-slot:track-false" | "v-slot:track-true">, string, {
    flat: boolean;
    style: vue.StyleValue;
    error: boolean;
    disabled: boolean | null;
    loading: string | boolean;
    messages: string | readonly string[];
    focused: boolean;
    errorMessages: string | readonly string[] | null;
    maxErrors: string | number;
    readonly: boolean | null;
    rules: readonly ValidationRule[];
    inset: boolean;
    inline: boolean;
    multiple: boolean | null;
    density: Density;
    direction: "horizontal" | "vertical";
    indeterminate: boolean;
    ripple: boolean | {
        class: string;
    } | undefined;
    valueComparator: typeof deepEqual;
    centerAffix: boolean;
    hideSpinButtons: boolean;
    persistentHint: boolean;
}, {}, string, vue.SlotsType<Partial<{
    default: (arg: VInputSlot & {
        backgroundColorClasses: Ref<string[]>;
        backgroundColorStyles: Ref<vue.CSSProperties>;
    }) => vue.VNode<vue.RendererNode, vue.RendererElement, {
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
    label: (arg: {
        label: string | undefined;
        props: Record<string, unknown>;
    }) => vue.VNode<vue.RendererNode, vue.RendererElement, {
        [key: string]: any;
    }>[];
    input: (arg: SelectionControlSlot) => vue.VNode<vue.RendererNode, vue.RendererElement, {
        [key: string]: any;
    }>[];
    loader: (arg: LoaderSlotProps) => vue.VNode<vue.RendererNode, vue.RendererElement, {
        [key: string]: any;
    }>[];
    thumb: (arg: {
        icon: IconValue | undefined;
    } & VSwitchSlot) => vue.VNode<vue.RendererNode, vue.RendererElement, {
        [key: string]: any;
    }>[];
    'track-false': (arg: VSwitchSlot) => vue.VNode<vue.RendererNode, vue.RendererElement, {
        [key: string]: any;
    }>[];
    'track-true': (arg: VSwitchSlot) => vue.VNode<vue.RendererNode, vue.RendererElement, {
        [key: string]: any;
    }>[];
}>>> & vue.VNodeProps & vue.AllowedComponentProps & vue.ComponentCustomProps & (new <T>(props: {
    modelValue?: T | null | undefined;
    'onUpdate:modelValue'?: ((value: T | null) => void) | undefined;
}, slots: VSwitchSlots) => GenericProps<{
    modelValue?: T | null | undefined;
    'onUpdate:modelValue'?: ((value: T | null) => void) | undefined;
}, VSwitchSlots>) & FilterPropsOptions<{
    theme: StringConstructor;
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
    color: StringConstructor;
    disabled: {
        type: vue.PropType<boolean | null>;
        default: null;
    };
    defaultsTarget: StringConstructor;
    error: BooleanConstructor;
    id: StringConstructor;
    inline: BooleanConstructor;
    falseIcon: vue.PropType<IconValue>;
    trueIcon: vue.PropType<IconValue>;
    ripple: {
        type: vue.PropType<boolean | {
            class: string;
        } | undefined>;
        default: boolean;
    };
    multiple: {
        type: vue.PropType<boolean | null>;
        default: null;
    };
    name: StringConstructor;
    readonly: {
        type: vue.PropType<boolean | null>;
        default: null;
    };
    modelValue: null;
    type: StringConstructor;
    valueComparator: {
        type: vue.PropType<typeof deepEqual>;
        default: typeof deepEqual;
    };
    label: StringConstructor;
    baseColor: StringConstructor;
    trueValue: null;
    falseValue: null;
    value: null;
    focused: BooleanConstructor;
    'onUpdate:focused': vue.PropType<(args_0: boolean) => void>;
    errorMessages: {
        type: vue.PropType<string | readonly string[] | null>;
        default: () => never[];
    };
    maxErrors: {
        type: (StringConstructor | NumberConstructor)[];
        default: number;
    };
    rules: {
        type: vue.PropType<readonly ValidationRule[]>;
        default: () => never[];
    };
    validateOn: vue.PropType<("input" | "blur" | "submit") | "input lazy" | "blur lazy" | "submit lazy" | "lazy input" | "lazy blur" | "lazy submit" | "lazy" | undefined>;
    validationValue: null;
    width: (StringConstructor | NumberConstructor)[];
    maxWidth: (StringConstructor | NumberConstructor)[];
    minWidth: (StringConstructor | NumberConstructor)[];
    appendIcon: vue.PropType<IconValue>;
    centerAffix: {
        type: BooleanConstructor;
        default: boolean;
    };
    prependIcon: vue.PropType<IconValue>;
    hideDetails: vue.PropType<boolean | "auto">;
    hideSpinButtons: BooleanConstructor;
    hint: StringConstructor;
    persistentHint: BooleanConstructor;
    messages: {
        type: vue.PropType<string | readonly string[]>;
        default: () => never[];
    };
    direction: {
        type: vue.PropType<"horizontal" | "vertical">;
        default: string;
        validator: (v: any) => boolean;
    };
    'onClick:prepend': vue.PropType<(args_0: MouseEvent) => void>;
    'onClick:append': vue.PropType<(args_0: MouseEvent) => void>;
    indeterminate: BooleanConstructor;
    inset: BooleanConstructor;
    flat: BooleanConstructor;
    loading: {
        type: (StringConstructor | BooleanConstructor)[];
        default: boolean;
    };
}, vue.ExtractPropTypes<{
    theme: StringConstructor;
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
    color: StringConstructor;
    disabled: {
        type: vue.PropType<boolean | null>;
        default: null;
    };
    defaultsTarget: StringConstructor;
    error: BooleanConstructor;
    id: StringConstructor;
    inline: BooleanConstructor;
    falseIcon: vue.PropType<IconValue>;
    trueIcon: vue.PropType<IconValue>;
    ripple: {
        type: vue.PropType<boolean | {
            class: string;
        } | undefined>;
        default: boolean;
    };
    multiple: {
        type: vue.PropType<boolean | null>;
        default: null;
    };
    name: StringConstructor;
    readonly: {
        type: vue.PropType<boolean | null>;
        default: null;
    };
    modelValue: null;
    type: StringConstructor;
    valueComparator: {
        type: vue.PropType<typeof deepEqual>;
        default: typeof deepEqual;
    };
    label: StringConstructor;
    baseColor: StringConstructor;
    trueValue: null;
    falseValue: null;
    value: null;
    focused: BooleanConstructor;
    'onUpdate:focused': vue.PropType<(args_0: boolean) => void>;
    errorMessages: {
        type: vue.PropType<string | readonly string[] | null>;
        default: () => never[];
    };
    maxErrors: {
        type: (StringConstructor | NumberConstructor)[];
        default: number;
    };
    rules: {
        type: vue.PropType<readonly ValidationRule[]>;
        default: () => never[];
    };
    validateOn: vue.PropType<("input" | "blur" | "submit") | "input lazy" | "blur lazy" | "submit lazy" | "lazy input" | "lazy blur" | "lazy submit" | "lazy" | undefined>;
    validationValue: null;
    width: (StringConstructor | NumberConstructor)[];
    maxWidth: (StringConstructor | NumberConstructor)[];
    minWidth: (StringConstructor | NumberConstructor)[];
    appendIcon: vue.PropType<IconValue>;
    centerAffix: {
        type: BooleanConstructor;
        default: boolean;
    };
    prependIcon: vue.PropType<IconValue>;
    hideDetails: vue.PropType<boolean | "auto">;
    hideSpinButtons: BooleanConstructor;
    hint: StringConstructor;
    persistentHint: BooleanConstructor;
    messages: {
        type: vue.PropType<string | readonly string[]>;
        default: () => never[];
    };
    direction: {
        type: vue.PropType<"horizontal" | "vertical">;
        default: string;
        validator: (v: any) => boolean;
    };
    'onClick:prepend': vue.PropType<(args_0: MouseEvent) => void>;
    'onClick:append': vue.PropType<(args_0: MouseEvent) => void>;
    indeterminate: BooleanConstructor;
    inset: BooleanConstructor;
    flat: BooleanConstructor;
    loading: {
        type: (StringConstructor | BooleanConstructor)[];
        default: boolean;
    };
}>>;
type VSwitch = InstanceType<typeof VSwitch>;

export { VSwitch };
