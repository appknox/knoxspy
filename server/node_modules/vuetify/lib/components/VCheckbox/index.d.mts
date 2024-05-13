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

type VCheckboxSlots = Omit<VInputSlots, 'default'> & VSelectionControlSlots;
declare const VCheckbox: {
    new (...args: any[]): vue.CreateComponentPublicInstance<{
        style: vue.StyleValue;
        error: boolean;
        disabled: boolean | null;
        messages: string | readonly string[];
        focused: boolean;
        errorMessages: string | readonly string[] | null;
        maxErrors: string | number;
        readonly: boolean | null;
        rules: readonly ValidationRule[];
        multiple: boolean | null;
        density: Density;
        direction: "horizontal" | "vertical";
        indeterminate: boolean;
        ripple: boolean | {
            class: string;
        } | undefined;
        falseIcon: NonNullable<IconValue>;
        trueIcon: NonNullable<IconValue>;
        valueComparator: typeof deepEqual;
        indeterminateIcon: IconValue;
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
        trueValue?: any;
        falseValue?: any;
        'onClick:prepend'?: ((args_0: MouseEvent) => void) | undefined;
        'onClick:append'?: ((args_0: MouseEvent) => void) | undefined;
        hint?: string | undefined;
        hideDetails?: boolean | "auto" | undefined;
    } & {
        "onUpdate:focused"?: ((focused: boolean) => any) | undefined;
    }, {}, unknown, {}, {}, vue.ComponentOptionsMixin, vue.ComponentOptionsMixin, Omit<{
        'update:modelValue': (value: any) => boolean;
        'update:focused': (focused: boolean) => boolean;
    }, "v-slot:default" | "$children" | "v-slots" | "modelValue" | "v-slot:prepend" | "v-slot:append" | "update:modelValue" | "v-slot:input" | "v-slot:label" | "v-slot:message" | "v-slot:details">, vue.VNodeProps & vue.AllowedComponentProps & vue.ComponentCustomProps & {
        style: vue.StyleValue;
        error: boolean;
        disabled: boolean | null;
        messages: string | readonly string[];
        focused: boolean;
        errorMessages: string | readonly string[] | null;
        maxErrors: string | number;
        readonly: boolean | null;
        rules: readonly ValidationRule[];
        multiple: boolean | null;
        density: Density;
        direction: "horizontal" | "vertical";
        indeterminate: boolean;
        ripple: boolean | {
            class: string;
        } | undefined;
        falseIcon: NonNullable<IconValue>;
        trueIcon: NonNullable<IconValue>;
        valueComparator: typeof deepEqual;
        indeterminateIcon: IconValue;
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
        trueValue?: any;
        falseValue?: any;
        'onClick:prepend'?: ((args_0: MouseEvent) => void) | undefined;
        'onClick:append'?: ((args_0: MouseEvent) => void) | undefined;
        hint?: string | undefined;
        hideDetails?: boolean | "auto" | undefined;
    } & {
        "onUpdate:focused"?: ((focused: boolean) => any) | undefined;
    }, {
        style: vue.StyleValue;
        error: boolean;
        disabled: boolean | null;
        messages: string | readonly string[];
        focused: boolean;
        errorMessages: string | readonly string[] | null;
        maxErrors: string | number;
        readonly: boolean | null;
        rules: readonly ValidationRule[];
        multiple: boolean | null;
        density: Density;
        direction: "horizontal" | "vertical";
        indeterminate: boolean;
        ripple: boolean | {
            class: string;
        } | undefined;
        falseIcon: NonNullable<IconValue>;
        trueIcon: NonNullable<IconValue>;
        valueComparator: typeof deepEqual;
        indeterminateIcon: IconValue;
        centerAffix: boolean;
        hideSpinButtons: boolean;
        persistentHint: boolean;
    }, true, {}, vue.SlotsType<Partial<{
        details: (arg: VInputSlot) => vue.VNode<vue.RendererNode, vue.RendererElement, {
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
        default: (arg: {
            backgroundColorClasses: vue.Ref<string[]>;
            backgroundColorStyles: vue.Ref<vue.CSSProperties>;
        }) => vue.VNode<vue.RendererNode, vue.RendererElement, {
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
    }>>, {
        P: {};
        B: {};
        D: {};
        C: {};
        M: {};
        Defaults: {};
    }, {
        style: vue.StyleValue;
        error: boolean;
        disabled: boolean | null;
        messages: string | readonly string[];
        focused: boolean;
        errorMessages: string | readonly string[] | null;
        maxErrors: string | number;
        readonly: boolean | null;
        rules: readonly ValidationRule[];
        multiple: boolean | null;
        density: Density;
        direction: "horizontal" | "vertical";
        indeterminate: boolean;
        ripple: boolean | {
            class: string;
        } | undefined;
        falseIcon: NonNullable<IconValue>;
        trueIcon: NonNullable<IconValue>;
        valueComparator: typeof deepEqual;
        indeterminateIcon: IconValue;
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
        trueValue?: any;
        falseValue?: any;
        'onClick:prepend'?: ((args_0: MouseEvent) => void) | undefined;
        'onClick:append'?: ((args_0: MouseEvent) => void) | undefined;
        hint?: string | undefined;
        hideDetails?: boolean | "auto" | undefined;
    } & {
        "onUpdate:focused"?: ((focused: boolean) => any) | undefined;
    }, {}, {}, {}, {}, {
        style: vue.StyleValue;
        error: boolean;
        disabled: boolean | null;
        messages: string | readonly string[];
        focused: boolean;
        errorMessages: string | readonly string[] | null;
        maxErrors: string | number;
        readonly: boolean | null;
        rules: readonly ValidationRule[];
        multiple: boolean | null;
        density: Density;
        direction: "horizontal" | "vertical";
        indeterminate: boolean;
        ripple: boolean | {
            class: string;
        } | undefined;
        falseIcon: NonNullable<IconValue>;
        trueIcon: NonNullable<IconValue>;
        valueComparator: typeof deepEqual;
        indeterminateIcon: IconValue;
        centerAffix: boolean;
        hideSpinButtons: boolean;
        persistentHint: boolean;
    }>;
    __isFragment?: undefined;
    __isTeleport?: undefined;
    __isSuspense?: undefined;
} & vue.ComponentOptionsBase<{
    style: vue.StyleValue;
    error: boolean;
    disabled: boolean | null;
    messages: string | readonly string[];
    focused: boolean;
    errorMessages: string | readonly string[] | null;
    maxErrors: string | number;
    readonly: boolean | null;
    rules: readonly ValidationRule[];
    multiple: boolean | null;
    density: Density;
    direction: "horizontal" | "vertical";
    indeterminate: boolean;
    ripple: boolean | {
        class: string;
    } | undefined;
    falseIcon: NonNullable<IconValue>;
    trueIcon: NonNullable<IconValue>;
    valueComparator: typeof deepEqual;
    indeterminateIcon: IconValue;
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
    trueValue?: any;
    falseValue?: any;
    'onClick:prepend'?: ((args_0: MouseEvent) => void) | undefined;
    'onClick:append'?: ((args_0: MouseEvent) => void) | undefined;
    hint?: string | undefined;
    hideDetails?: boolean | "auto" | undefined;
} & {
    "onUpdate:focused"?: ((focused: boolean) => any) | undefined;
}, {}, unknown, {}, {}, vue.ComponentOptionsMixin, vue.ComponentOptionsMixin, Omit<{
    'update:modelValue': (value: any) => boolean;
    'update:focused': (focused: boolean) => boolean;
}, "v-slot:default" | "$children" | "v-slots" | "modelValue" | "v-slot:prepend" | "v-slot:append" | "update:modelValue" | "v-slot:input" | "v-slot:label" | "v-slot:message" | "v-slot:details">, string, {
    style: vue.StyleValue;
    error: boolean;
    disabled: boolean | null;
    messages: string | readonly string[];
    focused: boolean;
    errorMessages: string | readonly string[] | null;
    maxErrors: string | number;
    readonly: boolean | null;
    rules: readonly ValidationRule[];
    multiple: boolean | null;
    density: Density;
    direction: "horizontal" | "vertical";
    indeterminate: boolean;
    ripple: boolean | {
        class: string;
    } | undefined;
    falseIcon: NonNullable<IconValue>;
    trueIcon: NonNullable<IconValue>;
    valueComparator: typeof deepEqual;
    indeterminateIcon: IconValue;
    centerAffix: boolean;
    hideSpinButtons: boolean;
    persistentHint: boolean;
}, {}, string, vue.SlotsType<Partial<{
    details: (arg: VInputSlot) => vue.VNode<vue.RendererNode, vue.RendererElement, {
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
    default: (arg: {
        backgroundColorClasses: vue.Ref<string[]>;
        backgroundColorStyles: vue.Ref<vue.CSSProperties>;
    }) => vue.VNode<vue.RendererNode, vue.RendererElement, {
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
}>>> & vue.VNodeProps & vue.AllowedComponentProps & vue.ComponentCustomProps & (new <T>(props: {
    modelValue?: T | null | undefined;
    'onUpdate:modelValue'?: ((value: T | null) => void) | undefined;
}, slots: VCheckboxSlots) => GenericProps<{
    modelValue?: T | null | undefined;
    'onUpdate:modelValue'?: ((value: T | null) => void) | undefined;
}, VCheckboxSlots>) & FilterPropsOptions<{
    class: vue.PropType<any>;
    style: {
        type: vue.PropType<vue.StyleValue>;
        default: null;
    };
    id: StringConstructor;
    label: StringConstructor;
    type: StringConstructor;
    value: null;
    error: BooleanConstructor;
    theme: StringConstructor;
    color: StringConstructor;
    name: StringConstructor;
    disabled: {
        type: vue.PropType<boolean | null>;
        default: null;
    };
    readonly: {
        type: vue.PropType<boolean | null>;
        default: null;
    };
    modelValue: null;
    multiple: {
        type: vue.PropType<boolean | null>;
        default: null;
    };
    density: {
        type: vue.PropType<Density>;
        default: string;
        validator: (v: any) => boolean;
    };
    baseColor: StringConstructor;
    indeterminate: BooleanConstructor;
    ripple: {
        type: vue.PropType<boolean | {
            class: string;
        } | undefined>;
        default: boolean;
    };
    defaultsTarget: StringConstructor;
    falseIcon: {
        type: vue.PropType<NonNullable<IconValue>>;
        default: NonNullable<IconValue>;
    };
    trueIcon: {
        type: vue.PropType<NonNullable<IconValue>>;
        default: NonNullable<IconValue>;
    };
    valueComparator: {
        type: vue.PropType<typeof deepEqual>;
        default: typeof deepEqual;
    };
    trueValue: null;
    falseValue: null;
    indeterminateIcon: {
        type: vue.PropType<IconValue>;
        default: string;
    };
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
}, vue.ExtractPropTypes<{
    class: vue.PropType<any>;
    style: {
        type: vue.PropType<vue.StyleValue>;
        default: null;
    };
    id: StringConstructor;
    label: StringConstructor;
    type: StringConstructor;
    value: null;
    error: BooleanConstructor;
    theme: StringConstructor;
    color: StringConstructor;
    name: StringConstructor;
    disabled: {
        type: vue.PropType<boolean | null>;
        default: null;
    };
    readonly: {
        type: vue.PropType<boolean | null>;
        default: null;
    };
    modelValue: null;
    multiple: {
        type: vue.PropType<boolean | null>;
        default: null;
    };
    density: {
        type: vue.PropType<Density>;
        default: string;
        validator: (v: any) => boolean;
    };
    baseColor: StringConstructor;
    indeterminate: BooleanConstructor;
    ripple: {
        type: vue.PropType<boolean | {
            class: string;
        } | undefined>;
        default: boolean;
    };
    defaultsTarget: StringConstructor;
    falseIcon: {
        type: vue.PropType<NonNullable<IconValue>>;
        default: NonNullable<IconValue>;
    };
    trueIcon: {
        type: vue.PropType<NonNullable<IconValue>>;
        default: NonNullable<IconValue>;
    };
    valueComparator: {
        type: vue.PropType<typeof deepEqual>;
        default: typeof deepEqual;
    };
    trueValue: null;
    falseValue: null;
    indeterminateIcon: {
        type: vue.PropType<IconValue>;
        default: string;
    };
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
}>>;
type VCheckbox = InstanceType<typeof VCheckbox>;

declare const VCheckboxBtn: {
    new (...args: any[]): vue.CreateComponentPublicInstance<{
        style: vue.StyleValue;
        error: boolean;
        disabled: boolean | null;
        readonly: boolean | null;
        inline: boolean;
        multiple: boolean | null;
        density: Density;
        indeterminate: boolean;
        ripple: boolean | {
            class: string;
        } | undefined;
        falseIcon: NonNullable<IconValue>;
        trueIcon: NonNullable<IconValue>;
        valueComparator: typeof deepEqual;
        indeterminateIcon: IconValue;
    } & {
        class?: any;
        id?: string | undefined;
        label?: string | undefined;
        type?: string | undefined;
        value?: any;
        theme?: string | undefined;
        color?: string | undefined;
        name?: string | undefined;
        baseColor?: string | undefined;
        defaultsTarget?: string | undefined;
        trueValue?: any;
        falseValue?: any;
    } & {
        "onUpdate:indeterminate"?: ((value: boolean) => any) | undefined;
    }, {}, unknown, {}, {}, vue.ComponentOptionsMixin, vue.ComponentOptionsMixin, Omit<{
        'update:modelValue': (value: any) => boolean;
        'update:indeterminate': (value: boolean) => boolean;
    }, "v-slot:default" | "$children" | "v-slots" | "modelValue" | "update:modelValue" | "v-slot:input" | "v-slot:label">, vue.VNodeProps & vue.AllowedComponentProps & vue.ComponentCustomProps & {
        style: vue.StyleValue;
        error: boolean;
        disabled: boolean | null;
        readonly: boolean | null;
        inline: boolean;
        multiple: boolean | null;
        density: Density;
        indeterminate: boolean;
        ripple: boolean | {
            class: string;
        } | undefined;
        falseIcon: NonNullable<IconValue>;
        trueIcon: NonNullable<IconValue>;
        valueComparator: typeof deepEqual;
        indeterminateIcon: IconValue;
    } & {
        class?: any;
        id?: string | undefined;
        label?: string | undefined;
        type?: string | undefined;
        value?: any;
        theme?: string | undefined;
        color?: string | undefined;
        name?: string | undefined;
        baseColor?: string | undefined;
        defaultsTarget?: string | undefined;
        trueValue?: any;
        falseValue?: any;
    } & {
        "onUpdate:indeterminate"?: ((value: boolean) => any) | undefined;
    }, {
        style: vue.StyleValue;
        error: boolean;
        disabled: boolean | null;
        readonly: boolean | null;
        inline: boolean;
        multiple: boolean | null;
        density: Density;
        indeterminate: boolean;
        ripple: boolean | {
            class: string;
        } | undefined;
        falseIcon: NonNullable<IconValue>;
        trueIcon: NonNullable<IconValue>;
        valueComparator: typeof deepEqual;
        indeterminateIcon: IconValue;
    }, true, {}, vue.SlotsType<Partial<{
        default: (arg: {
            backgroundColorClasses: vue.Ref<string[]>;
            backgroundColorStyles: vue.Ref<vue.CSSProperties>;
        }) => vue.VNode<vue.RendererNode, vue.RendererElement, {
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
    }>>, {
        P: {};
        B: {};
        D: {};
        C: {};
        M: {};
        Defaults: {};
    }, {
        style: vue.StyleValue;
        error: boolean;
        disabled: boolean | null;
        readonly: boolean | null;
        inline: boolean;
        multiple: boolean | null;
        density: Density;
        indeterminate: boolean;
        ripple: boolean | {
            class: string;
        } | undefined;
        falseIcon: NonNullable<IconValue>;
        trueIcon: NonNullable<IconValue>;
        valueComparator: typeof deepEqual;
        indeterminateIcon: IconValue;
    } & {
        class?: any;
        id?: string | undefined;
        label?: string | undefined;
        type?: string | undefined;
        value?: any;
        theme?: string | undefined;
        color?: string | undefined;
        name?: string | undefined;
        baseColor?: string | undefined;
        defaultsTarget?: string | undefined;
        trueValue?: any;
        falseValue?: any;
    } & {
        "onUpdate:indeterminate"?: ((value: boolean) => any) | undefined;
    }, {}, {}, {}, {}, {
        style: vue.StyleValue;
        error: boolean;
        disabled: boolean | null;
        readonly: boolean | null;
        inline: boolean;
        multiple: boolean | null;
        density: Density;
        indeterminate: boolean;
        ripple: boolean | {
            class: string;
        } | undefined;
        falseIcon: NonNullable<IconValue>;
        trueIcon: NonNullable<IconValue>;
        valueComparator: typeof deepEqual;
        indeterminateIcon: IconValue;
    }>;
    __isFragment?: undefined;
    __isTeleport?: undefined;
    __isSuspense?: undefined;
} & vue.ComponentOptionsBase<{
    style: vue.StyleValue;
    error: boolean;
    disabled: boolean | null;
    readonly: boolean | null;
    inline: boolean;
    multiple: boolean | null;
    density: Density;
    indeterminate: boolean;
    ripple: boolean | {
        class: string;
    } | undefined;
    falseIcon: NonNullable<IconValue>;
    trueIcon: NonNullable<IconValue>;
    valueComparator: typeof deepEqual;
    indeterminateIcon: IconValue;
} & {
    class?: any;
    id?: string | undefined;
    label?: string | undefined;
    type?: string | undefined;
    value?: any;
    theme?: string | undefined;
    color?: string | undefined;
    name?: string | undefined;
    baseColor?: string | undefined;
    defaultsTarget?: string | undefined;
    trueValue?: any;
    falseValue?: any;
} & {
    "onUpdate:indeterminate"?: ((value: boolean) => any) | undefined;
}, {}, unknown, {}, {}, vue.ComponentOptionsMixin, vue.ComponentOptionsMixin, Omit<{
    'update:modelValue': (value: any) => boolean;
    'update:indeterminate': (value: boolean) => boolean;
}, "v-slot:default" | "$children" | "v-slots" | "modelValue" | "update:modelValue" | "v-slot:input" | "v-slot:label">, string, {
    style: vue.StyleValue;
    error: boolean;
    disabled: boolean | null;
    readonly: boolean | null;
    inline: boolean;
    multiple: boolean | null;
    density: Density;
    indeterminate: boolean;
    ripple: boolean | {
        class: string;
    } | undefined;
    falseIcon: NonNullable<IconValue>;
    trueIcon: NonNullable<IconValue>;
    valueComparator: typeof deepEqual;
    indeterminateIcon: IconValue;
}, {}, string, vue.SlotsType<Partial<{
    default: (arg: {
        backgroundColorClasses: vue.Ref<string[]>;
        backgroundColorStyles: vue.Ref<vue.CSSProperties>;
    }) => vue.VNode<vue.RendererNode, vue.RendererElement, {
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
}>>> & vue.VNodeProps & vue.AllowedComponentProps & vue.ComponentCustomProps & (new <T>(props: {
    modelValue?: T | undefined;
    'onUpdate:modelValue'?: ((value: T) => void) | undefined;
}, slots: VSelectionControlSlots) => GenericProps<{
    modelValue?: T | undefined;
    'onUpdate:modelValue'?: ((value: T) => void) | undefined;
}, VSelectionControlSlots>) & FilterPropsOptions<{
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
    falseIcon: {
        type: vue.PropType<NonNullable<IconValue>>;
        default: NonNullable<IconValue>;
    };
    trueIcon: {
        type: vue.PropType<NonNullable<IconValue>>;
        default: NonNullable<IconValue>;
    };
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
    indeterminate: BooleanConstructor;
    indeterminateIcon: {
        type: vue.PropType<IconValue>;
        default: string;
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
    falseIcon: {
        type: vue.PropType<NonNullable<IconValue>>;
        default: NonNullable<IconValue>;
    };
    trueIcon: {
        type: vue.PropType<NonNullable<IconValue>>;
        default: NonNullable<IconValue>;
    };
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
    indeterminate: BooleanConstructor;
    indeterminateIcon: {
        type: vue.PropType<IconValue>;
        default: string;
    };
}>>;
type VCheckboxBtn = InstanceType<typeof VCheckboxBtn>;

export { VCheckbox, VCheckboxBtn };
