import * as vue from 'vue';
import { ComponentPropsOptions, ExtractPropTypes, VNodeChild, VNode, JSXComponent, PropType, ComputedRef, Ref } from 'vue';

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

type VRadioGroupSlots = Omit<VInputSlots, 'default'> & {
    default: never;
    label: {
        label: string | undefined;
        props: Record<string, any>;
    };
};
declare const VRadioGroup: {
    new (...args: any[]): vue.CreateComponentPublicInstance<{
        style: vue.StyleValue;
        type: string;
        height: string | number;
        error: boolean;
        disabled: boolean | null;
        messages: string | readonly string[];
        focused: boolean;
        errorMessages: string | readonly string[] | null;
        maxErrors: string | number;
        readonly: boolean | null;
        rules: readonly ValidationRule[];
        inline: boolean;
        density: Density;
        direction: "horizontal" | "vertical";
        ripple: boolean | {
            class: string;
        } | undefined;
        falseIcon: IconValue;
        trueIcon: IconValue;
        valueComparator: typeof deepEqual;
        centerAffix: boolean;
        hideSpinButtons: boolean;
        persistentHint: boolean;
    } & {
        class?: any;
        id?: string | undefined;
        label?: string | undefined;
        width?: string | number | undefined;
        theme?: string | undefined;
        color?: string | undefined;
        name?: string | undefined;
        'onUpdate:focused'?: ((args_0: boolean) => void) | undefined;
        validateOn?: ("input" | "blur" | "submit") | "input lazy" | "blur lazy" | "submit lazy" | "lazy input" | "lazy blur" | "lazy submit" | "lazy" | undefined;
        validationValue?: any;
        maxWidth?: string | number | undefined;
        minWidth?: string | number | undefined;
        prependIcon?: IconValue | undefined;
        appendIcon?: IconValue | undefined;
        defaultsTarget?: string | undefined;
        'onClick:prepend'?: ((args_0: MouseEvent) => void) | undefined;
        'onClick:append'?: ((args_0: MouseEvent) => void) | undefined;
        hint?: string | undefined;
        hideDetails?: boolean | "auto" | undefined;
    } & {}, {}, unknown, {}, {}, vue.ComponentOptionsMixin, vue.ComponentOptionsMixin, Omit<{
        'update:modelValue': (value: any) => boolean;
    }, "v-slot:default" | "$children" | "v-slots" | "modelValue" | "v-slot:prepend" | "v-slot:append" | "update:modelValue" | "v-slot:label" | "v-slot:message" | "v-slot:details">, vue.VNodeProps & vue.AllowedComponentProps & vue.ComponentCustomProps & {
        style: vue.StyleValue;
        type: string;
        height: string | number;
        error: boolean;
        disabled: boolean | null;
        messages: string | readonly string[];
        focused: boolean;
        errorMessages: string | readonly string[] | null;
        maxErrors: string | number;
        readonly: boolean | null;
        rules: readonly ValidationRule[];
        inline: boolean;
        density: Density;
        direction: "horizontal" | "vertical";
        ripple: boolean | {
            class: string;
        } | undefined;
        falseIcon: IconValue;
        trueIcon: IconValue;
        valueComparator: typeof deepEqual;
        centerAffix: boolean;
        hideSpinButtons: boolean;
        persistentHint: boolean;
    } & {
        class?: any;
        id?: string | undefined;
        label?: string | undefined;
        width?: string | number | undefined;
        theme?: string | undefined;
        color?: string | undefined;
        name?: string | undefined;
        'onUpdate:focused'?: ((args_0: boolean) => void) | undefined;
        validateOn?: ("input" | "blur" | "submit") | "input lazy" | "blur lazy" | "submit lazy" | "lazy input" | "lazy blur" | "lazy submit" | "lazy" | undefined;
        validationValue?: any;
        maxWidth?: string | number | undefined;
        minWidth?: string | number | undefined;
        prependIcon?: IconValue | undefined;
        appendIcon?: IconValue | undefined;
        defaultsTarget?: string | undefined;
        'onClick:prepend'?: ((args_0: MouseEvent) => void) | undefined;
        'onClick:append'?: ((args_0: MouseEvent) => void) | undefined;
        hint?: string | undefined;
        hideDetails?: boolean | "auto" | undefined;
    } & {}, {
        style: vue.StyleValue;
        type: string;
        height: string | number;
        error: boolean;
        disabled: boolean | null;
        messages: string | readonly string[];
        focused: boolean;
        errorMessages: string | readonly string[] | null;
        maxErrors: string | number;
        readonly: boolean | null;
        rules: readonly ValidationRule[];
        inline: boolean;
        density: Density;
        direction: "horizontal" | "vertical";
        ripple: boolean | {
            class: string;
        } | undefined;
        falseIcon: IconValue;
        trueIcon: IconValue;
        valueComparator: typeof deepEqual;
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
        default: () => vue.VNode<vue.RendererNode, vue.RendererElement, {
            [key: string]: any;
        }>[];
        label: (arg: {
            label: string | undefined;
            props: Record<string, any>;
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
        type: string;
        height: string | number;
        error: boolean;
        disabled: boolean | null;
        messages: string | readonly string[];
        focused: boolean;
        errorMessages: string | readonly string[] | null;
        maxErrors: string | number;
        readonly: boolean | null;
        rules: readonly ValidationRule[];
        inline: boolean;
        density: Density;
        direction: "horizontal" | "vertical";
        ripple: boolean | {
            class: string;
        } | undefined;
        falseIcon: IconValue;
        trueIcon: IconValue;
        valueComparator: typeof deepEqual;
        centerAffix: boolean;
        hideSpinButtons: boolean;
        persistentHint: boolean;
    } & {
        class?: any;
        id?: string | undefined;
        label?: string | undefined;
        width?: string | number | undefined;
        theme?: string | undefined;
        color?: string | undefined;
        name?: string | undefined;
        'onUpdate:focused'?: ((args_0: boolean) => void) | undefined;
        validateOn?: ("input" | "blur" | "submit") | "input lazy" | "blur lazy" | "submit lazy" | "lazy input" | "lazy blur" | "lazy submit" | "lazy" | undefined;
        validationValue?: any;
        maxWidth?: string | number | undefined;
        minWidth?: string | number | undefined;
        prependIcon?: IconValue | undefined;
        appendIcon?: IconValue | undefined;
        defaultsTarget?: string | undefined;
        'onClick:prepend'?: ((args_0: MouseEvent) => void) | undefined;
        'onClick:append'?: ((args_0: MouseEvent) => void) | undefined;
        hint?: string | undefined;
        hideDetails?: boolean | "auto" | undefined;
    } & {}, {}, {}, {}, {}, {
        style: vue.StyleValue;
        type: string;
        height: string | number;
        error: boolean;
        disabled: boolean | null;
        messages: string | readonly string[];
        focused: boolean;
        errorMessages: string | readonly string[] | null;
        maxErrors: string | number;
        readonly: boolean | null;
        rules: readonly ValidationRule[];
        inline: boolean;
        density: Density;
        direction: "horizontal" | "vertical";
        ripple: boolean | {
            class: string;
        } | undefined;
        falseIcon: IconValue;
        trueIcon: IconValue;
        valueComparator: typeof deepEqual;
        centerAffix: boolean;
        hideSpinButtons: boolean;
        persistentHint: boolean;
    }>;
    __isFragment?: undefined;
    __isTeleport?: undefined;
    __isSuspense?: undefined;
} & vue.ComponentOptionsBase<{
    style: vue.StyleValue;
    type: string;
    height: string | number;
    error: boolean;
    disabled: boolean | null;
    messages: string | readonly string[];
    focused: boolean;
    errorMessages: string | readonly string[] | null;
    maxErrors: string | number;
    readonly: boolean | null;
    rules: readonly ValidationRule[];
    inline: boolean;
    density: Density;
    direction: "horizontal" | "vertical";
    ripple: boolean | {
        class: string;
    } | undefined;
    falseIcon: IconValue;
    trueIcon: IconValue;
    valueComparator: typeof deepEqual;
    centerAffix: boolean;
    hideSpinButtons: boolean;
    persistentHint: boolean;
} & {
    class?: any;
    id?: string | undefined;
    label?: string | undefined;
    width?: string | number | undefined;
    theme?: string | undefined;
    color?: string | undefined;
    name?: string | undefined;
    'onUpdate:focused'?: ((args_0: boolean) => void) | undefined;
    validateOn?: ("input" | "blur" | "submit") | "input lazy" | "blur lazy" | "submit lazy" | "lazy input" | "lazy blur" | "lazy submit" | "lazy" | undefined;
    validationValue?: any;
    maxWidth?: string | number | undefined;
    minWidth?: string | number | undefined;
    prependIcon?: IconValue | undefined;
    appendIcon?: IconValue | undefined;
    defaultsTarget?: string | undefined;
    'onClick:prepend'?: ((args_0: MouseEvent) => void) | undefined;
    'onClick:append'?: ((args_0: MouseEvent) => void) | undefined;
    hint?: string | undefined;
    hideDetails?: boolean | "auto" | undefined;
} & {}, {}, unknown, {}, {}, vue.ComponentOptionsMixin, vue.ComponentOptionsMixin, Omit<{
    'update:modelValue': (value: any) => boolean;
}, "v-slot:default" | "$children" | "v-slots" | "modelValue" | "v-slot:prepend" | "v-slot:append" | "update:modelValue" | "v-slot:label" | "v-slot:message" | "v-slot:details">, string, {
    style: vue.StyleValue;
    type: string;
    height: string | number;
    error: boolean;
    disabled: boolean | null;
    messages: string | readonly string[];
    focused: boolean;
    errorMessages: string | readonly string[] | null;
    maxErrors: string | number;
    readonly: boolean | null;
    rules: readonly ValidationRule[];
    inline: boolean;
    density: Density;
    direction: "horizontal" | "vertical";
    ripple: boolean | {
        class: string;
    } | undefined;
    falseIcon: IconValue;
    trueIcon: IconValue;
    valueComparator: typeof deepEqual;
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
    default: () => vue.VNode<vue.RendererNode, vue.RendererElement, {
        [key: string]: any;
    }>[];
    label: (arg: {
        label: string | undefined;
        props: Record<string, any>;
    }) => vue.VNode<vue.RendererNode, vue.RendererElement, {
        [key: string]: any;
    }>[];
}>>> & vue.VNodeProps & vue.AllowedComponentProps & vue.ComponentCustomProps & (new <T>(props: {
    modelValue?: T | null | undefined;
    'onUpdate:modelValue'?: ((value: T | null) => void) | undefined;
}, slots: VRadioGroupSlots) => GenericProps<{
    modelValue?: T | null | undefined;
    'onUpdate:modelValue'?: ((value: T | null) => void) | undefined;
}, VRadioGroupSlots>) & FilterPropsOptions<{
    trueIcon: {
        type: vue.PropType<IconValue>;
        default: string;
    };
    falseIcon: {
        type: vue.PropType<IconValue>;
        default: string;
    };
    type: {
        type: StringConstructor;
        default: string;
    };
    class: vue.PropType<any>;
    style: {
        type: vue.PropType<vue.StyleValue>;
        default: null;
    };
    id: StringConstructor;
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
    inline: BooleanConstructor;
    density: {
        type: vue.PropType<Density>;
        default: string;
        validator: (v: any) => boolean;
    };
    ripple: {
        type: vue.PropType<boolean | {
            class: string;
        } | undefined>;
        default: boolean;
    };
    defaultsTarget: StringConstructor;
    valueComparator: {
        type: vue.PropType<typeof deepEqual>;
        default: typeof deepEqual;
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
    label: StringConstructor;
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
    height: {
        type: (StringConstructor | NumberConstructor)[];
        default: string;
    };
}, vue.ExtractPropTypes<{
    trueIcon: {
        type: vue.PropType<IconValue>;
        default: string;
    };
    falseIcon: {
        type: vue.PropType<IconValue>;
        default: string;
    };
    type: {
        type: StringConstructor;
        default: string;
    };
    class: vue.PropType<any>;
    style: {
        type: vue.PropType<vue.StyleValue>;
        default: null;
    };
    id: StringConstructor;
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
    inline: BooleanConstructor;
    density: {
        type: vue.PropType<Density>;
        default: string;
        validator: (v: any) => boolean;
    };
    ripple: {
        type: vue.PropType<boolean | {
            class: string;
        } | undefined>;
        default: boolean;
    };
    defaultsTarget: StringConstructor;
    valueComparator: {
        type: vue.PropType<typeof deepEqual>;
        default: typeof deepEqual;
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
    label: StringConstructor;
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
    height: {
        type: (StringConstructor | NumberConstructor)[];
        default: string;
    };
}>>;
type VRadioGroup = InstanceType<typeof VRadioGroup>;

export { VRadioGroup };
