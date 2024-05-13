import * as vue from 'vue';
import { ComponentPropsOptions, ExtractPropTypes, VNodeChild, VNode, JSXComponent, PropType, ComponentInternalInstance, Ref, ComputedRef } from 'vue';

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

interface TouchHandlers {
    start?: (wrapperEvent: {
        originalEvent: TouchEvent;
    } & TouchData) => void;
    end?: (wrapperEvent: {
        originalEvent: TouchEvent;
    } & TouchData) => void;
    move?: (wrapperEvent: {
        originalEvent: TouchEvent;
    } & TouchData) => void;
    left?: (wrapper: TouchData) => void;
    right?: (wrapper: TouchData) => void;
    up?: (wrapper: TouchData) => void;
    down?: (wrapper: TouchData) => void;
}
interface TouchData {
    touchstartX: number;
    touchstartY: number;
    touchmoveX: number;
    touchmoveY: number;
    touchendX: number;
    touchendY: number;
    offsetX: number;
    offsetY: number;
}

type IconValue = string | (string | [path: string, opacity: number])[] | JSXComponent;
declare const IconValue: PropType<IconValue>;

interface GroupItem {
    id: number;
    value: Ref<unknown>;
    disabled: Ref<boolean | undefined>;
    useIndexAsValue?: boolean;
}
interface GroupProvide {
    register: (item: GroupItem, cmp: ComponentInternalInstance) => void;
    unregister: (id: number) => void;
    select: (id: number, value: boolean) => void;
    selected: Ref<Readonly<number[]>>;
    isSelected: (id: number) => boolean;
    prev: () => void;
    next: () => void;
    selectedClass: Ref<string | undefined>;
    items: ComputedRef<{
        id: number;
        value: unknown;
        disabled: boolean | undefined;
    }[]>;
    disabled: Ref<boolean | undefined>;
    getItemIndex: (value: unknown) => number;
}

type VWindowSlots = {
    default: {
        group: GroupProvide;
    };
    additional: {
        group: GroupProvide;
    };
    prev: {
        props: ControlProps;
    };
    next: {
        props: ControlProps;
    };
};
type ControlProps = {
    icon: IconValue;
    class: string;
    onClick: () => void;
    'aria-label': string;
};

type VCarouselSlots = VWindowSlots & {
    item: {
        props: Record<string, any>;
        item: {
            id: number;
            value: unknown;
            disabled: boolean | undefined;
        };
    };
};
declare const VCarousel: {
    new (...args: any[]): vue.CreateComponentPublicInstance<{
        reverse: boolean;
        style: vue.StyleValue;
        height: string | number;
        disabled: boolean;
        tag: string;
        mandatory: NonNullable<boolean | "force">;
        direction: "horizontal" | "vertical";
        selectedClass: string;
        nextIcon: IconValue;
        prevIcon: IconValue;
        showArrows: NonNullable<string | boolean>;
        continuous: boolean;
        cycle: boolean;
        delimiterIcon: IconValue;
        hideDelimiters: boolean;
        hideDelimiterBackground: boolean;
        interval: string | number;
    } & {
        class?: any;
        progress?: string | boolean | undefined;
        theme?: string | undefined;
        color?: string | undefined;
        touch?: boolean | TouchHandlers | undefined;
        verticalDelimiters?: boolean | "left" | "right" | undefined;
    } & {}, {}, unknown, {}, {}, vue.ComponentOptionsMixin, vue.ComponentOptionsMixin, Omit<{
        'update:modelValue': (value: any) => boolean;
    }, "v-slot:default" | "$children" | "v-slots" | "modelValue" | "v-slot:additional" | "update:modelValue" | "v-slot:next" | "v-slot:prev" | "v-slot:item">, vue.VNodeProps & vue.AllowedComponentProps & vue.ComponentCustomProps & {
        reverse: boolean;
        style: vue.StyleValue;
        height: string | number;
        disabled: boolean;
        tag: string;
        mandatory: NonNullable<boolean | "force">;
        direction: "horizontal" | "vertical";
        selectedClass: string;
        nextIcon: IconValue;
        prevIcon: IconValue;
        showArrows: NonNullable<string | boolean>;
        continuous: boolean;
        cycle: boolean;
        delimiterIcon: IconValue;
        hideDelimiters: boolean;
        hideDelimiterBackground: boolean;
        interval: string | number;
    } & {
        class?: any;
        progress?: string | boolean | undefined;
        theme?: string | undefined;
        color?: string | undefined;
        touch?: boolean | TouchHandlers | undefined;
        verticalDelimiters?: boolean | "left" | "right" | undefined;
    } & {}, {
        reverse: boolean;
        style: vue.StyleValue;
        height: string | number;
        disabled: boolean;
        tag: string;
        mandatory: NonNullable<boolean | "force">;
        touch: boolean | TouchHandlers;
        direction: "horizontal" | "vertical";
        selectedClass: string;
        nextIcon: IconValue;
        prevIcon: IconValue;
        showArrows: NonNullable<string | boolean>;
        continuous: boolean;
        cycle: boolean;
        delimiterIcon: IconValue;
        hideDelimiters: boolean;
        hideDelimiterBackground: boolean;
        interval: string | number;
    }, true, {}, vue.SlotsType<Partial<{
        default: (arg: {
            group: GroupProvide;
        }) => vue.VNode<vue.RendererNode, vue.RendererElement, {
            [key: string]: any;
        }>[];
        additional: (arg: {
            group: GroupProvide;
        }) => vue.VNode<vue.RendererNode, vue.RendererElement, {
            [key: string]: any;
        }>[];
        prev: (arg: {
            props: {
                icon: IconValue;
                class: string;
                onClick: () => void;
                'aria-label': string;
            };
        }) => vue.VNode<vue.RendererNode, vue.RendererElement, {
            [key: string]: any;
        }>[];
        next: (arg: {
            props: {
                icon: IconValue;
                class: string;
                onClick: () => void;
                'aria-label': string;
            };
        }) => vue.VNode<vue.RendererNode, vue.RendererElement, {
            [key: string]: any;
        }>[];
        item: (arg: {
            props: Record<string, any>;
            item: {
                id: number;
                value: unknown;
                disabled: boolean | undefined;
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
        reverse: boolean;
        style: vue.StyleValue;
        height: string | number;
        disabled: boolean;
        tag: string;
        mandatory: NonNullable<boolean | "force">;
        direction: "horizontal" | "vertical";
        selectedClass: string;
        nextIcon: IconValue;
        prevIcon: IconValue;
        showArrows: NonNullable<string | boolean>;
        continuous: boolean;
        cycle: boolean;
        delimiterIcon: IconValue;
        hideDelimiters: boolean;
        hideDelimiterBackground: boolean;
        interval: string | number;
    } & {
        class?: any;
        progress?: string | boolean | undefined;
        theme?: string | undefined;
        color?: string | undefined;
        touch?: boolean | TouchHandlers | undefined;
        verticalDelimiters?: boolean | "left" | "right" | undefined;
    } & {}, {}, {}, {}, {}, {
        reverse: boolean;
        style: vue.StyleValue;
        height: string | number;
        disabled: boolean;
        tag: string;
        mandatory: NonNullable<boolean | "force">;
        touch: boolean | TouchHandlers;
        direction: "horizontal" | "vertical";
        selectedClass: string;
        nextIcon: IconValue;
        prevIcon: IconValue;
        showArrows: NonNullable<string | boolean>;
        continuous: boolean;
        cycle: boolean;
        delimiterIcon: IconValue;
        hideDelimiters: boolean;
        hideDelimiterBackground: boolean;
        interval: string | number;
    }>;
    __isFragment?: undefined;
    __isTeleport?: undefined;
    __isSuspense?: undefined;
} & vue.ComponentOptionsBase<{
    reverse: boolean;
    style: vue.StyleValue;
    height: string | number;
    disabled: boolean;
    tag: string;
    mandatory: NonNullable<boolean | "force">;
    direction: "horizontal" | "vertical";
    selectedClass: string;
    nextIcon: IconValue;
    prevIcon: IconValue;
    showArrows: NonNullable<string | boolean>;
    continuous: boolean;
    cycle: boolean;
    delimiterIcon: IconValue;
    hideDelimiters: boolean;
    hideDelimiterBackground: boolean;
    interval: string | number;
} & {
    class?: any;
    progress?: string | boolean | undefined;
    theme?: string | undefined;
    color?: string | undefined;
    touch?: boolean | TouchHandlers | undefined;
    verticalDelimiters?: boolean | "left" | "right" | undefined;
} & {}, {}, unknown, {}, {}, vue.ComponentOptionsMixin, vue.ComponentOptionsMixin, Omit<{
    'update:modelValue': (value: any) => boolean;
}, "v-slot:default" | "$children" | "v-slots" | "modelValue" | "v-slot:additional" | "update:modelValue" | "v-slot:next" | "v-slot:prev" | "v-slot:item">, string, {
    reverse: boolean;
    style: vue.StyleValue;
    height: string | number;
    disabled: boolean;
    tag: string;
    mandatory: NonNullable<boolean | "force">;
    touch: boolean | TouchHandlers;
    direction: "horizontal" | "vertical";
    selectedClass: string;
    nextIcon: IconValue;
    prevIcon: IconValue;
    showArrows: NonNullable<string | boolean>;
    continuous: boolean;
    cycle: boolean;
    delimiterIcon: IconValue;
    hideDelimiters: boolean;
    hideDelimiterBackground: boolean;
    interval: string | number;
}, {}, string, vue.SlotsType<Partial<{
    default: (arg: {
        group: GroupProvide;
    }) => vue.VNode<vue.RendererNode, vue.RendererElement, {
        [key: string]: any;
    }>[];
    additional: (arg: {
        group: GroupProvide;
    }) => vue.VNode<vue.RendererNode, vue.RendererElement, {
        [key: string]: any;
    }>[];
    prev: (arg: {
        props: {
            icon: IconValue;
            class: string;
            onClick: () => void;
            'aria-label': string;
        };
    }) => vue.VNode<vue.RendererNode, vue.RendererElement, {
        [key: string]: any;
    }>[];
    next: (arg: {
        props: {
            icon: IconValue;
            class: string;
            onClick: () => void;
            'aria-label': string;
        };
    }) => vue.VNode<vue.RendererNode, vue.RendererElement, {
        [key: string]: any;
    }>[];
    item: (arg: {
        props: Record<string, any>;
        item: {
            id: number;
            value: unknown;
            disabled: boolean | undefined;
        };
    }) => vue.VNode<vue.RendererNode, vue.RendererElement, {
        [key: string]: any;
    }>[];
}>>> & vue.VNodeProps & vue.AllowedComponentProps & vue.ComponentCustomProps & (new <T>(props: {
    modelValue?: T | undefined;
    'onUpdate:modelValue'?: ((value: T) => void) | undefined;
}, slots: VCarouselSlots) => GenericProps<{
    modelValue?: T | undefined;
    'onUpdate:modelValue'?: ((value: T) => void) | undefined;
}, VCarouselSlots>) & FilterPropsOptions<{
    theme: StringConstructor;
    tag: {
        type: StringConstructor;
        default: string;
    };
    class: PropType<any>;
    style: {
        type: PropType<vue.StyleValue>;
        default: null;
    };
    continuous: {
        type: PropType<boolean>;
        default: boolean;
    };
    nextIcon: {
        type: PropType<IconValue>;
        default: string;
    };
    prevIcon: {
        type: PropType<IconValue>;
        default: string;
    };
    reverse: BooleanConstructor;
    showArrows: Omit<{
        type: (StringConstructor | BooleanConstructor)[];
        validator: (v: any) => boolean;
    }, "default" | "type"> & {
        type: PropType<NonNullable<string | boolean>>;
        default: NonNullable<string | boolean>;
    };
    touch: {
        type: PropType<boolean | TouchHandlers>;
        default: undefined;
    };
    direction: {
        type: PropType<"horizontal" | "vertical">;
        default: string;
    };
    modelValue: null;
    disabled: BooleanConstructor;
    selectedClass: {
        type: StringConstructor;
        default: string;
    };
    mandatory: Omit<{
        type: PropType<boolean | "force">;
        default: "force";
    }, "default" | "type"> & {
        type: PropType<NonNullable<boolean | "force">>;
        default: NonNullable<boolean | "force">;
    };
    color: StringConstructor;
    cycle: BooleanConstructor;
    delimiterIcon: {
        type: PropType<IconValue>;
        default: string;
    };
    height: {
        type: (StringConstructor | NumberConstructor)[];
        default: number;
    };
    hideDelimiters: BooleanConstructor;
    hideDelimiterBackground: BooleanConstructor;
    interval: {
        type: (StringConstructor | NumberConstructor)[];
        default: number;
        validator: (value: string | number) => boolean;
    };
    progress: (StringConstructor | BooleanConstructor)[];
    verticalDelimiters: PropType<boolean | "left" | "right">;
}, vue.ExtractPropTypes<{
    theme: StringConstructor;
    tag: {
        type: StringConstructor;
        default: string;
    };
    class: PropType<any>;
    style: {
        type: PropType<vue.StyleValue>;
        default: null;
    };
    continuous: {
        type: PropType<boolean>;
        default: boolean;
    };
    nextIcon: {
        type: PropType<IconValue>;
        default: string;
    };
    prevIcon: {
        type: PropType<IconValue>;
        default: string;
    };
    reverse: BooleanConstructor;
    showArrows: Omit<{
        type: (StringConstructor | BooleanConstructor)[];
        validator: (v: any) => boolean;
    }, "default" | "type"> & {
        type: PropType<NonNullable<string | boolean>>;
        default: NonNullable<string | boolean>;
    };
    touch: {
        type: PropType<boolean | TouchHandlers>;
        default: undefined;
    };
    direction: {
        type: PropType<"horizontal" | "vertical">;
        default: string;
    };
    modelValue: null;
    disabled: BooleanConstructor;
    selectedClass: {
        type: StringConstructor;
        default: string;
    };
    mandatory: Omit<{
        type: PropType<boolean | "force">;
        default: "force";
    }, "default" | "type"> & {
        type: PropType<NonNullable<boolean | "force">>;
        default: NonNullable<boolean | "force">;
    };
    color: StringConstructor;
    cycle: BooleanConstructor;
    delimiterIcon: {
        type: PropType<IconValue>;
        default: string;
    };
    height: {
        type: (StringConstructor | NumberConstructor)[];
        default: number;
    };
    hideDelimiters: BooleanConstructor;
    hideDelimiterBackground: BooleanConstructor;
    interval: {
        type: (StringConstructor | NumberConstructor)[];
        default: number;
        validator: (value: string | number) => boolean;
    };
    progress: (StringConstructor | BooleanConstructor)[];
    verticalDelimiters: PropType<boolean | "left" | "right">;
}>>;
type VCarousel = InstanceType<typeof VCarousel>;

interface srcObject {
    src?: string;
    srcset?: string;
    lazySrc?: string;
    aspect: number;
}

declare const VCarouselItem: {
    new (...args: any[]): vue.CreateComponentPublicInstance<{
        style: vue.StyleValue;
        src: string | srcObject;
        disabled: boolean;
        options: IntersectionObserverInit;
        inline: boolean;
        cover: boolean;
        tile: boolean;
        eager: boolean;
    } & {
        class?: any;
        value?: any;
        width?: string | number | undefined;
        height?: string | number | undefined;
        color?: string | undefined;
        crossorigin?: "" | "anonymous" | "use-credentials" | undefined;
        referrerpolicy?: "origin" | "no-referrer" | "no-referrer-when-downgrade" | "origin-when-cross-origin" | "same-origin" | "strict-origin" | "strict-origin-when-cross-origin" | "unsafe-url" | undefined;
        sizes?: string | undefined;
        transition?: string | boolean | undefined;
        position?: string | undefined;
        rounded?: string | number | boolean | undefined;
        contentClass?: any;
        maxHeight?: string | number | undefined;
        maxWidth?: string | number | undefined;
        minHeight?: string | number | undefined;
        minWidth?: string | number | undefined;
        aspectRatio?: string | number | undefined;
        alt?: string | undefined;
        draggable?: boolean | "false" | "true" | undefined;
        gradient?: string | undefined;
        lazySrc?: string | undefined;
        srcset?: string | undefined;
        selectedClass?: string | undefined;
        reverseTransition?: string | boolean | undefined;
    } & {
        $children?: vue.VNodeChild | (() => vue.VNodeChild) | {
            default?: (() => vue.VNodeChild) | undefined;
            placeholder?: (() => vue.VNodeChild) | undefined;
            error?: (() => vue.VNodeChild) | undefined;
            sources?: (() => vue.VNodeChild) | undefined;
        };
        'v-slots'?: {
            default?: false | (() => vue.VNodeChild) | undefined;
            placeholder?: false | (() => vue.VNodeChild) | undefined;
            error?: false | (() => vue.VNodeChild) | undefined;
            sources?: false | (() => vue.VNodeChild) | undefined;
        } | undefined;
    } & {
        "v-slot:default"?: false | (() => vue.VNodeChild) | undefined;
        "v-slot:placeholder"?: false | (() => vue.VNodeChild) | undefined;
        "v-slot:error"?: false | (() => vue.VNodeChild) | undefined;
        "v-slot:sources"?: false | (() => vue.VNodeChild) | undefined;
    }, void, unknown, {}, {}, vue.ComponentOptionsMixin, vue.ComponentOptionsMixin, Record<string, any>, vue.VNodeProps & vue.AllowedComponentProps & vue.ComponentCustomProps & {
        style: vue.StyleValue;
        src: string | srcObject;
        disabled: boolean;
        options: IntersectionObserverInit;
        inline: boolean;
        cover: boolean;
        tile: boolean;
        eager: boolean;
    } & {
        class?: any;
        value?: any;
        width?: string | number | undefined;
        height?: string | number | undefined;
        color?: string | undefined;
        crossorigin?: "" | "anonymous" | "use-credentials" | undefined;
        referrerpolicy?: "origin" | "no-referrer" | "no-referrer-when-downgrade" | "origin-when-cross-origin" | "same-origin" | "strict-origin" | "strict-origin-when-cross-origin" | "unsafe-url" | undefined;
        sizes?: string | undefined;
        transition?: string | boolean | undefined;
        position?: string | undefined;
        rounded?: string | number | boolean | undefined;
        contentClass?: any;
        maxHeight?: string | number | undefined;
        maxWidth?: string | number | undefined;
        minHeight?: string | number | undefined;
        minWidth?: string | number | undefined;
        aspectRatio?: string | number | undefined;
        alt?: string | undefined;
        draggable?: boolean | "false" | "true" | undefined;
        gradient?: string | undefined;
        lazySrc?: string | undefined;
        srcset?: string | undefined;
        selectedClass?: string | undefined;
        reverseTransition?: string | boolean | undefined;
    } & {
        $children?: vue.VNodeChild | (() => vue.VNodeChild) | {
            default?: (() => vue.VNodeChild) | undefined;
            placeholder?: (() => vue.VNodeChild) | undefined;
            error?: (() => vue.VNodeChild) | undefined;
            sources?: (() => vue.VNodeChild) | undefined;
        };
        'v-slots'?: {
            default?: false | (() => vue.VNodeChild) | undefined;
            placeholder?: false | (() => vue.VNodeChild) | undefined;
            error?: false | (() => vue.VNodeChild) | undefined;
            sources?: false | (() => vue.VNodeChild) | undefined;
        } | undefined;
    } & {
        "v-slot:default"?: false | (() => vue.VNodeChild) | undefined;
        "v-slot:placeholder"?: false | (() => vue.VNodeChild) | undefined;
        "v-slot:error"?: false | (() => vue.VNodeChild) | undefined;
        "v-slot:sources"?: false | (() => vue.VNodeChild) | undefined;
    }, {
        style: vue.StyleValue;
        src: string | srcObject;
        disabled: boolean;
        options: IntersectionObserverInit;
        transition: string | boolean;
        rounded: string | number | boolean;
        inline: boolean;
        cover: boolean;
        tile: boolean;
        draggable: boolean | "false" | "true";
        eager: boolean;
        reverseTransition: string | boolean;
    }, true, {}, vue.SlotsType<Partial<{
        default: () => vue.VNode<vue.RendererNode, vue.RendererElement, {
            [key: string]: any;
        }>[];
        placeholder: () => vue.VNode<vue.RendererNode, vue.RendererElement, {
            [key: string]: any;
        }>[];
        error: () => vue.VNode<vue.RendererNode, vue.RendererElement, {
            [key: string]: any;
        }>[];
        sources: () => vue.VNode<vue.RendererNode, vue.RendererElement, {
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
        src: string | srcObject;
        disabled: boolean;
        options: IntersectionObserverInit;
        inline: boolean;
        cover: boolean;
        tile: boolean;
        eager: boolean;
    } & {
        class?: any;
        value?: any;
        width?: string | number | undefined;
        height?: string | number | undefined;
        color?: string | undefined;
        crossorigin?: "" | "anonymous" | "use-credentials" | undefined;
        referrerpolicy?: "origin" | "no-referrer" | "no-referrer-when-downgrade" | "origin-when-cross-origin" | "same-origin" | "strict-origin" | "strict-origin-when-cross-origin" | "unsafe-url" | undefined;
        sizes?: string | undefined;
        transition?: string | boolean | undefined;
        position?: string | undefined;
        rounded?: string | number | boolean | undefined;
        contentClass?: any;
        maxHeight?: string | number | undefined;
        maxWidth?: string | number | undefined;
        minHeight?: string | number | undefined;
        minWidth?: string | number | undefined;
        aspectRatio?: string | number | undefined;
        alt?: string | undefined;
        draggable?: boolean | "false" | "true" | undefined;
        gradient?: string | undefined;
        lazySrc?: string | undefined;
        srcset?: string | undefined;
        selectedClass?: string | undefined;
        reverseTransition?: string | boolean | undefined;
    } & {
        $children?: vue.VNodeChild | (() => vue.VNodeChild) | {
            default?: (() => vue.VNodeChild) | undefined;
            placeholder?: (() => vue.VNodeChild) | undefined;
            error?: (() => vue.VNodeChild) | undefined;
            sources?: (() => vue.VNodeChild) | undefined;
        };
        'v-slots'?: {
            default?: false | (() => vue.VNodeChild) | undefined;
            placeholder?: false | (() => vue.VNodeChild) | undefined;
            error?: false | (() => vue.VNodeChild) | undefined;
            sources?: false | (() => vue.VNodeChild) | undefined;
        } | undefined;
    } & {
        "v-slot:default"?: false | (() => vue.VNodeChild) | undefined;
        "v-slot:placeholder"?: false | (() => vue.VNodeChild) | undefined;
        "v-slot:error"?: false | (() => vue.VNodeChild) | undefined;
        "v-slot:sources"?: false | (() => vue.VNodeChild) | undefined;
    }, {}, {}, {}, {}, {
        style: vue.StyleValue;
        src: string | srcObject;
        disabled: boolean;
        options: IntersectionObserverInit;
        transition: string | boolean;
        rounded: string | number | boolean;
        inline: boolean;
        cover: boolean;
        tile: boolean;
        draggable: boolean | "false" | "true";
        eager: boolean;
        reverseTransition: string | boolean;
    }>;
    __isFragment?: undefined;
    __isTeleport?: undefined;
    __isSuspense?: undefined;
} & vue.ComponentOptionsBase<{
    style: vue.StyleValue;
    src: string | srcObject;
    disabled: boolean;
    options: IntersectionObserverInit;
    inline: boolean;
    cover: boolean;
    tile: boolean;
    eager: boolean;
} & {
    class?: any;
    value?: any;
    width?: string | number | undefined;
    height?: string | number | undefined;
    color?: string | undefined;
    crossorigin?: "" | "anonymous" | "use-credentials" | undefined;
    referrerpolicy?: "origin" | "no-referrer" | "no-referrer-when-downgrade" | "origin-when-cross-origin" | "same-origin" | "strict-origin" | "strict-origin-when-cross-origin" | "unsafe-url" | undefined;
    sizes?: string | undefined;
    transition?: string | boolean | undefined;
    position?: string | undefined;
    rounded?: string | number | boolean | undefined;
    contentClass?: any;
    maxHeight?: string | number | undefined;
    maxWidth?: string | number | undefined;
    minHeight?: string | number | undefined;
    minWidth?: string | number | undefined;
    aspectRatio?: string | number | undefined;
    alt?: string | undefined;
    draggable?: boolean | "false" | "true" | undefined;
    gradient?: string | undefined;
    lazySrc?: string | undefined;
    srcset?: string | undefined;
    selectedClass?: string | undefined;
    reverseTransition?: string | boolean | undefined;
} & {
    $children?: vue.VNodeChild | (() => vue.VNodeChild) | {
        default?: (() => vue.VNodeChild) | undefined;
        placeholder?: (() => vue.VNodeChild) | undefined;
        error?: (() => vue.VNodeChild) | undefined;
        sources?: (() => vue.VNodeChild) | undefined;
    };
    'v-slots'?: {
        default?: false | (() => vue.VNodeChild) | undefined;
        placeholder?: false | (() => vue.VNodeChild) | undefined;
        error?: false | (() => vue.VNodeChild) | undefined;
        sources?: false | (() => vue.VNodeChild) | undefined;
    } | undefined;
} & {
    "v-slot:default"?: false | (() => vue.VNodeChild) | undefined;
    "v-slot:placeholder"?: false | (() => vue.VNodeChild) | undefined;
    "v-slot:error"?: false | (() => vue.VNodeChild) | undefined;
    "v-slot:sources"?: false | (() => vue.VNodeChild) | undefined;
}, void, unknown, {}, {}, vue.ComponentOptionsMixin, vue.ComponentOptionsMixin, Record<string, any>, string, {
    style: vue.StyleValue;
    src: string | srcObject;
    disabled: boolean;
    options: IntersectionObserverInit;
    transition: string | boolean;
    rounded: string | number | boolean;
    inline: boolean;
    cover: boolean;
    tile: boolean;
    draggable: boolean | "false" | "true";
    eager: boolean;
    reverseTransition: string | boolean;
}, {}, string, vue.SlotsType<Partial<{
    default: () => vue.VNode<vue.RendererNode, vue.RendererElement, {
        [key: string]: any;
    }>[];
    placeholder: () => vue.VNode<vue.RendererNode, vue.RendererElement, {
        [key: string]: any;
    }>[];
    error: () => vue.VNode<vue.RendererNode, vue.RendererElement, {
        [key: string]: any;
    }>[];
    sources: () => vue.VNode<vue.RendererNode, vue.RendererElement, {
        [key: string]: any;
    }>[];
}>>> & vue.VNodeProps & vue.AllowedComponentProps & vue.ComponentCustomProps & FilterPropsOptions<{
    eager: BooleanConstructor;
    value: null;
    disabled: BooleanConstructor;
    selectedClass: StringConstructor;
    class: vue.PropType<any>;
    style: {
        type: vue.PropType<vue.StyleValue>;
        default: null;
    };
    reverseTransition: {
        type: (StringConstructor | BooleanConstructor)[];
        default: undefined;
    };
    transition: {
        type: (StringConstructor | BooleanConstructor)[];
        default: undefined;
    };
    rounded: {
        type: (StringConstructor | NumberConstructor | BooleanConstructor)[];
        default: undefined;
    };
    tile: BooleanConstructor;
    height: (StringConstructor | NumberConstructor)[];
    maxHeight: (StringConstructor | NumberConstructor)[];
    maxWidth: (StringConstructor | NumberConstructor)[];
    minHeight: (StringConstructor | NumberConstructor)[];
    minWidth: (StringConstructor | NumberConstructor)[];
    width: (StringConstructor | NumberConstructor)[];
    aspectRatio: (StringConstructor | NumberConstructor)[];
    contentClass: null;
    inline: BooleanConstructor;
    alt: StringConstructor;
    cover: BooleanConstructor;
    color: StringConstructor;
    draggable: {
        type: vue.PropType<boolean | "false" | "true">;
        default: undefined;
    };
    gradient: StringConstructor;
    lazySrc: StringConstructor;
    options: {
        type: vue.PropType<IntersectionObserverInit>;
        default: () => {
            root: undefined;
            rootMargin: undefined;
            threshold: undefined;
        };
    };
    sizes: StringConstructor;
    src: {
        type: vue.PropType<string | srcObject>;
        default: string;
    };
    crossorigin: vue.PropType<"" | "anonymous" | "use-credentials">;
    referrerpolicy: vue.PropType<"origin" | "no-referrer" | "no-referrer-when-downgrade" | "origin-when-cross-origin" | "same-origin" | "strict-origin" | "strict-origin-when-cross-origin" | "unsafe-url">;
    srcset: StringConstructor;
    position: StringConstructor;
}, vue.ExtractPropTypes<{
    eager: BooleanConstructor;
    value: null;
    disabled: BooleanConstructor;
    selectedClass: StringConstructor;
    class: vue.PropType<any>;
    style: {
        type: vue.PropType<vue.StyleValue>;
        default: null;
    };
    reverseTransition: {
        type: (StringConstructor | BooleanConstructor)[];
        default: undefined;
    };
    transition: {
        type: (StringConstructor | BooleanConstructor)[];
        default: undefined;
    };
    rounded: {
        type: (StringConstructor | NumberConstructor | BooleanConstructor)[];
        default: undefined;
    };
    tile: BooleanConstructor;
    height: (StringConstructor | NumberConstructor)[];
    maxHeight: (StringConstructor | NumberConstructor)[];
    maxWidth: (StringConstructor | NumberConstructor)[];
    minHeight: (StringConstructor | NumberConstructor)[];
    minWidth: (StringConstructor | NumberConstructor)[];
    width: (StringConstructor | NumberConstructor)[];
    aspectRatio: (StringConstructor | NumberConstructor)[];
    contentClass: null;
    inline: BooleanConstructor;
    alt: StringConstructor;
    cover: BooleanConstructor;
    color: StringConstructor;
    draggable: {
        type: vue.PropType<boolean | "false" | "true">;
        default: undefined;
    };
    gradient: StringConstructor;
    lazySrc: StringConstructor;
    options: {
        type: vue.PropType<IntersectionObserverInit>;
        default: () => {
            root: undefined;
            rootMargin: undefined;
            threshold: undefined;
        };
    };
    sizes: StringConstructor;
    src: {
        type: vue.PropType<string | srcObject>;
        default: string;
    };
    crossorigin: vue.PropType<"" | "anonymous" | "use-credentials">;
    referrerpolicy: vue.PropType<"origin" | "no-referrer" | "no-referrer-when-downgrade" | "origin-when-cross-origin" | "same-origin" | "strict-origin" | "strict-origin-when-cross-origin" | "unsafe-url">;
    srcset: StringConstructor;
    position: StringConstructor;
}>>;
type VCarouselItem = InstanceType<typeof VCarouselItem>;

export { VCarousel, VCarouselItem };
