import * as vue from 'vue';
import { ComponentPropsOptions, ExtractPropTypes, PropType, Prop } from 'vue';

interface FilterPropsOptions<PropsOptions extends Readonly<ComponentPropsOptions>, Props = ExtractPropTypes<PropsOptions>> {
    filterProps<T extends Partial<Props>, U extends Exclude<keyof Props, Exclude<keyof Props, keyof T>>>(props: T): Partial<Pick<T, U>>;
}

declare const VContainer: {
    new (...args: any[]): vue.CreateComponentPublicInstance<{
        style: vue.StyleValue;
        tag: string;
        fluid: boolean;
    } & {
        class?: any;
    } & {
        $children?: vue.VNodeChild | {
            default?: (() => vue.VNodeChild) | undefined;
        } | (() => vue.VNodeChild);
        'v-slots'?: {
            default?: false | (() => vue.VNodeChild) | undefined;
        } | undefined;
    } & {
        "v-slot:default"?: false | (() => vue.VNodeChild) | undefined;
    }, {}, unknown, {}, {}, vue.ComponentOptionsMixin, vue.ComponentOptionsMixin, Record<string, any>, vue.VNodeProps & vue.AllowedComponentProps & vue.ComponentCustomProps & {
        style: vue.StyleValue;
        tag: string;
        fluid: boolean;
    } & {
        class?: any;
    } & {
        $children?: vue.VNodeChild | {
            default?: (() => vue.VNodeChild) | undefined;
        } | (() => vue.VNodeChild);
        'v-slots'?: {
            default?: false | (() => vue.VNodeChild) | undefined;
        } | undefined;
    } & {
        "v-slot:default"?: false | (() => vue.VNodeChild) | undefined;
    }, {
        style: vue.StyleValue;
        tag: string;
        fluid: boolean;
    }, true, {}, vue.SlotsType<Partial<{
        default: () => vue.VNode<vue.RendererNode, vue.RendererElement, {
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
        tag: string;
        fluid: boolean;
    } & {
        class?: any;
    } & {
        $children?: vue.VNodeChild | {
            default?: (() => vue.VNodeChild) | undefined;
        } | (() => vue.VNodeChild);
        'v-slots'?: {
            default?: false | (() => vue.VNodeChild) | undefined;
        } | undefined;
    } & {
        "v-slot:default"?: false | (() => vue.VNodeChild) | undefined;
    }, {}, {}, {}, {}, {
        style: vue.StyleValue;
        tag: string;
        fluid: boolean;
    }>;
    __isFragment?: undefined;
    __isTeleport?: undefined;
    __isSuspense?: undefined;
} & vue.ComponentOptionsBase<{
    style: vue.StyleValue;
    tag: string;
    fluid: boolean;
} & {
    class?: any;
} & {
    $children?: vue.VNodeChild | {
        default?: (() => vue.VNodeChild) | undefined;
    } | (() => vue.VNodeChild);
    'v-slots'?: {
        default?: false | (() => vue.VNodeChild) | undefined;
    } | undefined;
} & {
    "v-slot:default"?: false | (() => vue.VNodeChild) | undefined;
}, {}, unknown, {}, {}, vue.ComponentOptionsMixin, vue.ComponentOptionsMixin, Record<string, any>, string, {
    style: vue.StyleValue;
    tag: string;
    fluid: boolean;
}, {}, string, vue.SlotsType<Partial<{
    default: () => vue.VNode<vue.RendererNode, vue.RendererElement, {
        [key: string]: any;
    }>[];
}>>> & vue.VNodeProps & vue.AllowedComponentProps & vue.ComponentCustomProps & FilterPropsOptions<{
    tag: {
        type: StringConstructor;
        default: string;
    };
    class: vue.PropType<any>;
    style: {
        type: vue.PropType<vue.StyleValue>;
        default: null;
    };
    fluid: {
        type: BooleanConstructor;
        default: boolean;
    };
}, vue.ExtractPropTypes<{
    tag: {
        type: StringConstructor;
        default: string;
    };
    class: vue.PropType<any>;
    style: {
        type: vue.PropType<vue.StyleValue>;
        default: null;
    };
    fluid: {
        type: BooleanConstructor;
        default: boolean;
    };
}>>;
type VContainer = InstanceType<typeof VContainer>;

declare const VCol: {
    new (...args: any[]): vue.CreateComponentPublicInstance<{
        style: vue.StyleValue;
        tag: string;
        offset: string | number;
        order: string | number;
        alignSelf: "end" | "center" | "start" | "auto" | "stretch" | "baseline";
        cols: string | number | boolean;
    } & {
        class?: any;
        sm?: string | number | boolean | undefined;
        md?: string | number | boolean | undefined;
        lg?: string | number | boolean | undefined;
        xl?: string | number | boolean | undefined;
        xxl?: string | number | boolean | undefined;
        offsetSm?: string | number | undefined;
        offsetMd?: string | number | undefined;
        offsetLg?: string | number | undefined;
        offsetXl?: string | number | undefined;
        offsetXxl?: string | number | undefined;
        orderSm?: string | number | undefined;
        orderMd?: string | number | undefined;
        orderLg?: string | number | undefined;
        orderXl?: string | number | undefined;
        orderXxl?: string | number | undefined;
    } & {
        $children?: vue.VNodeChild | {
            default?: (() => vue.VNodeChild) | undefined;
        } | (() => vue.VNodeChild);
        'v-slots'?: {
            default?: false | (() => vue.VNodeChild) | undefined;
        } | undefined;
    } & {
        "v-slot:default"?: false | (() => vue.VNodeChild) | undefined;
    }, () => vue.VNode<vue.RendererNode, vue.RendererElement, {
        [key: string]: any;
    }>, unknown, {}, {}, vue.ComponentOptionsMixin, vue.ComponentOptionsMixin, Record<string, any>, vue.VNodeProps & vue.AllowedComponentProps & vue.ComponentCustomProps & {
        style: vue.StyleValue;
        tag: string;
        offset: string | number;
        order: string | number;
        alignSelf: "end" | "center" | "start" | "auto" | "stretch" | "baseline";
        cols: string | number | boolean;
    } & {
        class?: any;
        sm?: string | number | boolean | undefined;
        md?: string | number | boolean | undefined;
        lg?: string | number | boolean | undefined;
        xl?: string | number | boolean | undefined;
        xxl?: string | number | boolean | undefined;
        offsetSm?: string | number | undefined;
        offsetMd?: string | number | undefined;
        offsetLg?: string | number | undefined;
        offsetXl?: string | number | undefined;
        offsetXxl?: string | number | undefined;
        orderSm?: string | number | undefined;
        orderMd?: string | number | undefined;
        orderLg?: string | number | undefined;
        orderXl?: string | number | undefined;
        orderXxl?: string | number | undefined;
    } & {
        $children?: vue.VNodeChild | {
            default?: (() => vue.VNodeChild) | undefined;
        } | (() => vue.VNodeChild);
        'v-slots'?: {
            default?: false | (() => vue.VNodeChild) | undefined;
        } | undefined;
    } & {
        "v-slot:default"?: false | (() => vue.VNodeChild) | undefined;
    }, {
        style: vue.StyleValue;
        tag: string;
        offset: string | number;
        order: string | number;
        alignSelf: "end" | "center" | "start" | "auto" | "stretch" | "baseline";
        cols: string | number | boolean;
    }, true, {}, vue.SlotsType<Partial<{
        default: () => vue.VNode<vue.RendererNode, vue.RendererElement, {
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
        tag: string;
        offset: string | number;
        order: string | number;
        alignSelf: "end" | "center" | "start" | "auto" | "stretch" | "baseline";
        cols: string | number | boolean;
    } & {
        class?: any;
        sm?: string | number | boolean | undefined;
        md?: string | number | boolean | undefined;
        lg?: string | number | boolean | undefined;
        xl?: string | number | boolean | undefined;
        xxl?: string | number | boolean | undefined;
        offsetSm?: string | number | undefined;
        offsetMd?: string | number | undefined;
        offsetLg?: string | number | undefined;
        offsetXl?: string | number | undefined;
        offsetXxl?: string | number | undefined;
        orderSm?: string | number | undefined;
        orderMd?: string | number | undefined;
        orderLg?: string | number | undefined;
        orderXl?: string | number | undefined;
        orderXxl?: string | number | undefined;
    } & {
        $children?: vue.VNodeChild | {
            default?: (() => vue.VNodeChild) | undefined;
        } | (() => vue.VNodeChild);
        'v-slots'?: {
            default?: false | (() => vue.VNodeChild) | undefined;
        } | undefined;
    } & {
        "v-slot:default"?: false | (() => vue.VNodeChild) | undefined;
    }, () => vue.VNode<vue.RendererNode, vue.RendererElement, {
        [key: string]: any;
    }>, {}, {}, {}, {
        style: vue.StyleValue;
        tag: string;
        offset: string | number;
        order: string | number;
        alignSelf: "end" | "center" | "start" | "auto" | "stretch" | "baseline";
        cols: string | number | boolean;
    }>;
    __isFragment?: undefined;
    __isTeleport?: undefined;
    __isSuspense?: undefined;
} & vue.ComponentOptionsBase<{
    style: vue.StyleValue;
    tag: string;
    offset: string | number;
    order: string | number;
    alignSelf: "end" | "center" | "start" | "auto" | "stretch" | "baseline";
    cols: string | number | boolean;
} & {
    class?: any;
    sm?: string | number | boolean | undefined;
    md?: string | number | boolean | undefined;
    lg?: string | number | boolean | undefined;
    xl?: string | number | boolean | undefined;
    xxl?: string | number | boolean | undefined;
    offsetSm?: string | number | undefined;
    offsetMd?: string | number | undefined;
    offsetLg?: string | number | undefined;
    offsetXl?: string | number | undefined;
    offsetXxl?: string | number | undefined;
    orderSm?: string | number | undefined;
    orderMd?: string | number | undefined;
    orderLg?: string | number | undefined;
    orderXl?: string | number | undefined;
    orderXxl?: string | number | undefined;
} & {
    $children?: vue.VNodeChild | {
        default?: (() => vue.VNodeChild) | undefined;
    } | (() => vue.VNodeChild);
    'v-slots'?: {
        default?: false | (() => vue.VNodeChild) | undefined;
    } | undefined;
} & {
    "v-slot:default"?: false | (() => vue.VNodeChild) | undefined;
}, () => vue.VNode<vue.RendererNode, vue.RendererElement, {
    [key: string]: any;
}>, unknown, {}, {}, vue.ComponentOptionsMixin, vue.ComponentOptionsMixin, Record<string, any>, string, {
    style: vue.StyleValue;
    tag: string;
    offset: string | number;
    order: string | number;
    alignSelf: "end" | "center" | "start" | "auto" | "stretch" | "baseline";
    cols: string | number | boolean;
}, {}, string, vue.SlotsType<Partial<{
    default: () => vue.VNode<vue.RendererNode, vue.RendererElement, {
        [key: string]: any;
    }>[];
}>>> & vue.VNodeProps & vue.AllowedComponentProps & vue.ComponentCustomProps & FilterPropsOptions<{
    tag: {
        type: StringConstructor;
        default: string;
    };
    class: PropType<any>;
    style: {
        type: PropType<vue.StyleValue>;
        default: null;
    };
    alignSelf: {
        type: PropType<"end" | "center" | "start" | "auto" | "stretch" | "baseline">;
        default: null;
        validator: (str: any) => boolean;
    };
    orderSm: Prop<string | number, null>;
    orderMd: Prop<string | number, null>;
    orderLg: Prop<string | number, null>;
    orderXl: Prop<string | number, null>;
    orderXxl: Prop<string | number, null>;
    order: {
        type: (StringConstructor | NumberConstructor)[];
        default: null;
    };
    offsetSm: Prop<string | number, null>;
    offsetMd: Prop<string | number, null>;
    offsetLg: Prop<string | number, null>;
    offsetXl: Prop<string | number, null>;
    offsetXxl: Prop<string | number, null>;
    offset: {
        type: (StringConstructor | NumberConstructor)[];
        default: null;
    };
    sm: Prop<string | number | boolean, false>;
    md: Prop<string | number | boolean, false>;
    lg: Prop<string | number | boolean, false>;
    xl: Prop<string | number | boolean, false>;
    xxl: Prop<string | number | boolean, false>;
    cols: {
        type: (StringConstructor | NumberConstructor | BooleanConstructor)[];
        default: boolean;
    };
}, vue.ExtractPropTypes<{
    tag: {
        type: StringConstructor;
        default: string;
    };
    class: PropType<any>;
    style: {
        type: PropType<vue.StyleValue>;
        default: null;
    };
    alignSelf: {
        type: PropType<"end" | "center" | "start" | "auto" | "stretch" | "baseline">;
        default: null;
        validator: (str: any) => boolean;
    };
    orderSm: Prop<string | number, null>;
    orderMd: Prop<string | number, null>;
    orderLg: Prop<string | number, null>;
    orderXl: Prop<string | number, null>;
    orderXxl: Prop<string | number, null>;
    order: {
        type: (StringConstructor | NumberConstructor)[];
        default: null;
    };
    offsetSm: Prop<string | number, null>;
    offsetMd: Prop<string | number, null>;
    offsetLg: Prop<string | number, null>;
    offsetXl: Prop<string | number, null>;
    offsetXxl: Prop<string | number, null>;
    offset: {
        type: (StringConstructor | NumberConstructor)[];
        default: null;
    };
    sm: Prop<string | number | boolean, false>;
    md: Prop<string | number | boolean, false>;
    lg: Prop<string | number | boolean, false>;
    xl: Prop<string | number | boolean, false>;
    xxl: Prop<string | number | boolean, false>;
    cols: {
        type: (StringConstructor | NumberConstructor | BooleanConstructor)[];
        default: boolean;
    };
}>>;
type VCol = InstanceType<typeof VCol>;

declare const VRow: {
    new (...args: any[]): vue.CreateComponentPublicInstance<{
        style: vue.StyleValue;
        align: "end" | "center" | "start" | "stretch" | "baseline";
        tag: string;
        dense: boolean;
        justify: "end" | "center" | "start" | "space-around" | "space-between" | "space-evenly" | "stretch";
        alignContent: "end" | "center" | "start" | "space-around" | "space-between" | "space-evenly" | "stretch";
        noGutters: boolean;
    } & {
        class?: any;
        alignSm?: "end" | "center" | "start" | "stretch" | "baseline" | undefined;
        alignMd?: "end" | "center" | "start" | "stretch" | "baseline" | undefined;
        alignLg?: "end" | "center" | "start" | "stretch" | "baseline" | undefined;
        alignXl?: "end" | "center" | "start" | "stretch" | "baseline" | undefined;
        alignXxl?: "end" | "center" | "start" | "stretch" | "baseline" | undefined;
        justifySm?: "end" | "center" | "start" | "space-around" | "space-between" | "space-evenly" | undefined;
        justifyMd?: "end" | "center" | "start" | "space-around" | "space-between" | "space-evenly" | undefined;
        justifyLg?: "end" | "center" | "start" | "space-around" | "space-between" | "space-evenly" | undefined;
        justifyXl?: "end" | "center" | "start" | "space-around" | "space-between" | "space-evenly" | undefined;
        justifyXxl?: "end" | "center" | "start" | "space-around" | "space-between" | "space-evenly" | undefined;
        alignContentSm?: "end" | "center" | "start" | "space-around" | "space-between" | "space-evenly" | "stretch" | undefined;
        alignContentMd?: "end" | "center" | "start" | "space-around" | "space-between" | "space-evenly" | "stretch" | undefined;
        alignContentLg?: "end" | "center" | "start" | "space-around" | "space-between" | "space-evenly" | "stretch" | undefined;
        alignContentXl?: "end" | "center" | "start" | "space-around" | "space-between" | "space-evenly" | "stretch" | undefined;
        alignContentXxl?: "end" | "center" | "start" | "space-around" | "space-between" | "space-evenly" | "stretch" | undefined;
    } & {
        $children?: vue.VNodeChild | {
            default?: (() => vue.VNodeChild) | undefined;
        } | (() => vue.VNodeChild);
        'v-slots'?: {
            default?: false | (() => vue.VNodeChild) | undefined;
        } | undefined;
    } & {
        "v-slot:default"?: false | (() => vue.VNodeChild) | undefined;
    }, () => vue.VNode<vue.RendererNode, vue.RendererElement, {
        [key: string]: any;
    }>, unknown, {}, {}, vue.ComponentOptionsMixin, vue.ComponentOptionsMixin, Record<string, any>, vue.VNodeProps & vue.AllowedComponentProps & vue.ComponentCustomProps & {
        style: vue.StyleValue;
        align: "end" | "center" | "start" | "stretch" | "baseline";
        tag: string;
        dense: boolean;
        justify: "end" | "center" | "start" | "space-around" | "space-between" | "space-evenly" | "stretch";
        alignContent: "end" | "center" | "start" | "space-around" | "space-between" | "space-evenly" | "stretch";
        noGutters: boolean;
    } & {
        class?: any;
        alignSm?: "end" | "center" | "start" | "stretch" | "baseline" | undefined;
        alignMd?: "end" | "center" | "start" | "stretch" | "baseline" | undefined;
        alignLg?: "end" | "center" | "start" | "stretch" | "baseline" | undefined;
        alignXl?: "end" | "center" | "start" | "stretch" | "baseline" | undefined;
        alignXxl?: "end" | "center" | "start" | "stretch" | "baseline" | undefined;
        justifySm?: "end" | "center" | "start" | "space-around" | "space-between" | "space-evenly" | undefined;
        justifyMd?: "end" | "center" | "start" | "space-around" | "space-between" | "space-evenly" | undefined;
        justifyLg?: "end" | "center" | "start" | "space-around" | "space-between" | "space-evenly" | undefined;
        justifyXl?: "end" | "center" | "start" | "space-around" | "space-between" | "space-evenly" | undefined;
        justifyXxl?: "end" | "center" | "start" | "space-around" | "space-between" | "space-evenly" | undefined;
        alignContentSm?: "end" | "center" | "start" | "space-around" | "space-between" | "space-evenly" | "stretch" | undefined;
        alignContentMd?: "end" | "center" | "start" | "space-around" | "space-between" | "space-evenly" | "stretch" | undefined;
        alignContentLg?: "end" | "center" | "start" | "space-around" | "space-between" | "space-evenly" | "stretch" | undefined;
        alignContentXl?: "end" | "center" | "start" | "space-around" | "space-between" | "space-evenly" | "stretch" | undefined;
        alignContentXxl?: "end" | "center" | "start" | "space-around" | "space-between" | "space-evenly" | "stretch" | undefined;
    } & {
        $children?: vue.VNodeChild | {
            default?: (() => vue.VNodeChild) | undefined;
        } | (() => vue.VNodeChild);
        'v-slots'?: {
            default?: false | (() => vue.VNodeChild) | undefined;
        } | undefined;
    } & {
        "v-slot:default"?: false | (() => vue.VNodeChild) | undefined;
    }, {
        style: vue.StyleValue;
        align: "end" | "center" | "start" | "stretch" | "baseline";
        tag: string;
        dense: boolean;
        justify: "end" | "center" | "start" | "space-around" | "space-between" | "space-evenly" | "stretch";
        alignContent: "end" | "center" | "start" | "space-around" | "space-between" | "space-evenly" | "stretch";
        noGutters: boolean;
    }, true, {}, vue.SlotsType<Partial<{
        default: () => vue.VNode<vue.RendererNode, vue.RendererElement, {
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
        align: "end" | "center" | "start" | "stretch" | "baseline";
        tag: string;
        dense: boolean;
        justify: "end" | "center" | "start" | "space-around" | "space-between" | "space-evenly" | "stretch";
        alignContent: "end" | "center" | "start" | "space-around" | "space-between" | "space-evenly" | "stretch";
        noGutters: boolean;
    } & {
        class?: any;
        alignSm?: "end" | "center" | "start" | "stretch" | "baseline" | undefined;
        alignMd?: "end" | "center" | "start" | "stretch" | "baseline" | undefined;
        alignLg?: "end" | "center" | "start" | "stretch" | "baseline" | undefined;
        alignXl?: "end" | "center" | "start" | "stretch" | "baseline" | undefined;
        alignXxl?: "end" | "center" | "start" | "stretch" | "baseline" | undefined;
        justifySm?: "end" | "center" | "start" | "space-around" | "space-between" | "space-evenly" | undefined;
        justifyMd?: "end" | "center" | "start" | "space-around" | "space-between" | "space-evenly" | undefined;
        justifyLg?: "end" | "center" | "start" | "space-around" | "space-between" | "space-evenly" | undefined;
        justifyXl?: "end" | "center" | "start" | "space-around" | "space-between" | "space-evenly" | undefined;
        justifyXxl?: "end" | "center" | "start" | "space-around" | "space-between" | "space-evenly" | undefined;
        alignContentSm?: "end" | "center" | "start" | "space-around" | "space-between" | "space-evenly" | "stretch" | undefined;
        alignContentMd?: "end" | "center" | "start" | "space-around" | "space-between" | "space-evenly" | "stretch" | undefined;
        alignContentLg?: "end" | "center" | "start" | "space-around" | "space-between" | "space-evenly" | "stretch" | undefined;
        alignContentXl?: "end" | "center" | "start" | "space-around" | "space-between" | "space-evenly" | "stretch" | undefined;
        alignContentXxl?: "end" | "center" | "start" | "space-around" | "space-between" | "space-evenly" | "stretch" | undefined;
    } & {
        $children?: vue.VNodeChild | {
            default?: (() => vue.VNodeChild) | undefined;
        } | (() => vue.VNodeChild);
        'v-slots'?: {
            default?: false | (() => vue.VNodeChild) | undefined;
        } | undefined;
    } & {
        "v-slot:default"?: false | (() => vue.VNodeChild) | undefined;
    }, () => vue.VNode<vue.RendererNode, vue.RendererElement, {
        [key: string]: any;
    }>, {}, {}, {}, {
        style: vue.StyleValue;
        align: "end" | "center" | "start" | "stretch" | "baseline";
        tag: string;
        dense: boolean;
        justify: "end" | "center" | "start" | "space-around" | "space-between" | "space-evenly" | "stretch";
        alignContent: "end" | "center" | "start" | "space-around" | "space-between" | "space-evenly" | "stretch";
        noGutters: boolean;
    }>;
    __isFragment?: undefined;
    __isTeleport?: undefined;
    __isSuspense?: undefined;
} & vue.ComponentOptionsBase<{
    style: vue.StyleValue;
    align: "end" | "center" | "start" | "stretch" | "baseline";
    tag: string;
    dense: boolean;
    justify: "end" | "center" | "start" | "space-around" | "space-between" | "space-evenly" | "stretch";
    alignContent: "end" | "center" | "start" | "space-around" | "space-between" | "space-evenly" | "stretch";
    noGutters: boolean;
} & {
    class?: any;
    alignSm?: "end" | "center" | "start" | "stretch" | "baseline" | undefined;
    alignMd?: "end" | "center" | "start" | "stretch" | "baseline" | undefined;
    alignLg?: "end" | "center" | "start" | "stretch" | "baseline" | undefined;
    alignXl?: "end" | "center" | "start" | "stretch" | "baseline" | undefined;
    alignXxl?: "end" | "center" | "start" | "stretch" | "baseline" | undefined;
    justifySm?: "end" | "center" | "start" | "space-around" | "space-between" | "space-evenly" | undefined;
    justifyMd?: "end" | "center" | "start" | "space-around" | "space-between" | "space-evenly" | undefined;
    justifyLg?: "end" | "center" | "start" | "space-around" | "space-between" | "space-evenly" | undefined;
    justifyXl?: "end" | "center" | "start" | "space-around" | "space-between" | "space-evenly" | undefined;
    justifyXxl?: "end" | "center" | "start" | "space-around" | "space-between" | "space-evenly" | undefined;
    alignContentSm?: "end" | "center" | "start" | "space-around" | "space-between" | "space-evenly" | "stretch" | undefined;
    alignContentMd?: "end" | "center" | "start" | "space-around" | "space-between" | "space-evenly" | "stretch" | undefined;
    alignContentLg?: "end" | "center" | "start" | "space-around" | "space-between" | "space-evenly" | "stretch" | undefined;
    alignContentXl?: "end" | "center" | "start" | "space-around" | "space-between" | "space-evenly" | "stretch" | undefined;
    alignContentXxl?: "end" | "center" | "start" | "space-around" | "space-between" | "space-evenly" | "stretch" | undefined;
} & {
    $children?: vue.VNodeChild | {
        default?: (() => vue.VNodeChild) | undefined;
    } | (() => vue.VNodeChild);
    'v-slots'?: {
        default?: false | (() => vue.VNodeChild) | undefined;
    } | undefined;
} & {
    "v-slot:default"?: false | (() => vue.VNodeChild) | undefined;
}, () => vue.VNode<vue.RendererNode, vue.RendererElement, {
    [key: string]: any;
}>, unknown, {}, {}, vue.ComponentOptionsMixin, vue.ComponentOptionsMixin, Record<string, any>, string, {
    style: vue.StyleValue;
    align: "end" | "center" | "start" | "stretch" | "baseline";
    tag: string;
    dense: boolean;
    justify: "end" | "center" | "start" | "space-around" | "space-between" | "space-evenly" | "stretch";
    alignContent: "end" | "center" | "start" | "space-around" | "space-between" | "space-evenly" | "stretch";
    noGutters: boolean;
}, {}, string, vue.SlotsType<Partial<{
    default: () => vue.VNode<vue.RendererNode, vue.RendererElement, {
        [key: string]: any;
    }>[];
}>>> & vue.VNodeProps & vue.AllowedComponentProps & vue.ComponentCustomProps & FilterPropsOptions<{
    tag: {
        type: StringConstructor;
        default: string;
    };
    class: PropType<any>;
    style: {
        type: PropType<vue.StyleValue>;
        default: null;
    };
    alignContentSm: Prop<"end" | "center" | "start" | "space-around" | "space-between" | "space-evenly" | "stretch", null>;
    alignContentMd: Prop<"end" | "center" | "start" | "space-around" | "space-between" | "space-evenly" | "stretch", null>;
    alignContentLg: Prop<"end" | "center" | "start" | "space-around" | "space-between" | "space-evenly" | "stretch", null>;
    alignContentXl: Prop<"end" | "center" | "start" | "space-around" | "space-between" | "space-evenly" | "stretch", null>;
    alignContentXxl: Prop<"end" | "center" | "start" | "space-around" | "space-between" | "space-evenly" | "stretch", null>;
    alignContent: {
        type: PropType<"end" | "center" | "start" | "space-around" | "space-between" | "space-evenly" | "stretch">;
        default: null;
        validator: (str: any) => boolean;
    };
    justifySm: Prop<"end" | "center" | "start" | "space-around" | "space-between" | "space-evenly", null>;
    justifyMd: Prop<"end" | "center" | "start" | "space-around" | "space-between" | "space-evenly", null>;
    justifyLg: Prop<"end" | "center" | "start" | "space-around" | "space-between" | "space-evenly", null>;
    justifyXl: Prop<"end" | "center" | "start" | "space-around" | "space-between" | "space-evenly", null>;
    justifyXxl: Prop<"end" | "center" | "start" | "space-around" | "space-between" | "space-evenly", null>;
    justify: {
        type: PropType<"end" | "center" | "start" | "space-around" | "space-between" | "space-evenly" | "stretch">;
        default: null;
        validator: (str: any) => boolean;
    };
    alignSm: Prop<"end" | "center" | "start" | "stretch" | "baseline", null>;
    alignMd: Prop<"end" | "center" | "start" | "stretch" | "baseline", null>;
    alignLg: Prop<"end" | "center" | "start" | "stretch" | "baseline", null>;
    alignXl: Prop<"end" | "center" | "start" | "stretch" | "baseline", null>;
    alignXxl: Prop<"end" | "center" | "start" | "stretch" | "baseline", null>;
    dense: BooleanConstructor;
    noGutters: BooleanConstructor;
    align: {
        type: PropType<"end" | "center" | "start" | "stretch" | "baseline">;
        default: null;
        validator: (str: any) => boolean;
    };
}, vue.ExtractPropTypes<{
    tag: {
        type: StringConstructor;
        default: string;
    };
    class: PropType<any>;
    style: {
        type: PropType<vue.StyleValue>;
        default: null;
    };
    alignContentSm: Prop<"end" | "center" | "start" | "space-around" | "space-between" | "space-evenly" | "stretch", null>;
    alignContentMd: Prop<"end" | "center" | "start" | "space-around" | "space-between" | "space-evenly" | "stretch", null>;
    alignContentLg: Prop<"end" | "center" | "start" | "space-around" | "space-between" | "space-evenly" | "stretch", null>;
    alignContentXl: Prop<"end" | "center" | "start" | "space-around" | "space-between" | "space-evenly" | "stretch", null>;
    alignContentXxl: Prop<"end" | "center" | "start" | "space-around" | "space-between" | "space-evenly" | "stretch", null>;
    alignContent: {
        type: PropType<"end" | "center" | "start" | "space-around" | "space-between" | "space-evenly" | "stretch">;
        default: null;
        validator: (str: any) => boolean;
    };
    justifySm: Prop<"end" | "center" | "start" | "space-around" | "space-between" | "space-evenly", null>;
    justifyMd: Prop<"end" | "center" | "start" | "space-around" | "space-between" | "space-evenly", null>;
    justifyLg: Prop<"end" | "center" | "start" | "space-around" | "space-between" | "space-evenly", null>;
    justifyXl: Prop<"end" | "center" | "start" | "space-around" | "space-between" | "space-evenly", null>;
    justifyXxl: Prop<"end" | "center" | "start" | "space-around" | "space-between" | "space-evenly", null>;
    justify: {
        type: PropType<"end" | "center" | "start" | "space-around" | "space-between" | "space-evenly" | "stretch">;
        default: null;
        validator: (str: any) => boolean;
    };
    alignSm: Prop<"end" | "center" | "start" | "stretch" | "baseline", null>;
    alignMd: Prop<"end" | "center" | "start" | "stretch" | "baseline", null>;
    alignLg: Prop<"end" | "center" | "start" | "stretch" | "baseline", null>;
    alignXl: Prop<"end" | "center" | "start" | "stretch" | "baseline", null>;
    alignXxl: Prop<"end" | "center" | "start" | "stretch" | "baseline", null>;
    dense: BooleanConstructor;
    noGutters: BooleanConstructor;
    align: {
        type: PropType<"end" | "center" | "start" | "stretch" | "baseline">;
        default: null;
        validator: (str: any) => boolean;
    };
}>>;
type VRow = InstanceType<typeof VRow>;

declare const VSpacer: {
    new (...args: any[]): vue.CreateComponentPublicInstance<{
        style: vue.StyleValue;
        tag: string;
    } & {
        class?: any;
    } & {
        $children?: vue.VNodeChild | {
            default?: (() => vue.VNodeChild) | undefined;
        } | (() => vue.VNodeChild);
        'v-slots'?: {
            default?: false | (() => vue.VNodeChild) | undefined;
        } | undefined;
    } & {
        "v-slot:default"?: false | (() => vue.VNodeChild) | undefined;
    }, () => vue.VNode<vue.RendererNode, vue.RendererElement, {
        [key: string]: any;
    }>, unknown, {}, {}, vue.ComponentOptionsMixin, vue.ComponentOptionsMixin, Record<string, any>, vue.VNodeProps & vue.AllowedComponentProps & vue.ComponentCustomProps & {
        style: vue.StyleValue;
        tag: string;
    } & {
        class?: any;
    } & {
        $children?: vue.VNodeChild | {
            default?: (() => vue.VNodeChild) | undefined;
        } | (() => vue.VNodeChild);
        'v-slots'?: {
            default?: false | (() => vue.VNodeChild) | undefined;
        } | undefined;
    } & {
        "v-slot:default"?: false | (() => vue.VNodeChild) | undefined;
    }, {
        style: vue.StyleValue;
        tag: string;
    }, true, {}, vue.SlotsType<Partial<{
        default: () => vue.VNode<vue.RendererNode, vue.RendererElement, {
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
        tag: string;
    } & {
        class?: any;
    } & {
        $children?: vue.VNodeChild | {
            default?: (() => vue.VNodeChild) | undefined;
        } | (() => vue.VNodeChild);
        'v-slots'?: {
            default?: false | (() => vue.VNodeChild) | undefined;
        } | undefined;
    } & {
        "v-slot:default"?: false | (() => vue.VNodeChild) | undefined;
    }, () => vue.VNode<vue.RendererNode, vue.RendererElement, {
        [key: string]: any;
    }>, {}, {}, {}, {
        style: vue.StyleValue;
        tag: string;
    }>;
    __isFragment?: undefined;
    __isTeleport?: undefined;
    __isSuspense?: undefined;
} & vue.ComponentOptionsBase<{
    style: vue.StyleValue;
    tag: string;
} & {
    class?: any;
} & {
    $children?: vue.VNodeChild | {
        default?: (() => vue.VNodeChild) | undefined;
    } | (() => vue.VNodeChild);
    'v-slots'?: {
        default?: false | (() => vue.VNodeChild) | undefined;
    } | undefined;
} & {
    "v-slot:default"?: false | (() => vue.VNodeChild) | undefined;
}, () => vue.VNode<vue.RendererNode, vue.RendererElement, {
    [key: string]: any;
}>, unknown, {}, {}, vue.ComponentOptionsMixin, vue.ComponentOptionsMixin, Record<string, any>, string, {
    style: vue.StyleValue;
    tag: string;
}, {}, string, vue.SlotsType<Partial<{
    default: () => vue.VNode<vue.RendererNode, vue.RendererElement, {
        [key: string]: any;
    }>[];
}>>> & vue.VNodeProps & vue.AllowedComponentProps & vue.ComponentCustomProps & FilterPropsOptions<{
    class: vue.PropType<any>;
    style: {
        type: vue.PropType<vue.StyleValue>;
        default: null;
    };
    tag: {
        type: StringConstructor;
        default: string;
    };
}, vue.ExtractPropTypes<{
    class: vue.PropType<any>;
    style: {
        type: vue.PropType<vue.StyleValue>;
        default: null;
    };
    tag: {
        type: StringConstructor;
        default: string;
    };
}>>;
type VSpacer = InstanceType<typeof VSpacer>;

export { VCol, VContainer, VRow, VSpacer };
