import * as vue from 'vue';
import { ComponentPropsOptions, ExtractPropTypes, PropType } from 'vue';

interface FilterPropsOptions<PropsOptions extends Readonly<ComponentPropsOptions>, Props = ExtractPropTypes<PropsOptions>> {
    filterProps<T extends Partial<Props>, U extends Exclude<keyof Props, Exclude<keyof Props, keyof T>>>(props: T): Partial<Pick<T, U>>;
}

interface srcObject {
    src?: string;
    srcset?: string;
    lazySrc?: string;
    aspect: number;
}
declare const VImg: {
    new (...args: any[]): vue.CreateComponentPublicInstance<{
        style: vue.StyleValue;
        src: string | srcObject;
        options: IntersectionObserverInit;
        transition: string | boolean | (vue.TransitionProps & {
            component?: vue.Component | undefined;
        });
        inline: boolean;
        cover: boolean;
        tile: boolean;
        eager: boolean;
    } & {
        class?: any;
        width?: string | number | undefined;
        height?: string | number | undefined;
        color?: string | undefined;
        crossorigin?: "" | "anonymous" | "use-credentials" | undefined;
        referrerpolicy?: "origin" | "no-referrer" | "no-referrer-when-downgrade" | "origin-when-cross-origin" | "same-origin" | "strict-origin" | "strict-origin-when-cross-origin" | "unsafe-url" | undefined;
        sizes?: string | undefined;
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
    } & {
        onError?: ((value: string | undefined) => any) | undefined;
        onLoad?: ((value: string | undefined) => any) | undefined;
        onLoadstart?: ((value: string | undefined) => any) | undefined;
    }, {
        currentSrc: vue.ShallowRef<string>;
        image: vue.Ref<HTMLImageElement | undefined>;
        state: vue.ShallowRef<"idle" | "error" | "loading" | "loaded">;
        naturalWidth: vue.ShallowRef<number | undefined>;
        naturalHeight: vue.ShallowRef<number | undefined>;
    }, unknown, {}, {}, vue.ComponentOptionsMixin, vue.ComponentOptionsMixin, {
        loadstart: (value: string | undefined) => true;
        load: (value: string | undefined) => true;
        error: (value: string | undefined) => true;
    }, vue.VNodeProps & vue.AllowedComponentProps & vue.ComponentCustomProps & {
        style: vue.StyleValue;
        src: string | srcObject;
        options: IntersectionObserverInit;
        transition: string | boolean | (vue.TransitionProps & {
            component?: vue.Component | undefined;
        });
        inline: boolean;
        cover: boolean;
        tile: boolean;
        eager: boolean;
    } & {
        class?: any;
        width?: string | number | undefined;
        height?: string | number | undefined;
        color?: string | undefined;
        crossorigin?: "" | "anonymous" | "use-credentials" | undefined;
        referrerpolicy?: "origin" | "no-referrer" | "no-referrer-when-downgrade" | "origin-when-cross-origin" | "same-origin" | "strict-origin" | "strict-origin-when-cross-origin" | "unsafe-url" | undefined;
        sizes?: string | undefined;
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
    } & {
        onError?: ((value: string | undefined) => any) | undefined;
        onLoad?: ((value: string | undefined) => any) | undefined;
        onLoadstart?: ((value: string | undefined) => any) | undefined;
    }, {
        style: vue.StyleValue;
        src: string | srcObject;
        options: IntersectionObserverInit;
        transition: string | boolean | (vue.TransitionProps & {
            component?: vue.Component | undefined;
        });
        rounded: string | number | boolean;
        inline: boolean;
        cover: boolean;
        tile: boolean;
        draggable: boolean | "false" | "true";
        eager: boolean;
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
        options: IntersectionObserverInit;
        transition: string | boolean | (vue.TransitionProps & {
            component?: vue.Component | undefined;
        });
        inline: boolean;
        cover: boolean;
        tile: boolean;
        eager: boolean;
    } & {
        class?: any;
        width?: string | number | undefined;
        height?: string | number | undefined;
        color?: string | undefined;
        crossorigin?: "" | "anonymous" | "use-credentials" | undefined;
        referrerpolicy?: "origin" | "no-referrer" | "no-referrer-when-downgrade" | "origin-when-cross-origin" | "same-origin" | "strict-origin" | "strict-origin-when-cross-origin" | "unsafe-url" | undefined;
        sizes?: string | undefined;
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
    } & {
        onError?: ((value: string | undefined) => any) | undefined;
        onLoad?: ((value: string | undefined) => any) | undefined;
        onLoadstart?: ((value: string | undefined) => any) | undefined;
    }, {
        currentSrc: vue.ShallowRef<string>;
        image: vue.Ref<HTMLImageElement | undefined>;
        state: vue.ShallowRef<"idle" | "error" | "loading" | "loaded">;
        naturalWidth: vue.ShallowRef<number | undefined>;
        naturalHeight: vue.ShallowRef<number | undefined>;
    }, {}, {}, {}, {
        style: vue.StyleValue;
        src: string | srcObject;
        options: IntersectionObserverInit;
        transition: string | boolean | (vue.TransitionProps & {
            component?: vue.Component | undefined;
        });
        rounded: string | number | boolean;
        inline: boolean;
        cover: boolean;
        tile: boolean;
        draggable: boolean | "false" | "true";
        eager: boolean;
    }>;
    __isFragment?: undefined;
    __isTeleport?: undefined;
    __isSuspense?: undefined;
} & vue.ComponentOptionsBase<{
    style: vue.StyleValue;
    src: string | srcObject;
    options: IntersectionObserverInit;
    transition: string | boolean | (vue.TransitionProps & {
        component?: vue.Component | undefined;
    });
    inline: boolean;
    cover: boolean;
    tile: boolean;
    eager: boolean;
} & {
    class?: any;
    width?: string | number | undefined;
    height?: string | number | undefined;
    color?: string | undefined;
    crossorigin?: "" | "anonymous" | "use-credentials" | undefined;
    referrerpolicy?: "origin" | "no-referrer" | "no-referrer-when-downgrade" | "origin-when-cross-origin" | "same-origin" | "strict-origin" | "strict-origin-when-cross-origin" | "unsafe-url" | undefined;
    sizes?: string | undefined;
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
} & {
    onError?: ((value: string | undefined) => any) | undefined;
    onLoad?: ((value: string | undefined) => any) | undefined;
    onLoadstart?: ((value: string | undefined) => any) | undefined;
}, {
    currentSrc: vue.ShallowRef<string>;
    image: vue.Ref<HTMLImageElement | undefined>;
    state: vue.ShallowRef<"idle" | "error" | "loading" | "loaded">;
    naturalWidth: vue.ShallowRef<number | undefined>;
    naturalHeight: vue.ShallowRef<number | undefined>;
}, unknown, {}, {}, vue.ComponentOptionsMixin, vue.ComponentOptionsMixin, {
    loadstart: (value: string | undefined) => true;
    load: (value: string | undefined) => true;
    error: (value: string | undefined) => true;
}, string, {
    style: vue.StyleValue;
    src: string | srcObject;
    options: IntersectionObserverInit;
    transition: string | boolean | (vue.TransitionProps & {
        component?: vue.Component | undefined;
    });
    rounded: string | number | boolean;
    inline: boolean;
    cover: boolean;
    tile: boolean;
    draggable: boolean | "false" | "true";
    eager: boolean;
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
    transition: {
        type: PropType<string | boolean | (vue.TransitionProps & {
            component?: vue.Component | undefined;
        })>;
        default: string;
        validator: (val: unknown) => boolean;
    };
    rounded: {
        type: (StringConstructor | NumberConstructor | BooleanConstructor)[];
        default: undefined;
    };
    tile: BooleanConstructor;
    class: PropType<any>;
    style: {
        type: PropType<vue.StyleValue>;
        default: null;
    };
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
        type: PropType<boolean | "false" | "true">;
        default: undefined;
    };
    eager: BooleanConstructor;
    gradient: StringConstructor;
    lazySrc: StringConstructor;
    options: {
        type: PropType<IntersectionObserverInit>;
        default: () => {
            root: undefined;
            rootMargin: undefined;
            threshold: undefined;
        };
    };
    sizes: StringConstructor;
    src: {
        type: PropType<string | srcObject>;
        default: string;
    };
    crossorigin: PropType<"" | "anonymous" | "use-credentials">;
    referrerpolicy: PropType<"origin" | "no-referrer" | "no-referrer-when-downgrade" | "origin-when-cross-origin" | "same-origin" | "strict-origin" | "strict-origin-when-cross-origin" | "unsafe-url">;
    srcset: StringConstructor;
    position: StringConstructor;
}, vue.ExtractPropTypes<{
    transition: {
        type: PropType<string | boolean | (vue.TransitionProps & {
            component?: vue.Component | undefined;
        })>;
        default: string;
        validator: (val: unknown) => boolean;
    };
    rounded: {
        type: (StringConstructor | NumberConstructor | BooleanConstructor)[];
        default: undefined;
    };
    tile: BooleanConstructor;
    class: PropType<any>;
    style: {
        type: PropType<vue.StyleValue>;
        default: null;
    };
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
        type: PropType<boolean | "false" | "true">;
        default: undefined;
    };
    eager: BooleanConstructor;
    gradient: StringConstructor;
    lazySrc: StringConstructor;
    options: {
        type: PropType<IntersectionObserverInit>;
        default: () => {
            root: undefined;
            rootMargin: undefined;
            threshold: undefined;
        };
    };
    sizes: StringConstructor;
    src: {
        type: PropType<string | srcObject>;
        default: string;
    };
    crossorigin: PropType<"" | "anonymous" | "use-credentials">;
    referrerpolicy: PropType<"origin" | "no-referrer" | "no-referrer-when-downgrade" | "origin-when-cross-origin" | "same-origin" | "strict-origin" | "strict-origin-when-cross-origin" | "unsafe-url">;
    srcset: StringConstructor;
    position: StringConstructor;
}>>;
type VImg = InstanceType<typeof VImg>;

export { VImg };
