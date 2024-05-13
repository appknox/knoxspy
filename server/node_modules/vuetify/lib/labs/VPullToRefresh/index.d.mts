import * as vue from 'vue';
import { ComponentPropsOptions, ExtractPropTypes } from 'vue';

interface FilterPropsOptions<PropsOptions extends Readonly<ComponentPropsOptions>, Props = ExtractPropTypes<PropsOptions>> {
    filterProps<T extends Partial<Props>, U extends Exclude<keyof Props, Exclude<keyof Props, keyof T>>>(props: T): Partial<Pick<T, U>>;
}

declare const VPullToRefresh: {
    new (...args: any[]): vue.CreateComponentPublicInstance<{
        pullDownThreshold: number;
    } & {} & {
        $children?: vue.VNodeChild | (() => vue.VNodeChild) | {
            default?: (() => vue.VNodeChild) | undefined;
            pullDownPanel?: ((arg: {
                canRefresh: boolean;
                goingUp: boolean;
                refreshing: boolean;
            }) => vue.VNodeChild) | undefined;
        };
        'v-slots'?: {
            default?: false | (() => vue.VNodeChild) | undefined;
            pullDownPanel?: false | ((arg: {
                canRefresh: boolean;
                goingUp: boolean;
                refreshing: boolean;
            }) => vue.VNodeChild) | undefined;
        } | undefined;
    } & {
        "v-slot:default"?: false | (() => vue.VNodeChild) | undefined;
        "v-slot:pullDownPanel"?: false | ((arg: {
            canRefresh: boolean;
            goingUp: boolean;
            refreshing: boolean;
        }) => vue.VNodeChild) | undefined;
    } & {
        onLoad?: ((options: {
            done: () => void;
        }) => any) | undefined;
    }, void, unknown, {}, {}, vue.ComponentOptionsMixin, vue.ComponentOptionsMixin, {
        load: (options: {
            done: () => void;
        }) => true;
    }, vue.VNodeProps & vue.AllowedComponentProps & vue.ComponentCustomProps & {
        pullDownThreshold: number;
    } & {} & {
        $children?: vue.VNodeChild | (() => vue.VNodeChild) | {
            default?: (() => vue.VNodeChild) | undefined;
            pullDownPanel?: ((arg: {
                canRefresh: boolean;
                goingUp: boolean;
                refreshing: boolean;
            }) => vue.VNodeChild) | undefined;
        };
        'v-slots'?: {
            default?: false | (() => vue.VNodeChild) | undefined;
            pullDownPanel?: false | ((arg: {
                canRefresh: boolean;
                goingUp: boolean;
                refreshing: boolean;
            }) => vue.VNodeChild) | undefined;
        } | undefined;
    } & {
        "v-slot:default"?: false | (() => vue.VNodeChild) | undefined;
        "v-slot:pullDownPanel"?: false | ((arg: {
            canRefresh: boolean;
            goingUp: boolean;
            refreshing: boolean;
        }) => vue.VNodeChild) | undefined;
    } & {
        onLoad?: ((options: {
            done: () => void;
        }) => any) | undefined;
    }, {
        pullDownThreshold: number;
    }, true, {}, vue.SlotsType<Partial<{
        default: () => vue.VNode<vue.RendererNode, vue.RendererElement, {
            [key: string]: any;
        }>[];
        pullDownPanel: (arg: {
            canRefresh: boolean;
            goingUp: boolean;
            refreshing: boolean;
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
        pullDownThreshold: number;
    } & {} & {
        $children?: vue.VNodeChild | (() => vue.VNodeChild) | {
            default?: (() => vue.VNodeChild) | undefined;
            pullDownPanel?: ((arg: {
                canRefresh: boolean;
                goingUp: boolean;
                refreshing: boolean;
            }) => vue.VNodeChild) | undefined;
        };
        'v-slots'?: {
            default?: false | (() => vue.VNodeChild) | undefined;
            pullDownPanel?: false | ((arg: {
                canRefresh: boolean;
                goingUp: boolean;
                refreshing: boolean;
            }) => vue.VNodeChild) | undefined;
        } | undefined;
    } & {
        "v-slot:default"?: false | (() => vue.VNodeChild) | undefined;
        "v-slot:pullDownPanel"?: false | ((arg: {
            canRefresh: boolean;
            goingUp: boolean;
            refreshing: boolean;
        }) => vue.VNodeChild) | undefined;
    } & {
        onLoad?: ((options: {
            done: () => void;
        }) => any) | undefined;
    }, {}, {}, {}, {}, {
        pullDownThreshold: number;
    }>;
    __isFragment?: undefined;
    __isTeleport?: undefined;
    __isSuspense?: undefined;
} & vue.ComponentOptionsBase<{
    pullDownThreshold: number;
} & {} & {
    $children?: vue.VNodeChild | (() => vue.VNodeChild) | {
        default?: (() => vue.VNodeChild) | undefined;
        pullDownPanel?: ((arg: {
            canRefresh: boolean;
            goingUp: boolean;
            refreshing: boolean;
        }) => vue.VNodeChild) | undefined;
    };
    'v-slots'?: {
        default?: false | (() => vue.VNodeChild) | undefined;
        pullDownPanel?: false | ((arg: {
            canRefresh: boolean;
            goingUp: boolean;
            refreshing: boolean;
        }) => vue.VNodeChild) | undefined;
    } | undefined;
} & {
    "v-slot:default"?: false | (() => vue.VNodeChild) | undefined;
    "v-slot:pullDownPanel"?: false | ((arg: {
        canRefresh: boolean;
        goingUp: boolean;
        refreshing: boolean;
    }) => vue.VNodeChild) | undefined;
} & {
    onLoad?: ((options: {
        done: () => void;
    }) => any) | undefined;
}, void, unknown, {}, {}, vue.ComponentOptionsMixin, vue.ComponentOptionsMixin, {
    load: (options: {
        done: () => void;
    }) => true;
}, string, {
    pullDownThreshold: number;
}, {}, string, vue.SlotsType<Partial<{
    default: () => vue.VNode<vue.RendererNode, vue.RendererElement, {
        [key: string]: any;
    }>[];
    pullDownPanel: (arg: {
        canRefresh: boolean;
        goingUp: boolean;
        refreshing: boolean;
    }) => vue.VNode<vue.RendererNode, vue.RendererElement, {
        [key: string]: any;
    }>[];
}>>> & vue.VNodeProps & vue.AllowedComponentProps & vue.ComponentCustomProps & FilterPropsOptions<{
    pullDownThreshold: {
        type: NumberConstructor;
        default: number;
    };
}, vue.ExtractPropTypes<{
    pullDownThreshold: {
        type: NumberConstructor;
        default: number;
    };
}>>;
type VPullToRefresh = InstanceType<typeof VPullToRefresh>;

export { VPullToRefresh };
