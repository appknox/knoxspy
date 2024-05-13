import * as vue from 'vue';
import { ComponentPropsOptions, ExtractPropTypes, PropType } from 'vue';

interface FilterPropsOptions<PropsOptions extends Readonly<ComponentPropsOptions>, Props = ExtractPropTypes<PropsOptions>> {
    filterProps<T extends Partial<Props>, U extends Exclude<keyof Props, Exclude<keyof Props, keyof T>>>(props: T): Partial<Pick<T, U>>;
}

declare const VCalendar: {
    new (...args: any[]): vue.CreateComponentPublicInstance<{
        text: string;
        disabled: boolean;
        day: Record<string, any>;
        nextIcon: string;
        prevIcon: string;
        viewMode: "month" | "day" | "week";
        showAdjacentMonths: boolean;
        weekdays: number[];
        weeksInMonth: "static" | "dynamic";
        hideHeader: boolean;
        intervalDivisions: number;
        intervalDuration: number;
        intervalHeight: number;
        intervalFormat: string | Function;
        intervalStart: number;
        hideDayHeader: boolean;
        intervals: number;
        hideWeekNumber: boolean;
    } & {
        events?: any[] | undefined;
        title?: string | undefined;
        month?: string | number | undefined;
        year?: string | number | undefined;
        modelValue?: unknown[] | undefined;
        max?: unknown;
        min?: unknown;
        allowedDates?: unknown[] | ((date: unknown) => boolean) | undefined;
        displayValue?: unknown;
        dayIndex?: number | undefined;
    } & {
        $children?: {} | vue.VNodeChild | {
            header?: ((arg: {
                title: string;
            }) => vue.VNodeChild) | undefined;
            event?: ((arg: {
                day?: Object | undefined;
                allDay: boolean;
                event: Record<string, unknown>;
            }) => vue.VNodeChild) | undefined;
        };
        'v-slots'?: {
            header?: false | ((arg: {
                title: string;
            }) => vue.VNodeChild) | undefined;
            event?: false | ((arg: {
                day?: Object | undefined;
                allDay: boolean;
                event: Record<string, unknown>;
            }) => vue.VNodeChild) | undefined;
        } | undefined;
    } & {
        "v-slot:header"?: false | ((arg: {
            title: string;
        }) => vue.VNodeChild) | undefined;
        "v-slot:event"?: false | ((arg: {
            day?: Object | undefined;
            allDay: boolean;
            event: Record<string, unknown>;
        }) => vue.VNodeChild) | undefined;
    } & {
        "onUpdate:modelValue"?: ((...args: any[]) => any) | undefined;
        onNext?: ((...args: any[]) => any) | undefined;
        onPrev?: ((...args: any[]) => any) | undefined;
    }, {
        daysInMonth: vue.ComputedRef<{
            date: unknown;
            isoDate: string;
            formatted: string;
            year: number;
            month: number;
            isDisabled: boolean;
            isWeekStart: boolean;
            isWeekEnd: boolean;
            isToday: boolean;
            isAdjacent: boolean;
            isHidden: boolean;
            isStart: boolean;
            isSelected: boolean;
            isEnd: boolean;
            isSame: boolean;
            localized: string;
        }[]>;
        daysInWeek: vue.ComputedRef<{
            date: unknown;
            isoDate: string;
            formatted: string;
            year: number;
            month: number;
            isDisabled: boolean;
            isWeekStart: boolean;
            isWeekEnd: boolean;
            isToday: boolean;
            isAdjacent: boolean;
            isHidden: boolean;
            isStart: boolean;
            isSelected: boolean;
            isEnd: boolean;
            isSame: boolean;
            localized: string;
        }[]>;
        genDays: (days: unknown[], today: unknown) => {
            date: unknown;
            isoDate: string;
            formatted: string;
            year: number;
            month: number;
            isDisabled: boolean;
            isWeekStart: boolean;
            isWeekEnd: boolean;
            isToday: boolean;
            isAdjacent: boolean;
            isHidden: boolean;
            isStart: boolean;
            isSelected: boolean;
            isEnd: boolean;
            isSame: boolean;
            localized: string;
        }[];
    }, unknown, {}, {}, vue.ComponentOptionsMixin, vue.ComponentOptionsMixin, {
        next: null;
        prev: null;
        'update:modelValue': null;
    }, vue.VNodeProps & vue.AllowedComponentProps & vue.ComponentCustomProps & {
        text: string;
        disabled: boolean;
        day: Record<string, any>;
        nextIcon: string;
        prevIcon: string;
        viewMode: "month" | "day" | "week";
        showAdjacentMonths: boolean;
        weekdays: number[];
        weeksInMonth: "static" | "dynamic";
        hideHeader: boolean;
        intervalDivisions: number;
        intervalDuration: number;
        intervalHeight: number;
        intervalFormat: string | Function;
        intervalStart: number;
        hideDayHeader: boolean;
        intervals: number;
        hideWeekNumber: boolean;
    } & {
        events?: any[] | undefined;
        title?: string | undefined;
        month?: string | number | undefined;
        year?: string | number | undefined;
        modelValue?: unknown[] | undefined;
        max?: unknown;
        min?: unknown;
        allowedDates?: unknown[] | ((date: unknown) => boolean) | undefined;
        displayValue?: unknown;
        dayIndex?: number | undefined;
    } & {
        $children?: {} | vue.VNodeChild | {
            header?: ((arg: {
                title: string;
            }) => vue.VNodeChild) | undefined;
            event?: ((arg: {
                day?: Object | undefined;
                allDay: boolean;
                event: Record<string, unknown>;
            }) => vue.VNodeChild) | undefined;
        };
        'v-slots'?: {
            header?: false | ((arg: {
                title: string;
            }) => vue.VNodeChild) | undefined;
            event?: false | ((arg: {
                day?: Object | undefined;
                allDay: boolean;
                event: Record<string, unknown>;
            }) => vue.VNodeChild) | undefined;
        } | undefined;
    } & {
        "v-slot:header"?: false | ((arg: {
            title: string;
        }) => vue.VNodeChild) | undefined;
        "v-slot:event"?: false | ((arg: {
            day?: Object | undefined;
            allDay: boolean;
            event: Record<string, unknown>;
        }) => vue.VNodeChild) | undefined;
    } & {
        "onUpdate:modelValue"?: ((...args: any[]) => any) | undefined;
        onNext?: ((...args: any[]) => any) | undefined;
        onPrev?: ((...args: any[]) => any) | undefined;
    }, {
        text: string;
        disabled: boolean;
        day: Record<string, any>;
        nextIcon: string;
        prevIcon: string;
        viewMode: "month" | "day" | "week";
        showAdjacentMonths: boolean;
        weekdays: number[];
        weeksInMonth: "static" | "dynamic";
        hideHeader: boolean;
        intervalDivisions: number;
        intervalDuration: number;
        intervalHeight: number;
        intervalFormat: string | Function;
        intervalStart: number;
        hideDayHeader: boolean;
        intervals: number;
        hideWeekNumber: boolean;
    }, true, {}, vue.SlotsType<Partial<{
        header: (arg: {
            title: string;
        }) => vue.VNode<vue.RendererNode, vue.RendererElement, {
            [key: string]: any;
        }>[];
        event: (arg: {
            day?: Object | undefined;
            allDay: boolean;
            event: Record<string, unknown>;
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
        text: string;
        disabled: boolean;
        day: Record<string, any>;
        nextIcon: string;
        prevIcon: string;
        viewMode: "month" | "day" | "week";
        showAdjacentMonths: boolean;
        weekdays: number[];
        weeksInMonth: "static" | "dynamic";
        hideHeader: boolean;
        intervalDivisions: number;
        intervalDuration: number;
        intervalHeight: number;
        intervalFormat: string | Function;
        intervalStart: number;
        hideDayHeader: boolean;
        intervals: number;
        hideWeekNumber: boolean;
    } & {
        events?: any[] | undefined;
        title?: string | undefined;
        month?: string | number | undefined;
        year?: string | number | undefined;
        modelValue?: unknown[] | undefined;
        max?: unknown;
        min?: unknown;
        allowedDates?: unknown[] | ((date: unknown) => boolean) | undefined;
        displayValue?: unknown;
        dayIndex?: number | undefined;
    } & {
        $children?: {} | vue.VNodeChild | {
            header?: ((arg: {
                title: string;
            }) => vue.VNodeChild) | undefined;
            event?: ((arg: {
                day?: Object | undefined;
                allDay: boolean;
                event: Record<string, unknown>;
            }) => vue.VNodeChild) | undefined;
        };
        'v-slots'?: {
            header?: false | ((arg: {
                title: string;
            }) => vue.VNodeChild) | undefined;
            event?: false | ((arg: {
                day?: Object | undefined;
                allDay: boolean;
                event: Record<string, unknown>;
            }) => vue.VNodeChild) | undefined;
        } | undefined;
    } & {
        "v-slot:header"?: false | ((arg: {
            title: string;
        }) => vue.VNodeChild) | undefined;
        "v-slot:event"?: false | ((arg: {
            day?: Object | undefined;
            allDay: boolean;
            event: Record<string, unknown>;
        }) => vue.VNodeChild) | undefined;
    } & {
        "onUpdate:modelValue"?: ((...args: any[]) => any) | undefined;
        onNext?: ((...args: any[]) => any) | undefined;
        onPrev?: ((...args: any[]) => any) | undefined;
    }, {
        daysInMonth: vue.ComputedRef<{
            date: unknown;
            isoDate: string;
            formatted: string;
            year: number;
            month: number;
            isDisabled: boolean;
            isWeekStart: boolean;
            isWeekEnd: boolean;
            isToday: boolean;
            isAdjacent: boolean;
            isHidden: boolean;
            isStart: boolean;
            isSelected: boolean;
            isEnd: boolean;
            isSame: boolean;
            localized: string;
        }[]>;
        daysInWeek: vue.ComputedRef<{
            date: unknown;
            isoDate: string;
            formatted: string;
            year: number;
            month: number;
            isDisabled: boolean;
            isWeekStart: boolean;
            isWeekEnd: boolean;
            isToday: boolean;
            isAdjacent: boolean;
            isHidden: boolean;
            isStart: boolean;
            isSelected: boolean;
            isEnd: boolean;
            isSame: boolean;
            localized: string;
        }[]>;
        genDays: (days: unknown[], today: unknown) => {
            date: unknown;
            isoDate: string;
            formatted: string;
            year: number;
            month: number;
            isDisabled: boolean;
            isWeekStart: boolean;
            isWeekEnd: boolean;
            isToday: boolean;
            isAdjacent: boolean;
            isHidden: boolean;
            isStart: boolean;
            isSelected: boolean;
            isEnd: boolean;
            isSame: boolean;
            localized: string;
        }[];
    }, {}, {}, {}, {
        text: string;
        disabled: boolean;
        day: Record<string, any>;
        nextIcon: string;
        prevIcon: string;
        viewMode: "month" | "day" | "week";
        showAdjacentMonths: boolean;
        weekdays: number[];
        weeksInMonth: "static" | "dynamic";
        hideHeader: boolean;
        intervalDivisions: number;
        intervalDuration: number;
        intervalHeight: number;
        intervalFormat: string | Function;
        intervalStart: number;
        hideDayHeader: boolean;
        intervals: number;
        hideWeekNumber: boolean;
    }>;
    __isFragment?: undefined;
    __isTeleport?: undefined;
    __isSuspense?: undefined;
} & vue.ComponentOptionsBase<{
    text: string;
    disabled: boolean;
    day: Record<string, any>;
    nextIcon: string;
    prevIcon: string;
    viewMode: "month" | "day" | "week";
    showAdjacentMonths: boolean;
    weekdays: number[];
    weeksInMonth: "static" | "dynamic";
    hideHeader: boolean;
    intervalDivisions: number;
    intervalDuration: number;
    intervalHeight: number;
    intervalFormat: string | Function;
    intervalStart: number;
    hideDayHeader: boolean;
    intervals: number;
    hideWeekNumber: boolean;
} & {
    events?: any[] | undefined;
    title?: string | undefined;
    month?: string | number | undefined;
    year?: string | number | undefined;
    modelValue?: unknown[] | undefined;
    max?: unknown;
    min?: unknown;
    allowedDates?: unknown[] | ((date: unknown) => boolean) | undefined;
    displayValue?: unknown;
    dayIndex?: number | undefined;
} & {
    $children?: {} | vue.VNodeChild | {
        header?: ((arg: {
            title: string;
        }) => vue.VNodeChild) | undefined;
        event?: ((arg: {
            day?: Object | undefined;
            allDay: boolean;
            event: Record<string, unknown>;
        }) => vue.VNodeChild) | undefined;
    };
    'v-slots'?: {
        header?: false | ((arg: {
            title: string;
        }) => vue.VNodeChild) | undefined;
        event?: false | ((arg: {
            day?: Object | undefined;
            allDay: boolean;
            event: Record<string, unknown>;
        }) => vue.VNodeChild) | undefined;
    } | undefined;
} & {
    "v-slot:header"?: false | ((arg: {
        title: string;
    }) => vue.VNodeChild) | undefined;
    "v-slot:event"?: false | ((arg: {
        day?: Object | undefined;
        allDay: boolean;
        event: Record<string, unknown>;
    }) => vue.VNodeChild) | undefined;
} & {
    "onUpdate:modelValue"?: ((...args: any[]) => any) | undefined;
    onNext?: ((...args: any[]) => any) | undefined;
    onPrev?: ((...args: any[]) => any) | undefined;
}, {
    daysInMonth: vue.ComputedRef<{
        date: unknown;
        isoDate: string;
        formatted: string;
        year: number;
        month: number;
        isDisabled: boolean;
        isWeekStart: boolean;
        isWeekEnd: boolean;
        isToday: boolean;
        isAdjacent: boolean;
        isHidden: boolean;
        isStart: boolean;
        isSelected: boolean;
        isEnd: boolean;
        isSame: boolean;
        localized: string;
    }[]>;
    daysInWeek: vue.ComputedRef<{
        date: unknown;
        isoDate: string;
        formatted: string;
        year: number;
        month: number;
        isDisabled: boolean;
        isWeekStart: boolean;
        isWeekEnd: boolean;
        isToday: boolean;
        isAdjacent: boolean;
        isHidden: boolean;
        isStart: boolean;
        isSelected: boolean;
        isEnd: boolean;
        isSame: boolean;
        localized: string;
    }[]>;
    genDays: (days: unknown[], today: unknown) => {
        date: unknown;
        isoDate: string;
        formatted: string;
        year: number;
        month: number;
        isDisabled: boolean;
        isWeekStart: boolean;
        isWeekEnd: boolean;
        isToday: boolean;
        isAdjacent: boolean;
        isHidden: boolean;
        isStart: boolean;
        isSelected: boolean;
        isEnd: boolean;
        isSame: boolean;
        localized: string;
    }[];
}, unknown, {}, {}, vue.ComponentOptionsMixin, vue.ComponentOptionsMixin, {
    next: null;
    prev: null;
    'update:modelValue': null;
}, string, {
    text: string;
    disabled: boolean;
    day: Record<string, any>;
    nextIcon: string;
    prevIcon: string;
    viewMode: "month" | "day" | "week";
    showAdjacentMonths: boolean;
    weekdays: number[];
    weeksInMonth: "static" | "dynamic";
    hideHeader: boolean;
    intervalDivisions: number;
    intervalDuration: number;
    intervalHeight: number;
    intervalFormat: string | Function;
    intervalStart: number;
    hideDayHeader: boolean;
    intervals: number;
    hideWeekNumber: boolean;
}, {}, string, vue.SlotsType<Partial<{
    header: (arg: {
        title: string;
    }) => vue.VNode<vue.RendererNode, vue.RendererElement, {
        [key: string]: any;
    }>[];
    event: (arg: {
        day?: Object | undefined;
        allDay: boolean;
        event: Record<string, unknown>;
    }) => vue.VNode<vue.RendererNode, vue.RendererElement, {
        [key: string]: any;
    }>[];
}>>> & vue.VNodeProps & vue.AllowedComponentProps & vue.ComponentCustomProps & FilterPropsOptions<{
    nextIcon: {
        type: StringConstructor;
        default: string;
    };
    prevIcon: {
        type: StringConstructor;
        default: string;
    };
    title: StringConstructor;
    text: {
        type: StringConstructor;
        default: string;
    };
    viewMode: {
        type: vue.PropType<"month" | "day" | "week">;
        default: string;
    };
    day: {
        type: ObjectConstructor;
        default: () => {};
    };
    dayIndex: NumberConstructor;
    events: {
        (arrayLength: number): any[];
        (...items: any[]): any[];
        new (arrayLength: number): any[];
        new (...items: any[]): any[];
        isArray(arg: any): arg is any[];
        readonly prototype: any[];
        from<T>(arrayLike: ArrayLike<T>): T[];
        from<T_1, U>(arrayLike: ArrayLike<T_1>, mapfn: (v: T_1, k: number) => U, thisArg?: any): U[];
        from<T_2>(iterable: Iterable<T_2> | ArrayLike<T_2>): T_2[];
        from<T_3, U_1>(iterable: Iterable<T_3> | ArrayLike<T_3>, mapfn: (v: T_3, k: number) => U_1, thisArg?: any): U_1[];
        of<T_4>(...items: T_4[]): T_4[];
        readonly [Symbol.species]: ArrayConstructor;
    };
    intervalDivisions: {
        type: NumberConstructor;
        default: number;
    };
    intervalDuration: {
        type: NumberConstructor;
        default: number;
    };
    intervalHeight: {
        type: NumberConstructor;
        default: number;
    };
    intervalFormat: {
        type: (StringConstructor | FunctionConstructor)[];
        default: string;
    };
    intervalStart: {
        type: NumberConstructor;
        default: number;
    };
    hideDayHeader: BooleanConstructor;
    intervals: {
        type: NumberConstructor;
        default: number;
    };
    allowedDates: vue.PropType<unknown[] | ((date: unknown) => boolean)>;
    disabled: BooleanConstructor;
    displayValue: vue.PropType<unknown>;
    modelValue: vue.PropType<unknown[]>;
    month: (StringConstructor | NumberConstructor)[];
    max: vue.PropType<unknown>;
    min: vue.PropType<unknown>;
    showAdjacentMonths: BooleanConstructor;
    year: (StringConstructor | NumberConstructor)[];
    weekdays: {
        type: {
            (arrayLength: number): number[];
            (...items: number[]): number[];
            new (arrayLength: number): number[];
            new (...items: number[]): number[];
            isArray(arg: any): arg is any[];
            readonly prototype: any[];
            from<T>(arrayLike: ArrayLike<T>): T[];
            from<T_1, U>(arrayLike: ArrayLike<T_1>, mapfn: (v: T_1, k: number) => U, thisArg?: any): U[];
            from<T_2>(iterable: Iterable<T_2> | ArrayLike<T_2>): T_2[];
            from<T_3, U_1>(iterable: Iterable<T_3> | ArrayLike<T_3>, mapfn: (v: T_3, k: number) => U_1, thisArg?: any): U_1[];
            of<T_4>(...items: T_4[]): T_4[];
            readonly [Symbol.species]: ArrayConstructor;
        };
        default: () => number[];
    };
    weeksInMonth: {
        type: vue.PropType<"static" | "dynamic">;
        default: string;
    };
    hideHeader: BooleanConstructor;
    hideWeekNumber: BooleanConstructor;
}, vue.ExtractPropTypes<{
    nextIcon: {
        type: StringConstructor;
        default: string;
    };
    prevIcon: {
        type: StringConstructor;
        default: string;
    };
    title: StringConstructor;
    text: {
        type: StringConstructor;
        default: string;
    };
    viewMode: {
        type: vue.PropType<"month" | "day" | "week">;
        default: string;
    };
    day: {
        type: ObjectConstructor;
        default: () => {};
    };
    dayIndex: NumberConstructor;
    events: {
        (arrayLength: number): any[];
        (...items: any[]): any[];
        new (arrayLength: number): any[];
        new (...items: any[]): any[];
        isArray(arg: any): arg is any[];
        readonly prototype: any[];
        from<T>(arrayLike: ArrayLike<T>): T[];
        from<T_1, U>(arrayLike: ArrayLike<T_1>, mapfn: (v: T_1, k: number) => U, thisArg?: any): U[];
        from<T_2>(iterable: Iterable<T_2> | ArrayLike<T_2>): T_2[];
        from<T_3, U_1>(iterable: Iterable<T_3> | ArrayLike<T_3>, mapfn: (v: T_3, k: number) => U_1, thisArg?: any): U_1[];
        of<T_4>(...items: T_4[]): T_4[];
        readonly [Symbol.species]: ArrayConstructor;
    };
    intervalDivisions: {
        type: NumberConstructor;
        default: number;
    };
    intervalDuration: {
        type: NumberConstructor;
        default: number;
    };
    intervalHeight: {
        type: NumberConstructor;
        default: number;
    };
    intervalFormat: {
        type: (StringConstructor | FunctionConstructor)[];
        default: string;
    };
    intervalStart: {
        type: NumberConstructor;
        default: number;
    };
    hideDayHeader: BooleanConstructor;
    intervals: {
        type: NumberConstructor;
        default: number;
    };
    allowedDates: vue.PropType<unknown[] | ((date: unknown) => boolean)>;
    disabled: BooleanConstructor;
    displayValue: vue.PropType<unknown>;
    modelValue: vue.PropType<unknown[]>;
    month: (StringConstructor | NumberConstructor)[];
    max: vue.PropType<unknown>;
    min: vue.PropType<unknown>;
    showAdjacentMonths: BooleanConstructor;
    year: (StringConstructor | NumberConstructor)[];
    weekdays: {
        type: {
            (arrayLength: number): number[];
            (...items: number[]): number[];
            new (arrayLength: number): number[];
            new (...items: number[]): number[];
            isArray(arg: any): arg is any[];
            readonly prototype: any[];
            from<T>(arrayLike: ArrayLike<T>): T[];
            from<T_1, U>(arrayLike: ArrayLike<T_1>, mapfn: (v: T_1, k: number) => U, thisArg?: any): U[];
            from<T_2>(iterable: Iterable<T_2> | ArrayLike<T_2>): T_2[];
            from<T_3, U_1>(iterable: Iterable<T_3> | ArrayLike<T_3>, mapfn: (v: T_3, k: number) => U_1, thisArg?: any): U_1[];
            of<T_4>(...items: T_4[]): T_4[];
            readonly [Symbol.species]: ArrayConstructor;
        };
        default: () => number[];
    };
    weeksInMonth: {
        type: vue.PropType<"static" | "dynamic">;
        default: string;
    };
    hideHeader: BooleanConstructor;
    hideWeekNumber: BooleanConstructor;
}>>;
type VCalendar = InstanceType<typeof VCalendar>;

declare const VCalendarDay: {
    new (...args: any[]): vue.CreateComponentPublicInstance<{
        day: Record<string, any>;
        intervalDivisions: number;
        intervalDuration: number;
        intervalHeight: number;
        intervalFormat: string | Function;
        intervalStart: number;
        hideDayHeader: boolean;
        intervals: number;
    } & {
        events?: any[] | undefined;
        dayIndex?: number | undefined;
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
        intervals: vue.ComputedRef<number[]>;
    }, unknown, {}, {}, vue.ComponentOptionsMixin, vue.ComponentOptionsMixin, Record<string, any>, vue.VNodeProps & vue.AllowedComponentProps & vue.ComponentCustomProps & {
        day: Record<string, any>;
        intervalDivisions: number;
        intervalDuration: number;
        intervalHeight: number;
        intervalFormat: string | Function;
        intervalStart: number;
        hideDayHeader: boolean;
        intervals: number;
    } & {
        events?: any[] | undefined;
        dayIndex?: number | undefined;
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
        day: Record<string, any>;
        intervalDivisions: number;
        intervalDuration: number;
        intervalHeight: number;
        intervalFormat: string | Function;
        intervalStart: number;
        hideDayHeader: boolean;
        intervals: number;
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
        day: Record<string, any>;
        intervalDivisions: number;
        intervalDuration: number;
        intervalHeight: number;
        intervalFormat: string | Function;
        intervalStart: number;
        hideDayHeader: boolean;
        intervals: number;
    } & {
        events?: any[] | undefined;
        dayIndex?: number | undefined;
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
        intervals: vue.ComputedRef<number[]>;
    }, {}, {}, {}, {
        day: Record<string, any>;
        intervalDivisions: number;
        intervalDuration: number;
        intervalHeight: number;
        intervalFormat: string | Function;
        intervalStart: number;
        hideDayHeader: boolean;
        intervals: number;
    }>;
    __isFragment?: undefined;
    __isTeleport?: undefined;
    __isSuspense?: undefined;
} & vue.ComponentOptionsBase<{
    day: Record<string, any>;
    intervalDivisions: number;
    intervalDuration: number;
    intervalHeight: number;
    intervalFormat: string | Function;
    intervalStart: number;
    hideDayHeader: boolean;
    intervals: number;
} & {
    events?: any[] | undefined;
    dayIndex?: number | undefined;
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
    intervals: vue.ComputedRef<number[]>;
}, unknown, {}, {}, vue.ComponentOptionsMixin, vue.ComponentOptionsMixin, Record<string, any>, string, {
    day: Record<string, any>;
    intervalDivisions: number;
    intervalDuration: number;
    intervalHeight: number;
    intervalFormat: string | Function;
    intervalStart: number;
    hideDayHeader: boolean;
    intervals: number;
}, {}, string, vue.SlotsType<Partial<{
    default: () => vue.VNode<vue.RendererNode, vue.RendererElement, {
        [key: string]: any;
    }>[];
}>>> & vue.VNodeProps & vue.AllowedComponentProps & vue.ComponentCustomProps & FilterPropsOptions<{
    day: {
        type: ObjectConstructor;
        default: () => {};
    };
    dayIndex: NumberConstructor;
    events: {
        (arrayLength: number): any[];
        (...items: any[]): any[];
        new (arrayLength: number): any[];
        new (...items: any[]): any[];
        isArray(arg: any): arg is any[];
        readonly prototype: any[];
        from<T>(arrayLike: ArrayLike<T>): T[];
        from<T_1, U>(arrayLike: ArrayLike<T_1>, mapfn: (v: T_1, k: number) => U, thisArg?: any): U[];
        from<T_2>(iterable: Iterable<T_2> | ArrayLike<T_2>): T_2[];
        from<T_3, U_1>(iterable: Iterable<T_3> | ArrayLike<T_3>, mapfn: (v: T_3, k: number) => U_1, thisArg?: any): U_1[];
        of<T_4>(...items: T_4[]): T_4[];
        readonly [Symbol.species]: ArrayConstructor;
    };
    intervalDivisions: {
        type: NumberConstructor;
        default: number;
    };
    intervalDuration: {
        type: NumberConstructor;
        default: number;
    };
    intervalHeight: {
        type: NumberConstructor;
        default: number;
    };
    intervalFormat: {
        type: (StringConstructor | FunctionConstructor)[];
        default: string;
    };
    intervalStart: {
        type: NumberConstructor;
        default: number;
    };
    hideDayHeader: BooleanConstructor;
    intervals: {
        type: NumberConstructor;
        default: number;
    };
}, vue.ExtractPropTypes<{
    day: {
        type: ObjectConstructor;
        default: () => {};
    };
    dayIndex: NumberConstructor;
    events: {
        (arrayLength: number): any[];
        (...items: any[]): any[];
        new (arrayLength: number): any[];
        new (...items: any[]): any[];
        isArray(arg: any): arg is any[];
        readonly prototype: any[];
        from<T>(arrayLike: ArrayLike<T>): T[];
        from<T_1, U>(arrayLike: ArrayLike<T_1>, mapfn: (v: T_1, k: number) => U, thisArg?: any): U[];
        from<T_2>(iterable: Iterable<T_2> | ArrayLike<T_2>): T_2[];
        from<T_3, U_1>(iterable: Iterable<T_3> | ArrayLike<T_3>, mapfn: (v: T_3, k: number) => U_1, thisArg?: any): U_1[];
        of<T_4>(...items: T_4[]): T_4[];
        readonly [Symbol.species]: ArrayConstructor;
    };
    intervalDivisions: {
        type: NumberConstructor;
        default: number;
    };
    intervalDuration: {
        type: NumberConstructor;
        default: number;
    };
    intervalHeight: {
        type: NumberConstructor;
        default: number;
    };
    intervalFormat: {
        type: (StringConstructor | FunctionConstructor)[];
        default: string;
    };
    intervalStart: {
        type: NumberConstructor;
        default: number;
    };
    hideDayHeader: BooleanConstructor;
    intervals: {
        type: NumberConstructor;
        default: number;
    };
}>>;
type VCalendarDay = InstanceType<typeof VCalendarDay>;

declare const VCalendarHeader: {
    new (...args: any[]): vue.CreateComponentPublicInstance<{
        text: string;
        nextIcon: string;
        prevIcon: string;
        viewMode: "month" | "day" | "week";
    } & {
        title?: string | undefined;
    } & {
        $children?: vue.VNodeChild | {
            default?: (() => vue.VNodeChild) | undefined;
        } | (() => vue.VNodeChild);
        'v-slots'?: {
            default?: false | (() => vue.VNodeChild) | undefined;
        } | undefined;
    } & {
        "v-slot:default"?: false | (() => vue.VNodeChild) | undefined;
    } & {
        "onClick:prev"?: (() => any) | undefined;
        "onClick:next"?: (() => any) | undefined;
        "onClick:toToday"?: (() => any) | undefined;
    }, {}, unknown, {}, {}, vue.ComponentOptionsMixin, vue.ComponentOptionsMixin, {
        'click:next': () => true;
        'click:prev': () => true;
        'click:toToday': () => true;
    }, vue.VNodeProps & vue.AllowedComponentProps & vue.ComponentCustomProps & {
        text: string;
        nextIcon: string;
        prevIcon: string;
        viewMode: "month" | "day" | "week";
    } & {
        title?: string | undefined;
    } & {
        $children?: vue.VNodeChild | {
            default?: (() => vue.VNodeChild) | undefined;
        } | (() => vue.VNodeChild);
        'v-slots'?: {
            default?: false | (() => vue.VNodeChild) | undefined;
        } | undefined;
    } & {
        "v-slot:default"?: false | (() => vue.VNodeChild) | undefined;
    } & {
        "onClick:prev"?: (() => any) | undefined;
        "onClick:next"?: (() => any) | undefined;
        "onClick:toToday"?: (() => any) | undefined;
    }, {
        text: string;
        nextIcon: string;
        prevIcon: string;
        viewMode: "month" | "day" | "week";
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
        text: string;
        nextIcon: string;
        prevIcon: string;
        viewMode: "month" | "day" | "week";
    } & {
        title?: string | undefined;
    } & {
        $children?: vue.VNodeChild | {
            default?: (() => vue.VNodeChild) | undefined;
        } | (() => vue.VNodeChild);
        'v-slots'?: {
            default?: false | (() => vue.VNodeChild) | undefined;
        } | undefined;
    } & {
        "v-slot:default"?: false | (() => vue.VNodeChild) | undefined;
    } & {
        "onClick:prev"?: (() => any) | undefined;
        "onClick:next"?: (() => any) | undefined;
        "onClick:toToday"?: (() => any) | undefined;
    }, {}, {}, {}, {}, {
        text: string;
        nextIcon: string;
        prevIcon: string;
        viewMode: "month" | "day" | "week";
    }>;
    __isFragment?: undefined;
    __isTeleport?: undefined;
    __isSuspense?: undefined;
} & vue.ComponentOptionsBase<{
    text: string;
    nextIcon: string;
    prevIcon: string;
    viewMode: "month" | "day" | "week";
} & {
    title?: string | undefined;
} & {
    $children?: vue.VNodeChild | {
        default?: (() => vue.VNodeChild) | undefined;
    } | (() => vue.VNodeChild);
    'v-slots'?: {
        default?: false | (() => vue.VNodeChild) | undefined;
    } | undefined;
} & {
    "v-slot:default"?: false | (() => vue.VNodeChild) | undefined;
} & {
    "onClick:prev"?: (() => any) | undefined;
    "onClick:next"?: (() => any) | undefined;
    "onClick:toToday"?: (() => any) | undefined;
}, {}, unknown, {}, {}, vue.ComponentOptionsMixin, vue.ComponentOptionsMixin, {
    'click:next': () => true;
    'click:prev': () => true;
    'click:toToday': () => true;
}, string, {
    text: string;
    nextIcon: string;
    prevIcon: string;
    viewMode: "month" | "day" | "week";
}, {}, string, vue.SlotsType<Partial<{
    default: () => vue.VNode<vue.RendererNode, vue.RendererElement, {
        [key: string]: any;
    }>[];
}>>> & vue.VNodeProps & vue.AllowedComponentProps & vue.ComponentCustomProps & FilterPropsOptions<{
    nextIcon: {
        type: StringConstructor;
        default: string;
    };
    prevIcon: {
        type: StringConstructor;
        default: string;
    };
    title: StringConstructor;
    text: {
        type: StringConstructor;
        default: string;
    };
    viewMode: {
        type: PropType<"month" | "day" | "week">;
        default: string;
    };
}, vue.ExtractPropTypes<{
    nextIcon: {
        type: StringConstructor;
        default: string;
    };
    prevIcon: {
        type: StringConstructor;
        default: string;
    };
    title: StringConstructor;
    text: {
        type: StringConstructor;
        default: string;
    };
    viewMode: {
        type: PropType<"month" | "day" | "week">;
        default: string;
    };
}>>;
type VCalendarHeader = InstanceType<typeof VCalendarHeader>;

declare const VCalendarInterval: {
    new (...args: any[]): vue.CreateComponentPublicInstance<{
        day: Record<string, any>;
        index: number;
        intervalDivisions: number;
        intervalDuration: number;
        intervalHeight: number;
        intervalFormat: string | Function;
        intervalStart: number;
    } & {
        events?: any[] | undefined;
        dayIndex?: number | undefined;
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
        interval: vue.ComputedRef<{
            label: string;
            start: unknown;
            end: unknown;
            events: any[];
        }>;
    }, unknown, {}, {}, vue.ComponentOptionsMixin, vue.ComponentOptionsMixin, Record<string, any>, vue.VNodeProps & vue.AllowedComponentProps & vue.ComponentCustomProps & {
        day: Record<string, any>;
        index: number;
        intervalDivisions: number;
        intervalDuration: number;
        intervalHeight: number;
        intervalFormat: string | Function;
        intervalStart: number;
    } & {
        events?: any[] | undefined;
        dayIndex?: number | undefined;
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
        day: Record<string, any>;
        intervalDivisions: number;
        intervalDuration: number;
        intervalHeight: number;
        intervalFormat: string | Function;
        intervalStart: number;
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
        day: Record<string, any>;
        index: number;
        intervalDivisions: number;
        intervalDuration: number;
        intervalHeight: number;
        intervalFormat: string | Function;
        intervalStart: number;
    } & {
        events?: any[] | undefined;
        dayIndex?: number | undefined;
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
        interval: vue.ComputedRef<{
            label: string;
            start: unknown;
            end: unknown;
            events: any[];
        }>;
    }, {}, {}, {}, {
        day: Record<string, any>;
        intervalDivisions: number;
        intervalDuration: number;
        intervalHeight: number;
        intervalFormat: string | Function;
        intervalStart: number;
    }>;
    __isFragment?: undefined;
    __isTeleport?: undefined;
    __isSuspense?: undefined;
} & vue.ComponentOptionsBase<{
    day: Record<string, any>;
    index: number;
    intervalDivisions: number;
    intervalDuration: number;
    intervalHeight: number;
    intervalFormat: string | Function;
    intervalStart: number;
} & {
    events?: any[] | undefined;
    dayIndex?: number | undefined;
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
    interval: vue.ComputedRef<{
        label: string;
        start: unknown;
        end: unknown;
        events: any[];
    }>;
}, unknown, {}, {}, vue.ComponentOptionsMixin, vue.ComponentOptionsMixin, Record<string, any>, string, {
    day: Record<string, any>;
    intervalDivisions: number;
    intervalDuration: number;
    intervalHeight: number;
    intervalFormat: string | Function;
    intervalStart: number;
}, {}, string, vue.SlotsType<Partial<{
    default: () => vue.VNode<vue.RendererNode, vue.RendererElement, {
        [key: string]: any;
    }>[];
}>>> & vue.VNodeProps & vue.AllowedComponentProps & vue.ComponentCustomProps & FilterPropsOptions<{
    day: {
        type: ObjectConstructor;
        default: () => {};
    };
    dayIndex: NumberConstructor;
    events: {
        (arrayLength: number): any[];
        (...items: any[]): any[];
        new (arrayLength: number): any[];
        new (...items: any[]): any[];
        isArray(arg: any): arg is any[];
        readonly prototype: any[];
        from<T>(arrayLike: ArrayLike<T>): T[];
        from<T_1, U>(arrayLike: ArrayLike<T_1>, mapfn: (v: T_1, k: number) => U, thisArg?: any): U[];
        from<T_2>(iterable: Iterable<T_2> | ArrayLike<T_2>): T_2[];
        from<T_3, U_1>(iterable: Iterable<T_3> | ArrayLike<T_3>, mapfn: (v: T_3, k: number) => U_1, thisArg?: any): U_1[];
        of<T_4>(...items: T_4[]): T_4[];
        readonly [Symbol.species]: ArrayConstructor;
    };
    intervalDivisions: {
        type: NumberConstructor;
        default: number;
    };
    intervalDuration: {
        type: NumberConstructor;
        default: number;
    };
    intervalHeight: {
        type: NumberConstructor;
        default: number;
    };
    intervalFormat: {
        type: (StringConstructor | FunctionConstructor)[];
        default: string;
    };
    intervalStart: {
        type: NumberConstructor;
        default: number;
    };
    index: {
        type: NumberConstructor;
        required: true;
    };
}, vue.ExtractPropTypes<{
    day: {
        type: ObjectConstructor;
        default: () => {};
    };
    dayIndex: NumberConstructor;
    events: {
        (arrayLength: number): any[];
        (...items: any[]): any[];
        new (arrayLength: number): any[];
        new (...items: any[]): any[];
        isArray(arg: any): arg is any[];
        readonly prototype: any[];
        from<T>(arrayLike: ArrayLike<T>): T[];
        from<T_1, U>(arrayLike: ArrayLike<T_1>, mapfn: (v: T_1, k: number) => U, thisArg?: any): U[];
        from<T_2>(iterable: Iterable<T_2> | ArrayLike<T_2>): T_2[];
        from<T_3, U_1>(iterable: Iterable<T_3> | ArrayLike<T_3>, mapfn: (v: T_3, k: number) => U_1, thisArg?: any): U_1[];
        of<T_4>(...items: T_4[]): T_4[];
        readonly [Symbol.species]: ArrayConstructor;
    };
    intervalDivisions: {
        type: NumberConstructor;
        default: number;
    };
    intervalDuration: {
        type: NumberConstructor;
        default: number;
    };
    intervalHeight: {
        type: NumberConstructor;
        default: number;
    };
    intervalFormat: {
        type: (StringConstructor | FunctionConstructor)[];
        default: string;
    };
    intervalStart: {
        type: NumberConstructor;
        default: number;
    };
    index: {
        type: NumberConstructor;
        required: true;
    };
}>>;
type VCalendarInterval = InstanceType<typeof VCalendarInterval>;

declare const VCalendarIntervalEvent: {
    new (...args: any[]): vue.CreateComponentPublicInstance<{
        allDay: boolean;
        intervalDivisions: number;
        intervalDuration: number;
        intervalHeight: number;
    } & {
        event?: Record<string, any> | undefined;
        interval?: Record<string, any> | undefined;
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
        allDay: boolean;
        intervalDivisions: number;
        intervalDuration: number;
        intervalHeight: number;
    } & {
        event?: Record<string, any> | undefined;
        interval?: Record<string, any> | undefined;
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
        allDay: boolean;
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
        allDay: boolean;
        intervalDivisions: number;
        intervalDuration: number;
        intervalHeight: number;
    } & {
        event?: Record<string, any> | undefined;
        interval?: Record<string, any> | undefined;
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
        allDay: boolean;
    }>;
    __isFragment?: undefined;
    __isTeleport?: undefined;
    __isSuspense?: undefined;
} & vue.ComponentOptionsBase<{
    allDay: boolean;
    intervalDivisions: number;
    intervalDuration: number;
    intervalHeight: number;
} & {
    event?: Record<string, any> | undefined;
    interval?: Record<string, any> | undefined;
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
    allDay: boolean;
}, {}, string, vue.SlotsType<Partial<{
    default: () => vue.VNode<vue.RendererNode, vue.RendererElement, {
        [key: string]: any;
    }>[];
}>>> & vue.VNodeProps & vue.AllowedComponentProps & vue.ComponentCustomProps & FilterPropsOptions<{
    allDay: BooleanConstructor;
    interval: ObjectConstructor;
    intervalDivisions: {
        type: NumberConstructor;
        required: true;
    };
    intervalDuration: {
        type: NumberConstructor;
        required: true;
    };
    intervalHeight: {
        type: NumberConstructor;
        required: true;
    };
    event: ObjectConstructor;
}, vue.ExtractPropTypes<{
    allDay: BooleanConstructor;
    interval: ObjectConstructor;
    intervalDivisions: {
        type: NumberConstructor;
        required: true;
    };
    intervalDuration: {
        type: NumberConstructor;
        required: true;
    };
    intervalHeight: {
        type: NumberConstructor;
        required: true;
    };
    event: ObjectConstructor;
}>>;
type VCalendarIntervalEvent = InstanceType<typeof VCalendarIntervalEvent>;

declare const VCalendarMonthDay: {
    new (...args: any[]): vue.CreateComponentPublicInstance<{
        active: boolean;
        disabled: boolean;
    } & {
        events?: any[] | undefined;
        title?: string | number | undefined;
        color?: string | undefined;
        day?: Record<string, any> | undefined;
    } & {
        $children?: vue.VNodeChild | (() => vue.VNodeChild) | {
            default?: (() => vue.VNodeChild) | undefined;
            content?: (() => vue.VNodeChild) | undefined;
            title?: ((arg: {
                title?: string | number | undefined;
            }) => vue.VNodeChild) | undefined;
            event?: ((arg: {
                day?: Object | undefined;
                allDay: boolean;
                event: Record<string, unknown>;
            }) => vue.VNodeChild) | undefined;
        };
        'v-slots'?: {
            default?: false | (() => vue.VNodeChild) | undefined;
            content?: false | (() => vue.VNodeChild) | undefined;
            title?: false | ((arg: {
                title?: string | number | undefined;
            }) => vue.VNodeChild) | undefined;
            event?: false | ((arg: {
                day?: Object | undefined;
                allDay: boolean;
                event: Record<string, unknown>;
            }) => vue.VNodeChild) | undefined;
        } | undefined;
    } & {
        "v-slot:default"?: false | (() => vue.VNodeChild) | undefined;
        "v-slot:content"?: false | (() => vue.VNodeChild) | undefined;
        "v-slot:title"?: false | ((arg: {
            title?: string | number | undefined;
        }) => vue.VNodeChild) | undefined;
        "v-slot:event"?: false | ((arg: {
            day?: Object | undefined;
            allDay: boolean;
            event: Record<string, unknown>;
        }) => vue.VNodeChild) | undefined;
    }, {}, unknown, {}, {}, vue.ComponentOptionsMixin, vue.ComponentOptionsMixin, Record<string, any>, vue.VNodeProps & vue.AllowedComponentProps & vue.ComponentCustomProps & {
        active: boolean;
        disabled: boolean;
    } & {
        events?: any[] | undefined;
        title?: string | number | undefined;
        color?: string | undefined;
        day?: Record<string, any> | undefined;
    } & {
        $children?: vue.VNodeChild | (() => vue.VNodeChild) | {
            default?: (() => vue.VNodeChild) | undefined;
            content?: (() => vue.VNodeChild) | undefined;
            title?: ((arg: {
                title?: string | number | undefined;
            }) => vue.VNodeChild) | undefined;
            event?: ((arg: {
                day?: Object | undefined;
                allDay: boolean;
                event: Record<string, unknown>;
            }) => vue.VNodeChild) | undefined;
        };
        'v-slots'?: {
            default?: false | (() => vue.VNodeChild) | undefined;
            content?: false | (() => vue.VNodeChild) | undefined;
            title?: false | ((arg: {
                title?: string | number | undefined;
            }) => vue.VNodeChild) | undefined;
            event?: false | ((arg: {
                day?: Object | undefined;
                allDay: boolean;
                event: Record<string, unknown>;
            }) => vue.VNodeChild) | undefined;
        } | undefined;
    } & {
        "v-slot:default"?: false | (() => vue.VNodeChild) | undefined;
        "v-slot:content"?: false | (() => vue.VNodeChild) | undefined;
        "v-slot:title"?: false | ((arg: {
            title?: string | number | undefined;
        }) => vue.VNodeChild) | undefined;
        "v-slot:event"?: false | ((arg: {
            day?: Object | undefined;
            allDay: boolean;
            event: Record<string, unknown>;
        }) => vue.VNodeChild) | undefined;
    }, {
        active: boolean;
        disabled: boolean;
    }, true, {}, vue.SlotsType<Partial<{
        default: () => vue.VNode<vue.RendererNode, vue.RendererElement, {
            [key: string]: any;
        }>[];
        content: () => vue.VNode<vue.RendererNode, vue.RendererElement, {
            [key: string]: any;
        }>[];
        title: (arg: {
            title?: string | number | undefined;
        }) => vue.VNode<vue.RendererNode, vue.RendererElement, {
            [key: string]: any;
        }>[];
        event: (arg: {
            day?: Object | undefined;
            allDay: boolean;
            event: Record<string, unknown>;
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
        active: boolean;
        disabled: boolean;
    } & {
        events?: any[] | undefined;
        title?: string | number | undefined;
        color?: string | undefined;
        day?: Record<string, any> | undefined;
    } & {
        $children?: vue.VNodeChild | (() => vue.VNodeChild) | {
            default?: (() => vue.VNodeChild) | undefined;
            content?: (() => vue.VNodeChild) | undefined;
            title?: ((arg: {
                title?: string | number | undefined;
            }) => vue.VNodeChild) | undefined;
            event?: ((arg: {
                day?: Object | undefined;
                allDay: boolean;
                event: Record<string, unknown>;
            }) => vue.VNodeChild) | undefined;
        };
        'v-slots'?: {
            default?: false | (() => vue.VNodeChild) | undefined;
            content?: false | (() => vue.VNodeChild) | undefined;
            title?: false | ((arg: {
                title?: string | number | undefined;
            }) => vue.VNodeChild) | undefined;
            event?: false | ((arg: {
                day?: Object | undefined;
                allDay: boolean;
                event: Record<string, unknown>;
            }) => vue.VNodeChild) | undefined;
        } | undefined;
    } & {
        "v-slot:default"?: false | (() => vue.VNodeChild) | undefined;
        "v-slot:content"?: false | (() => vue.VNodeChild) | undefined;
        "v-slot:title"?: false | ((arg: {
            title?: string | number | undefined;
        }) => vue.VNodeChild) | undefined;
        "v-slot:event"?: false | ((arg: {
            day?: Object | undefined;
            allDay: boolean;
            event: Record<string, unknown>;
        }) => vue.VNodeChild) | undefined;
    }, {}, {}, {}, {}, {
        active: boolean;
        disabled: boolean;
    }>;
    __isFragment?: undefined;
    __isTeleport?: undefined;
    __isSuspense?: undefined;
} & vue.ComponentOptionsBase<{
    active: boolean;
    disabled: boolean;
} & {
    events?: any[] | undefined;
    title?: string | number | undefined;
    color?: string | undefined;
    day?: Record<string, any> | undefined;
} & {
    $children?: vue.VNodeChild | (() => vue.VNodeChild) | {
        default?: (() => vue.VNodeChild) | undefined;
        content?: (() => vue.VNodeChild) | undefined;
        title?: ((arg: {
            title?: string | number | undefined;
        }) => vue.VNodeChild) | undefined;
        event?: ((arg: {
            day?: Object | undefined;
            allDay: boolean;
            event: Record<string, unknown>;
        }) => vue.VNodeChild) | undefined;
    };
    'v-slots'?: {
        default?: false | (() => vue.VNodeChild) | undefined;
        content?: false | (() => vue.VNodeChild) | undefined;
        title?: false | ((arg: {
            title?: string | number | undefined;
        }) => vue.VNodeChild) | undefined;
        event?: false | ((arg: {
            day?: Object | undefined;
            allDay: boolean;
            event: Record<string, unknown>;
        }) => vue.VNodeChild) | undefined;
    } | undefined;
} & {
    "v-slot:default"?: false | (() => vue.VNodeChild) | undefined;
    "v-slot:content"?: false | (() => vue.VNodeChild) | undefined;
    "v-slot:title"?: false | ((arg: {
        title?: string | number | undefined;
    }) => vue.VNodeChild) | undefined;
    "v-slot:event"?: false | ((arg: {
        day?: Object | undefined;
        allDay: boolean;
        event: Record<string, unknown>;
    }) => vue.VNodeChild) | undefined;
}, {}, unknown, {}, {}, vue.ComponentOptionsMixin, vue.ComponentOptionsMixin, Record<string, any>, string, {
    active: boolean;
    disabled: boolean;
}, {}, string, vue.SlotsType<Partial<{
    default: () => vue.VNode<vue.RendererNode, vue.RendererElement, {
        [key: string]: any;
    }>[];
    content: () => vue.VNode<vue.RendererNode, vue.RendererElement, {
        [key: string]: any;
    }>[];
    title: (arg: {
        title?: string | number | undefined;
    }) => vue.VNode<vue.RendererNode, vue.RendererElement, {
        [key: string]: any;
    }>[];
    event: (arg: {
        day?: Object | undefined;
        allDay: boolean;
        event: Record<string, unknown>;
    }) => vue.VNode<vue.RendererNode, vue.RendererElement, {
        [key: string]: any;
    }>[];
}>>> & vue.VNodeProps & vue.AllowedComponentProps & vue.ComponentCustomProps & FilterPropsOptions<{
    active: BooleanConstructor;
    color: StringConstructor;
    day: ObjectConstructor;
    disabled: BooleanConstructor;
    events: {
        (arrayLength: number): any[];
        (...items: any[]): any[];
        new (arrayLength: number): any[];
        new (...items: any[]): any[];
        isArray(arg: any): arg is any[];
        readonly prototype: any[];
        from<T>(arrayLike: ArrayLike<T>): T[];
        from<T_1, U>(arrayLike: ArrayLike<T_1>, mapfn: (v: T_1, k: number) => U, thisArg?: any): U[];
        from<T_2>(iterable: Iterable<T_2> | ArrayLike<T_2>): T_2[];
        from<T_3, U_1>(iterable: Iterable<T_3> | ArrayLike<T_3>, mapfn: (v: T_3, k: number) => U_1, thisArg?: any): U_1[];
        of<T_4>(...items: T_4[]): T_4[];
        readonly [Symbol.species]: ArrayConstructor;
    };
    title: (StringConstructor | NumberConstructor)[];
}, vue.ExtractPropTypes<{
    active: BooleanConstructor;
    color: StringConstructor;
    day: ObjectConstructor;
    disabled: BooleanConstructor;
    events: {
        (arrayLength: number): any[];
        (...items: any[]): any[];
        new (arrayLength: number): any[];
        new (...items: any[]): any[];
        isArray(arg: any): arg is any[];
        readonly prototype: any[];
        from<T>(arrayLike: ArrayLike<T>): T[];
        from<T_1, U>(arrayLike: ArrayLike<T_1>, mapfn: (v: T_1, k: number) => U, thisArg?: any): U[];
        from<T_2>(iterable: Iterable<T_2> | ArrayLike<T_2>): T_2[];
        from<T_3, U_1>(iterable: Iterable<T_3> | ArrayLike<T_3>, mapfn: (v: T_3, k: number) => U_1, thisArg?: any): U_1[];
        of<T_4>(...items: T_4[]): T_4[];
        readonly [Symbol.species]: ArrayConstructor;
    };
    title: (StringConstructor | NumberConstructor)[];
}>>;
type VCalendarMonthDay = InstanceType<typeof VCalendarMonthDay>;

export { VCalendar, VCalendarDay, VCalendarHeader, VCalendarInterval, VCalendarIntervalEvent, VCalendarMonthDay };
