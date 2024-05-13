import * as vue from 'vue';
import { ComponentPropsOptions, ExtractPropTypes, PropType } from 'vue';

type HSV = {
    h: number;
    s: number;
    v: number;
    a?: number;
};

interface FilterPropsOptions<PropsOptions extends Readonly<ComponentPropsOptions>, Props = ExtractPropTypes<PropsOptions>> {
    filterProps<T extends Partial<Props>, U extends Exclude<keyof Props, Exclude<keyof Props, keyof T>>>(props: T): Partial<Pick<T, U>>;
}

type ColorPickerMode = {
    inputProps: Record<string, unknown>;
    inputs: {
        [key: string]: any;
        getValue: (color: any) => number | string;
        getColor: (color: any, v: string) => any;
    }[];
    from: (color: any) => HSV;
    to: (color: HSV) => any;
};
declare const modes: {
    rgb: {
        inputs: {
            [key: string]: any;
            getValue: (color: any) => number | string;
            getColor: (color: any, v: string) => any;
        }[];
        inputProps: Record<string, unknown>;
        from: (color: any) => HSV;
        to: (color: HSV) => any;
    };
    rgba: ColorPickerMode;
    hsl: {
        inputs: {
            [key: string]: any;
            getValue: (color: any) => number | string;
            getColor: (color: any, v: string) => any;
        }[];
        inputProps: Record<string, unknown>;
        from: (color: any) => HSV;
        to: (color: HSV) => any;
    };
    hsla: ColorPickerMode;
    hex: {
        inputs: {
            label: string;
            getValue: (c: string) => string;
            getColor: (c: string, v: string) => string;
        }[];
        inputProps: Record<string, unknown>;
        from: (color: any) => HSV;
        to: (color: HSV) => any;
    };
    hexa: ColorPickerMode;
};

declare const VColorPicker: {
    new (...args: any[]): vue.CreateComponentPublicInstance<Readonly<vue.ExtractPropTypes<{
        class: PropType<any>;
        style: {
            type: PropType<vue.StyleValue>;
            default: null;
        };
        width: {
            type: PropType<NonNullable<string | number>>;
            default: NonNullable<string | number>;
        };
        theme: StringConstructor;
        color: StringConstructor;
        tag: {
            type: StringConstructor;
            default: string;
        };
        border: (StringConstructor | NumberConstructor | BooleanConstructor)[];
        position: {
            type: PropType<"fixed" | "absolute" | "relative" | "static" | "sticky">;
            validator: (v: any) => boolean;
        };
        rounded: {
            type: (StringConstructor | NumberConstructor | BooleanConstructor)[];
            default: undefined;
        };
        tile: BooleanConstructor;
        elevation: {
            type: (StringConstructor | NumberConstructor)[];
            validator(v: any): boolean;
        };
        canvasHeight: {
            type: (StringConstructor | NumberConstructor)[];
            default: number;
        };
        disabled: BooleanConstructor;
        dotSize: {
            type: (StringConstructor | NumberConstructor)[];
            default: number;
        };
        hideCanvas: BooleanConstructor;
        hideSliders: BooleanConstructor;
        hideInputs: BooleanConstructor;
        mode: {
            type: PropType<"rgb" | "rgba" | "hsl" | "hsla" | "hex" | "hexa">;
            default: string;
            validator: (v: string) => boolean;
        };
        modes: {
            type: PropType<readonly ("rgb" | "rgba" | "hsl" | "hsla" | "hex" | "hexa")[]>;
            default: () => string[];
            validator: (v: any) => boolean;
        };
        showSwatches: BooleanConstructor;
        swatches: PropType<readonly (readonly (string | number | {
            readonly r: number;
            readonly g: number;
            readonly b: number;
            readonly a?: number | undefined;
        } | {
            readonly h: number;
            readonly s: number;
            readonly v: number;
            readonly a?: number | undefined;
        } | {
            readonly h: number;
            readonly s: number;
            readonly l: number;
            readonly a?: number | undefined;
        })[])[]>;
        swatchesMaxHeight: {
            type: (StringConstructor | NumberConstructor)[];
            default: number;
        };
        modelValue: {
            type: PropType<string | Record<string, unknown> | null | undefined>;
        };
    }>> & {
        "onUpdate:modelValue"?: ((color: any) => any) | undefined;
        "onUpdate:mode"?: ((mode: "rgb" | "rgba" | "hsl" | "hsla" | "hex" | "hexa") => any) | undefined;
    }, {}, unknown, {}, {}, vue.ComponentOptionsMixin, vue.ComponentOptionsMixin, {
        'update:modelValue': (color: any) => true;
        'update:mode': (mode: keyof typeof modes) => true;
    }, vue.VNodeProps & vue.AllowedComponentProps & vue.ComponentCustomProps & Readonly<vue.ExtractPropTypes<{
        class: PropType<any>;
        style: {
            type: PropType<vue.StyleValue>;
            default: null;
        };
        width: {
            type: PropType<NonNullable<string | number>>;
            default: NonNullable<string | number>;
        };
        theme: StringConstructor;
        color: StringConstructor;
        tag: {
            type: StringConstructor;
            default: string;
        };
        border: (StringConstructor | NumberConstructor | BooleanConstructor)[];
        position: {
            type: PropType<"fixed" | "absolute" | "relative" | "static" | "sticky">;
            validator: (v: any) => boolean;
        };
        rounded: {
            type: (StringConstructor | NumberConstructor | BooleanConstructor)[];
            default: undefined;
        };
        tile: BooleanConstructor;
        elevation: {
            type: (StringConstructor | NumberConstructor)[];
            validator(v: any): boolean;
        };
        canvasHeight: {
            type: (StringConstructor | NumberConstructor)[];
            default: number;
        };
        disabled: BooleanConstructor;
        dotSize: {
            type: (StringConstructor | NumberConstructor)[];
            default: number;
        };
        hideCanvas: BooleanConstructor;
        hideSliders: BooleanConstructor;
        hideInputs: BooleanConstructor;
        mode: {
            type: PropType<"rgb" | "rgba" | "hsl" | "hsla" | "hex" | "hexa">;
            default: string;
            validator: (v: string) => boolean;
        };
        modes: {
            type: PropType<readonly ("rgb" | "rgba" | "hsl" | "hsla" | "hex" | "hexa")[]>;
            default: () => string[];
            validator: (v: any) => boolean;
        };
        showSwatches: BooleanConstructor;
        swatches: PropType<readonly (readonly (string | number | {
            readonly r: number;
            readonly g: number;
            readonly b: number;
            readonly a?: number | undefined;
        } | {
            readonly h: number;
            readonly s: number;
            readonly v: number;
            readonly a?: number | undefined;
        } | {
            readonly h: number;
            readonly s: number;
            readonly l: number;
            readonly a?: number | undefined;
        })[])[]>;
        swatchesMaxHeight: {
            type: (StringConstructor | NumberConstructor)[];
            default: number;
        };
        modelValue: {
            type: PropType<string | Record<string, unknown> | null | undefined>;
        };
    }>> & {
        "onUpdate:modelValue"?: ((color: any) => any) | undefined;
        "onUpdate:mode"?: ((mode: "rgb" | "rgba" | "hsl" | "hsla" | "hex" | "hexa") => any) | undefined;
    }, {
        style: vue.StyleValue;
        mode: "rgb" | "rgba" | "hsl" | "hsla" | "hex" | "hexa";
        width: NonNullable<string | number>;
        disabled: boolean;
        tag: string;
        rounded: string | number | boolean;
        tile: boolean;
        dotSize: string | number;
        modes: readonly ("rgb" | "rgba" | "hsl" | "hsla" | "hex" | "hexa")[];
        canvasHeight: string | number;
        hideCanvas: boolean;
        hideSliders: boolean;
        hideInputs: boolean;
        showSwatches: boolean;
        swatchesMaxHeight: string | number;
    }, true, {}, {}, {
        P: {};
        B: {};
        D: {};
        C: {};
        M: {};
        Defaults: {};
    }, Readonly<vue.ExtractPropTypes<{
        class: PropType<any>;
        style: {
            type: PropType<vue.StyleValue>;
            default: null;
        };
        width: {
            type: PropType<NonNullable<string | number>>;
            default: NonNullable<string | number>;
        };
        theme: StringConstructor;
        color: StringConstructor;
        tag: {
            type: StringConstructor;
            default: string;
        };
        border: (StringConstructor | NumberConstructor | BooleanConstructor)[];
        position: {
            type: PropType<"fixed" | "absolute" | "relative" | "static" | "sticky">;
            validator: (v: any) => boolean;
        };
        rounded: {
            type: (StringConstructor | NumberConstructor | BooleanConstructor)[];
            default: undefined;
        };
        tile: BooleanConstructor;
        elevation: {
            type: (StringConstructor | NumberConstructor)[];
            validator(v: any): boolean;
        };
        canvasHeight: {
            type: (StringConstructor | NumberConstructor)[];
            default: number;
        };
        disabled: BooleanConstructor;
        dotSize: {
            type: (StringConstructor | NumberConstructor)[];
            default: number;
        };
        hideCanvas: BooleanConstructor;
        hideSliders: BooleanConstructor;
        hideInputs: BooleanConstructor;
        mode: {
            type: PropType<"rgb" | "rgba" | "hsl" | "hsla" | "hex" | "hexa">;
            default: string;
            validator: (v: string) => boolean;
        };
        modes: {
            type: PropType<readonly ("rgb" | "rgba" | "hsl" | "hsla" | "hex" | "hexa")[]>;
            default: () => string[];
            validator: (v: any) => boolean;
        };
        showSwatches: BooleanConstructor;
        swatches: PropType<readonly (readonly (string | number | {
            readonly r: number;
            readonly g: number;
            readonly b: number;
            readonly a?: number | undefined;
        } | {
            readonly h: number;
            readonly s: number;
            readonly v: number;
            readonly a?: number | undefined;
        } | {
            readonly h: number;
            readonly s: number;
            readonly l: number;
            readonly a?: number | undefined;
        })[])[]>;
        swatchesMaxHeight: {
            type: (StringConstructor | NumberConstructor)[];
            default: number;
        };
        modelValue: {
            type: PropType<string | Record<string, unknown> | null | undefined>;
        };
    }>> & {
        "onUpdate:modelValue"?: ((color: any) => any) | undefined;
        "onUpdate:mode"?: ((mode: "rgb" | "rgba" | "hsl" | "hsla" | "hex" | "hexa") => any) | undefined;
    }, {}, {}, {}, {}, {
        style: vue.StyleValue;
        mode: "rgb" | "rgba" | "hsl" | "hsla" | "hex" | "hexa";
        width: NonNullable<string | number>;
        disabled: boolean;
        tag: string;
        rounded: string | number | boolean;
        tile: boolean;
        dotSize: string | number;
        modes: readonly ("rgb" | "rgba" | "hsl" | "hsla" | "hex" | "hexa")[];
        canvasHeight: string | number;
        hideCanvas: boolean;
        hideSliders: boolean;
        hideInputs: boolean;
        showSwatches: boolean;
        swatchesMaxHeight: string | number;
    }>;
    __isFragment?: undefined;
    __isTeleport?: undefined;
    __isSuspense?: undefined;
} & vue.ComponentOptionsBase<Readonly<vue.ExtractPropTypes<{
    class: PropType<any>;
    style: {
        type: PropType<vue.StyleValue>;
        default: null;
    };
    width: {
        type: PropType<NonNullable<string | number>>;
        default: NonNullable<string | number>;
    };
    theme: StringConstructor;
    color: StringConstructor;
    tag: {
        type: StringConstructor;
        default: string;
    };
    border: (StringConstructor | NumberConstructor | BooleanConstructor)[];
    position: {
        type: PropType<"fixed" | "absolute" | "relative" | "static" | "sticky">;
        validator: (v: any) => boolean;
    };
    rounded: {
        type: (StringConstructor | NumberConstructor | BooleanConstructor)[];
        default: undefined;
    };
    tile: BooleanConstructor;
    elevation: {
        type: (StringConstructor | NumberConstructor)[];
        validator(v: any): boolean;
    };
    canvasHeight: {
        type: (StringConstructor | NumberConstructor)[];
        default: number;
    };
    disabled: BooleanConstructor;
    dotSize: {
        type: (StringConstructor | NumberConstructor)[];
        default: number;
    };
    hideCanvas: BooleanConstructor;
    hideSliders: BooleanConstructor;
    hideInputs: BooleanConstructor;
    mode: {
        type: PropType<"rgb" | "rgba" | "hsl" | "hsla" | "hex" | "hexa">;
        default: string;
        validator: (v: string) => boolean;
    };
    modes: {
        type: PropType<readonly ("rgb" | "rgba" | "hsl" | "hsla" | "hex" | "hexa")[]>;
        default: () => string[];
        validator: (v: any) => boolean;
    };
    showSwatches: BooleanConstructor;
    swatches: PropType<readonly (readonly (string | number | {
        readonly r: number;
        readonly g: number;
        readonly b: number;
        readonly a?: number | undefined;
    } | {
        readonly h: number;
        readonly s: number;
        readonly v: number;
        readonly a?: number | undefined;
    } | {
        readonly h: number;
        readonly s: number;
        readonly l: number;
        readonly a?: number | undefined;
    })[])[]>;
    swatchesMaxHeight: {
        type: (StringConstructor | NumberConstructor)[];
        default: number;
    };
    modelValue: {
        type: PropType<string | Record<string, unknown> | null | undefined>;
    };
}>> & {
    "onUpdate:modelValue"?: ((color: any) => any) | undefined;
    "onUpdate:mode"?: ((mode: "rgb" | "rgba" | "hsl" | "hsla" | "hex" | "hexa") => any) | undefined;
}, {}, unknown, {}, {}, vue.ComponentOptionsMixin, vue.ComponentOptionsMixin, {
    'update:modelValue': (color: any) => true;
    'update:mode': (mode: keyof typeof modes) => true;
}, string, {
    style: vue.StyleValue;
    mode: "rgb" | "rgba" | "hsl" | "hsla" | "hex" | "hexa";
    width: NonNullable<string | number>;
    disabled: boolean;
    tag: string;
    rounded: string | number | boolean;
    tile: boolean;
    dotSize: string | number;
    modes: readonly ("rgb" | "rgba" | "hsl" | "hsla" | "hex" | "hexa")[];
    canvasHeight: string | number;
    hideCanvas: boolean;
    hideSliders: boolean;
    hideInputs: boolean;
    showSwatches: boolean;
    swatchesMaxHeight: string | number;
}, {}, string, {}> & vue.VNodeProps & vue.AllowedComponentProps & vue.ComponentCustomProps & FilterPropsOptions<{
    class: PropType<any>;
    style: {
        type: PropType<vue.StyleValue>;
        default: null;
    };
    width: {
        type: PropType<NonNullable<string | number>>;
        default: NonNullable<string | number>;
    };
    theme: StringConstructor;
    color: StringConstructor;
    tag: {
        type: StringConstructor;
        default: string;
    };
    border: (StringConstructor | NumberConstructor | BooleanConstructor)[];
    position: {
        type: PropType<"fixed" | "absolute" | "relative" | "static" | "sticky">;
        validator: (v: any) => boolean;
    };
    rounded: {
        type: (StringConstructor | NumberConstructor | BooleanConstructor)[];
        default: undefined;
    };
    tile: BooleanConstructor;
    elevation: {
        type: (StringConstructor | NumberConstructor)[];
        validator(v: any): boolean;
    };
    canvasHeight: {
        type: (StringConstructor | NumberConstructor)[];
        default: number;
    };
    disabled: BooleanConstructor;
    dotSize: {
        type: (StringConstructor | NumberConstructor)[];
        default: number;
    };
    hideCanvas: BooleanConstructor;
    hideSliders: BooleanConstructor;
    hideInputs: BooleanConstructor;
    mode: {
        type: PropType<"rgb" | "rgba" | "hsl" | "hsla" | "hex" | "hexa">;
        default: string;
        validator: (v: string) => boolean;
    };
    modes: {
        type: PropType<readonly ("rgb" | "rgba" | "hsl" | "hsla" | "hex" | "hexa")[]>;
        default: () => string[];
        validator: (v: any) => boolean;
    };
    showSwatches: BooleanConstructor;
    swatches: PropType<readonly (readonly (string | number | {
        readonly r: number;
        readonly g: number;
        readonly b: number;
        readonly a?: number | undefined;
    } | {
        readonly h: number;
        readonly s: number;
        readonly v: number;
        readonly a?: number | undefined;
    } | {
        readonly h: number;
        readonly s: number;
        readonly l: number;
        readonly a?: number | undefined;
    })[])[]>;
    swatchesMaxHeight: {
        type: (StringConstructor | NumberConstructor)[];
        default: number;
    };
    modelValue: {
        type: PropType<string | Record<string, unknown> | null | undefined>;
    };
}, vue.ExtractPropTypes<{
    class: PropType<any>;
    style: {
        type: PropType<vue.StyleValue>;
        default: null;
    };
    width: {
        type: PropType<NonNullable<string | number>>;
        default: NonNullable<string | number>;
    };
    theme: StringConstructor;
    color: StringConstructor;
    tag: {
        type: StringConstructor;
        default: string;
    };
    border: (StringConstructor | NumberConstructor | BooleanConstructor)[];
    position: {
        type: PropType<"fixed" | "absolute" | "relative" | "static" | "sticky">;
        validator: (v: any) => boolean;
    };
    rounded: {
        type: (StringConstructor | NumberConstructor | BooleanConstructor)[];
        default: undefined;
    };
    tile: BooleanConstructor;
    elevation: {
        type: (StringConstructor | NumberConstructor)[];
        validator(v: any): boolean;
    };
    canvasHeight: {
        type: (StringConstructor | NumberConstructor)[];
        default: number;
    };
    disabled: BooleanConstructor;
    dotSize: {
        type: (StringConstructor | NumberConstructor)[];
        default: number;
    };
    hideCanvas: BooleanConstructor;
    hideSliders: BooleanConstructor;
    hideInputs: BooleanConstructor;
    mode: {
        type: PropType<"rgb" | "rgba" | "hsl" | "hsla" | "hex" | "hexa">;
        default: string;
        validator: (v: string) => boolean;
    };
    modes: {
        type: PropType<readonly ("rgb" | "rgba" | "hsl" | "hsla" | "hex" | "hexa")[]>;
        default: () => string[];
        validator: (v: any) => boolean;
    };
    showSwatches: BooleanConstructor;
    swatches: PropType<readonly (readonly (string | number | {
        readonly r: number;
        readonly g: number;
        readonly b: number;
        readonly a?: number | undefined;
    } | {
        readonly h: number;
        readonly s: number;
        readonly v: number;
        readonly a?: number | undefined;
    } | {
        readonly h: number;
        readonly s: number;
        readonly l: number;
        readonly a?: number | undefined;
    })[])[]>;
    swatchesMaxHeight: {
        type: (StringConstructor | NumberConstructor)[];
        default: number;
    };
    modelValue: {
        type: PropType<string | Record<string, unknown> | null | undefined>;
    };
}>>;
type VColorPicker = InstanceType<typeof VColorPicker>;

export { VColorPicker };
