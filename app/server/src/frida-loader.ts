import type frida from "frida";

type FridaRuntime = typeof frida;
type FridaModule = { default: FridaRuntime };

const dynamicImport = new Function(
	"specifier",
	"return import(specifier);"
) as (specifier: string) => Promise<FridaModule>;

let fridaRuntimePromise: Promise<FridaRuntime> | null = null;

export function getFridaRuntime(): Promise<FridaRuntime> {
	if (!fridaRuntimePromise) {
		fridaRuntimePromise = dynamicImport("frida").then((module) => module.default);
	}

	return fridaRuntimePromise;
}
