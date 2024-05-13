import { generateImports, resolveVuetifyBase, isObject, normalizePath, includes, transformAssetUrls } from '@vuetify/loader-shared';
export { transformAssetUrls } from '@vuetify/loader-shared';
import { extname } from 'path';
import { URLSearchParams } from 'url';
import path from 'upath';

function parseId(id) {
  const [pathname, query] = id.split("?");
  return {
    query: query ? Object.fromEntries(new URLSearchParams(query)) : null,
    path: pathname ?? id
  };
}
function importPlugin(options) {
  return {
    name: "vuetify:import",
    configResolved(config) {
      if (config.plugins.findIndex((plugin) => plugin.name === "vuetify:import") < config.plugins.findIndex((plugin) => plugin.name === "vite:vue")) {
        throw new Error("Vuetify plugin must be loaded after the vue plugin");
      }
    },
    async transform(code, id) {
      const { query, path } = parseId(id);
      if ((!query || !("vue" in query)) && extname(path) === ".vue" && !/^import { render as _sfc_render } from ".*"$/m.test(code) || query && "vue" in query && (query.type === "template" || query.type === "script" && query.setup === "true")) {
        const { code: imports, source } = generateImports(code, options);
        return {
          code: source + imports,
          map: null
        };
      }
      return null;
    }
  };
}

function isSubdir(root, test) {
  const relative = path.relative(root, test);
  return relative && !relative.startsWith("..") && !path.isAbsolute(relative);
}
function stylesPlugin(options) {
  const vuetifyBase = resolveVuetifyBase();
  let configFile;
  const tempFiles = /* @__PURE__ */ new Map();
  return {
    name: "vuetify:styles",
    enforce: "pre",
    configResolved(config) {
      if (isObject(options.styles)) {
        if (path.isAbsolute(options.styles.configFile)) {
          configFile = options.styles.configFile;
        } else {
          configFile = path.join(config.root || process.cwd(), options.styles.configFile);
        }
      }
    },
    async resolveId(source, importer, { custom }) {
      if (source === "vuetify/styles" || importer && source.endsWith(".css") && isSubdir(vuetifyBase, path.isAbsolute(source) ? source : importer)) {
        if (options.styles === "none") {
          return "\0__void__";
        } else if (options.styles === "sass") {
          const target = source.replace(/\.css$/, ".sass");
          return this.resolve(target, importer, { skipSelf: true, custom });
        } else if (isObject(options.styles)) {
          const resolution = await this.resolve(source, importer, { skipSelf: true, custom });
          if (!resolution)
            return null;
          const target = resolution.id.replace(/\.css$/, ".sass");
          const file = path.relative(path.join(vuetifyBase, "lib"), target);
          const contents = `@use "${normalizePath(configFile)}"
@use "${normalizePath(target)}"`;
          tempFiles.set(file, contents);
          return `\0plugin-vuetify:${file}`;
        }
      } else if (source.startsWith("/plugin-vuetify:")) {
        return "\0" + source.slice(1);
      } else if (source.startsWith("/@id/__x00__plugin-vuetify:")) {
        return "\0" + source.slice(12);
      }
      return null;
    },
    load(id) {
      if (/^\0__void__(\?.*)?$/.test(id)) {
        return "";
      }
      if (id.startsWith("\0plugin-vuetify")) {
        const file = /^\0plugin-vuetify:(.*?)(\?.*)?$/.exec(id)[1];
        return tempFiles.get(file);
      }
      return null;
    }
  };
}

function vuetify(_options = {}) {
  const options = {
    autoImport: true,
    styles: true,
    ..._options
  };
  const plugins = [];
  if (options.autoImport) {
    plugins.push(importPlugin(options));
  }
  if (includes(["none", "sass"], options.styles) || isObject(options.styles)) {
    plugins.push(stylesPlugin(options));
  }
  return plugins;
}
vuetify.transformAssetUrls = transformAssetUrls;

export { vuetify as default };
