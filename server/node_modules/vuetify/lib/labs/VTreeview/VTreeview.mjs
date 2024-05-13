import { createVNode as _createVNode, mergeProps as _mergeProps, resolveDirective as _resolveDirective } from "vue";
// Components
import { makeVTreeviewChildrenProps, VTreeviewChildren } from "./VTreeviewChildren.mjs";
import { makeVListProps, useListItems, VList } from "../../components/VList/VList.mjs"; // Composables
import { provideDefaults } from "../../composables/defaults.mjs";
import { makeFilterProps, useFilter } from "../../composables/filter.mjs";
import { useProxiedModel } from "../../composables/proxiedModel.mjs"; // Utilities
import { computed, provide, ref, toRef, watch } from 'vue';
import { genericComponent, omit, propsFactory, useRender } from "../../util/index.mjs"; // Types
import { VTreeviewSymbol } from "./shared.mjs";
function flatten(items) {
  let flat = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : [];
  for (const item of items) {
    flat.push(item);
    if (item.children) flatten(item.children, flat);
  }
  return flat;
}
export const makeVTreeviewProps = propsFactory({
  openAll: Boolean,
  search: String,
  ...makeFilterProps({
    filterKeys: ['title']
  }),
  ...makeVTreeviewChildrenProps(),
  ...omit(makeVListProps({
    collapseIcon: '$treeviewCollapse',
    expandIcon: '$treeviewExpand',
    selectStrategy: 'independent',
    openStrategy: 'multiple',
    slim: true
  }), ['nav'])
}, 'VTreeview');
export const VTreeview = genericComponent()({
  name: 'VTreeview',
  props: makeVTreeviewProps(),
  emits: {
    'update:opened': val => true,
    'update:activated': val => true,
    'update:selected': val => true,
    'click:open': value => true,
    'click:select': value => true
  },
  setup(props, _ref) {
    let {
      slots
    } = _ref;
    const {
      items
    } = useListItems(props);
    const activeColor = toRef(props, 'activeColor');
    const baseColor = toRef(props, 'baseColor');
    const color = toRef(props, 'color');
    const opened = useProxiedModel(props, 'opened');
    const activated = useProxiedModel(props, 'activated');
    const selected = useProxiedModel(props, 'selected');
    const vListRef = ref();
    const flatItems = computed(() => flatten(items.value));
    const search = toRef(props, 'search');
    const {
      filteredItems
    } = useFilter(props, flatItems, search);
    const visibleIds = computed(() => {
      if (!search.value) {
        return null;
      }
      return new Set(filteredItems.value.flatMap(item => {
        return [...getPath(item.props.value), ...getChildren(item.props.value)];
      }));
    });
    function getPath(id) {
      const path = [];
      let parent = id;
      while (parent != null) {
        path.unshift(parent);
        parent = vListRef.value?.parents.get(parent);
      }
      return path;
    }
    function getChildren(id) {
      const arr = [];
      const queue = (vListRef.value?.children.get(id) ?? []).slice();
      while (queue.length) {
        const child = queue.shift();
        if (!child) continue;
        arr.push(child);
        queue.push(...(vListRef.value?.children.get(child) ?? []).slice());
      }
      return arr;
    }
    watch(() => props.openAll, val => {
      opened.value = val ? openAll(items.value) : [];
    }, {
      immediate: true
    });
    function openAll(item) {
      let ids = [];
      for (const i of item) {
        if (!i.children) continue;
        ids.push(i.value);
        if (i.children) {
          ids = ids.concat(openAll(i.children));
        }
      }
      return ids;
    }
    provide(VTreeviewSymbol, {
      visibleIds
    });
    provideDefaults({
      VTreeviewGroup: {
        activeColor,
        baseColor,
        color,
        collapseIcon: toRef(props, 'collapseIcon'),
        expandIcon: toRef(props, 'expandIcon')
      },
      VTreeviewItem: {
        activeClass: toRef(props, 'activeClass'),
        activeColor,
        baseColor,
        color,
        density: toRef(props, 'density'),
        disabled: toRef(props, 'disabled'),
        lines: toRef(props, 'lines'),
        variant: toRef(props, 'variant')
      }
    });
    useRender(() => {
      const listProps = VList.filterProps(props);
      const treeviewChildrenProps = VTreeviewChildren.filterProps(props);
      return _createVNode(VList, _mergeProps({
        "ref": vListRef
      }, listProps, {
        "class": ['v-treeview', props.class],
        "style": props.style,
        "opened": opened.value,
        "onUpdate:opened": $event => opened.value = $event,
        "activated": activated.value,
        "onUpdate:activated": $event => activated.value = $event,
        "selected": selected.value,
        "onUpdate:selected": $event => selected.value = $event
      }), {
        default: () => [_createVNode(VTreeviewChildren, _mergeProps(treeviewChildrenProps, {
          "items": items.value
        }), slots)]
      });
    });
    return {
      open
    };
  }
});
//# sourceMappingURL=VTreeview.mjs.map