import { mergeProps as _mergeProps, resolveDirective as _resolveDirective, createVNode as _createVNode } from "vue";
// Components
import { VTreeviewGroup } from "./VTreeviewGroup.mjs";
import { VTreeviewItem } from "./VTreeviewItem.mjs";
import { VCheckboxBtn } from "../../components/VCheckbox/index.mjs"; // Utilities
import { shallowRef } from 'vue';
import { genericComponent, propsFactory } from "../../util/index.mjs"; // Types
export const makeVTreeviewChildrenProps = propsFactory({
  loadChildren: Function,
  loadingIcon: {
    type: String,
    default: '$loading'
  },
  items: Array,
  selectable: Boolean
}, 'VTreeviewChildren');
export const VTreeviewChildren = genericComponent()({
  name: 'VTreeviewChildren',
  props: makeVTreeviewChildrenProps(),
  setup(props, _ref) {
    let {
      emit,
      slots
    } = _ref;
    const isLoading = shallowRef(false);
    const hasLoaded = shallowRef(false);
    function checkChildren(item) {
      return new Promise(resolve => {
        if (!props.items?.length || !props.loadChildren || hasLoaded.value) return resolve();
        isLoading.value = true;
        props.loadChildren(item).then(resolve);
      }).then(() => {
        hasLoaded.value = true;
      }).finally(() => {
        isLoading.value = false;
      });
    }
    function onClick(e, item) {
      e.stopPropagation();
      checkChildren(item);
    }
    return () => slots.default?.() ?? props.items?.map(_ref2 => {
      let {
        children,
        props: itemProps,
        raw: item
      } = _ref2;
      const slotsWithItem = {
        prepend: slots.prepend ? slotProps => slots.prepend?.({
          ...slotProps,
          item
        }) : props.selectable ? _ref3 => {
          let {
            isSelected,
            isIndeterminate
          } = _ref3;
          return _createVNode(VCheckboxBtn, {
            "key": item.value,
            "tabindex": "-1",
            "modelValue": isSelected,
            "loading": isLoading.value,
            "indeterminate": isIndeterminate,
            "onClick": e => onClick(e, item)
          }, null);
        } : undefined,
        append: slots.append ? slotProps => slots.append?.({
          ...slotProps,
          item
        }) : undefined,
        title: slots.title ? slotProps => slots.title?.({
          ...slotProps,
          item
        }) : undefined
      };
      const treeviewGroupProps = VTreeviewGroup.filterProps(itemProps);
      const treeviewChildrenProps = VTreeviewChildren.filterProps(props);
      return children ? _createVNode(VTreeviewGroup, _mergeProps({
        "value": itemProps?.value
      }, treeviewGroupProps), {
        activator: _ref4 => {
          let {
            props: activatorProps
          } = _ref4;
          return _createVNode(VTreeviewItem, _mergeProps(itemProps, activatorProps, {
            "loading": isLoading.value,
            "onClick": e => onClick(e, item)
          }), slotsWithItem);
        },
        default: () => _createVNode(VTreeviewChildren, _mergeProps(treeviewChildrenProps, {
          "items": children
        }), slots)
      }) : slots.item?.({
        props: itemProps
      }) ?? _createVNode(VTreeviewItem, itemProps, slotsWithItem);
    });
  }
});
//# sourceMappingURL=VTreeviewChildren.mjs.map