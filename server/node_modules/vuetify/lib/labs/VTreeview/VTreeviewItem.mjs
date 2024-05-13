import { mergeProps as _mergeProps, createVNode as _createVNode, Fragment as _Fragment } from "vue";
// Styles
import "./VTreeviewItem.css";

// Components
import { VBtn } from "../../components/VBtn/index.mjs";
import { VListItemAction } from "../../components/VList/index.mjs";
import { makeVListItemProps, VListItem } from "../../components/VList/VListItem.mjs"; // Composables
import { IconValue } from "../../composables/icons.mjs";
import { useLink } from "../../composables/router.mjs"; // Utilities
import { computed, inject, ref } from 'vue';
import { genericComponent, propsFactory, useRender } from "../../util/index.mjs"; // Types
import { VTreeviewSymbol } from "./shared.mjs";
import { VProgressCircular } from "../allComponents.mjs";
export const makeVTreeviewItemProps = propsFactory({
  loading: Boolean,
  toggleIcon: IconValue,
  ...makeVListItemProps({
    slim: true
  })
}, 'VTreeviewItem');
export const VTreeviewItem = genericComponent()({
  name: 'VTreeviewItem',
  props: makeVTreeviewItemProps(),
  setup(props, _ref) {
    let {
      attrs,
      slots,
      emit
    } = _ref;
    const link = useLink(props, attrs);
    const id = computed(() => props.value === undefined ? link.href.value : props.value);
    const vListItemRef = ref();
    const isClickable = computed(() => !props.disabled && props.link !== false && (props.link || link.isClickable.value || props.value != null && !!vListItemRef.value?.list));
    function onClick(e) {
      if (!vListItemRef.value?.isGroupActivator || !isClickable.value) return;
      props.value != null && vListItemRef.value?.select(!vListItemRef.value?.isSelected, e);
    }
    function onKeyDown(e) {
      if (e.key === 'Enter' || e.key === ' ') {
        e.preventDefault();
        onClick(e);
      }
    }
    const visibleIds = inject(VTreeviewSymbol, {
      visibleIds: ref()
    }).visibleIds;
    useRender(() => {
      const listItemProps = VListItem.filterProps(props);
      const hasPrepend = slots.prepend || props.toggleIcon;
      return _createVNode(VListItem, _mergeProps({
        "ref": vListItemRef
      }, listItemProps, {
        "class": ['v-treeview-item', {
          'v-treeview-item--filtered': visibleIds.value && !visibleIds.value.has(id.value)
        }, props.class],
        "onClick": onClick,
        "onKeydown": isClickable.value && onKeyDown
      }), {
        ...slots,
        prepend: hasPrepend ? slotProps => {
          return _createVNode(_Fragment, null, [props.toggleIcon && _createVNode(VListItemAction, {
            "start": false
          }, {
            default: () => [_createVNode(VBtn, {
              "density": "compact",
              "icon": props.toggleIcon,
              "loading": props.loading,
              "variant": "text"
            }, {
              loader() {
                return _createVNode(VProgressCircular, {
                  "indeterminate": "disable-shrink",
                  "size": "20",
                  "width": "2"
                }, null);
              }
            })]
          }), slots.prepend?.(slotProps)]);
        } : undefined
      });
    });
    return {};
  }
});
//# sourceMappingURL=VTreeviewItem.mjs.map