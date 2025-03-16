"use strict";const o=require("vue"),f=require("./useIconOnlyButton.js"),p=require("./_plugin-vue_export-helper.js"),y=o.defineComponent({name:"CdxToggleButton",props:{modelValue:{type:Boolean,default:!1},disabled:{type:Boolean,default:!1},quiet:{type:Boolean,default:!1}},emits:["update:modelValue"],setup(e,{emit:t,slots:s,attrs:u}){const d=f.useIconOnlyButton(s.default,u,"CdxToggleButton"),l=o.ref(!1),n=o.computed(()=>({"cdx-toggle-button--quiet":e.quiet,"cdx-toggle-button--framed":!e.quiet,"cdx-toggle-button--toggled-on":e.modelValue,"cdx-toggle-button--toggled-off":!e.modelValue,"cdx-toggle-button--icon-only":d.value,"cdx-toggle-button--is-active":l.value})),a=()=>{t("update:modelValue",!e.modelValue)},i=c=>{l.value=c};function r(){i(!0)}function g(){i(!1),a()}return{rootClasses:n,onClick:a,onKeyDown:r,onKeyUp:g}}}),m=["aria-pressed","disabled"];function b(e,t,s,u,d,l){return o.openBlock(),o.createElementBlock("button",{class:o.normalizeClass(["cdx-toggle-button",e.rootClasses]),"aria-pressed":e.modelValue,disabled:e.disabled,onClick:t[0]||(t[0]=(...n)=>e.onClick&&e.onClick(...n)),onKeydown:t[1]||(t[1]=o.withKeys(o.withModifiers((...n)=>e.onKeyDown&&e.onKeyDown(...n),["prevent"]),["space","enter"])),onKeyup:t[2]||(t[2]=o.withKeys((...n)=>e.onKeyUp&&e.onKeyUp(...n),["space","enter"]))},[o.renderSlot(e.$slots,"default")],42,m)}const C=p._export_sfc(y,[["render",b]]);module.exports=C;
