/// <reference types="vite/client" />
declare module 'vue3-shortkey';
declare module '*.vue' {
	import { DefineComponent } from 'vue';
	const component: DefineComponent<{}, {}, any>;
	export default component;
  }