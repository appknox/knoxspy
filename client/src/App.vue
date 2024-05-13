<script lang="ts">
import { defineComponent } from 'vue';
import SideBar from './components/SideBar.vue';

export default defineComponent({
    data() {
        return {
        };
    },
    components:{
        SideBar
    },
})
</script>


<template>
	<SideBar/>
	<router-view />
</template>



<style>
body {
	margin: 0;
}
#app {
	font-family: Avenir, Helvetica, Arial, sans-serif;
	-webkit-font-smoothing: antialiased;
	-moz-osx-font-smoothing: grayscale;
	text-align: center;
	color: #2c3e50;
	display: flex;
    margin: 0;
	flex-direction: row;
}
</style>
