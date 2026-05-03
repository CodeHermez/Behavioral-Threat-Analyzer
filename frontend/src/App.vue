<script setup>
import { ref, onMounted } from "vue";
import Prototype_Analyzer_Comp from "@/components/Prototype_Analyzer_Comp.vue";
const appBackgroundColor = ref("#121212");
const randomizeBackground = () => {
  const randomHue = Math.floor(Math.random() * 360);
  appBackgroundColor.value = `hsl(${randomHue}, 30%, 15%)`;
};
onMounted(() => {
  randomizeBackground();
});
</script>

<!--this is the frontend tags and the background color function that shifts-->
<!--different colors when refresh this is just a gimic more than anything-->
<template>
  <v-app
    :style="{
      backgroundColor: appBackgroundColor,
      transition: 'background-color 0.5s ease',
    }"
  >
    <v-main>
      <Prototype_Analyzer_Comp />
    </v-main>
  </v-app>
</template>

<style scoped></style>
