<script setup>
import { ref, onMounted } from "vue";
import Prototype_Analyzer_Comp from "@/components/Prototype_Analyzer_Comp.vue";
import Proto_Documentation from "@/components/Proto_Documentation.vue";

const currentView = ref("analyzer");
const appBackgroundColor = ref("#121212");
const randomizeBackground = () => {
  const randomHue = Math.floor(Math.random() * 360);
  appBackgroundColor.value = `hsl(${randomHue}, 30%, 15%)`;
};
onMounted(() => {
  randomizeBackground();
});

const setView = async (view) => {
  currentView.value = view;

  if (view === "analyzer") {
    // rehydrate safely
    await nextTick();
    analyzerRef?.restoreSession?.();
  }
};
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
      <v-container fluid>
        <!-- NAV BAR (NO ROUTER NEEDED) -->
        <div class="d-flex justify-end pa-4">
          <v-btn-toggle
            v-model="currentView"
            mandatory
            color="primary"
            variant="outlined"
          >
            <v-btn value="analyzer"> Analyzer </v-btn>

            <v-btn value="docs"> Documentation </v-btn>
          </v-btn-toggle>
        </div>

        <!-- page switch with if statement-->
        <Prototype_Analyzer_Comp v-if="currentView === 'analyzer'" />
        <Proto_Documentation v-else />
      </v-container>
    </v-main>
  </v-app>
</template>

<style scoped></style>
