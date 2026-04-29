import { createApp } from "vue";
import App from "./App.vue";

// --- VUETIFY SETUP ---
// 1. Import Vuetify's core CSS
import "vuetify/styles";
// 2. Import the Material Design Icons CSS
import "@mdi/font/css/materialdesignicons.css";

// 3. Import the Vuetify engine and all its components/directives
import { createVuetify } from "vuetify";
import * as components from "vuetify/components";
import * as directives from "vuetify/directives";

// 4. Create the Vuetify instance
const vuetify = createVuetify({
  components,
  directives,
  icons: {
    defaultSet: "mdi", // Tells Vuetify to use the Material icons we imported
  },
});
// ---------------------

// Create the Vue app, tell it to use Vuetify, and mount it to the screen
createApp(App).use(vuetify).mount("#app");
