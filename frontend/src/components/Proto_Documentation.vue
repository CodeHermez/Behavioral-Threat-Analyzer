<script setup>
const apiEndpoints = [
  {
    method: "POST",
    endpoint: "/modal-sample/",
    description: "Analyze a single employee profile",
  },
  {
    method: "POST",
    endpoint: "/modal-csv/analyze/",
    description: "Upload and analyze CSV datasets",
  },
  {
    method: "GET",
    endpoint: "/modal-csv/results/",
    description: "Retrieve paginated analysis results",
  },
];
</script>

<template>
  <v-container max-width="1200" class="py-8">
    <div class="mb-8">
      <h1 class="text-h3 font-weight-bold mb-2">
        Behavioral Threat Analyzer Documentation
      </h1>

      <p class="text-subtitle-1 text-medium-emphasis">
        Frontend system architecture and API integration documentation.
      </p>
    </div>

    <!-- SYSTEM OVERVIEW -->
    <v-card class="mb-6" elevation="2" border>
      <v-card-title>System Overview</v-card-title>

      <v-card-text>
        <p class="mb-4">
          The Behavioral Threat Analyzer is an AI-assisted insider threat
          detection platform designed to identify suspicious employee behavior
          patterns using machine learning and explainability techniques.
        </p>

        <ul class="pl-6">
          <li>Machine learning threat detection</li>
          <li>CSV batch threat analysis</li>
          <li>Single profile behavioral analysis</li>
          <li>AI-generated explainability summaries</li>
          <li>Risk scoring and classification</li>
          <li>Threat triage visualization</li>
        </ul>
      </v-card-text>
    </v-card>

    <!-- FRONTEND FEATURES -->
    <v-card class="mb-6" elevation="2" border>
      <v-card-title>Frontend Features</v-card-title>

      <v-card-text>
        <v-row>
          <v-col cols="12" md="6">
            <ul class="pl-6">
              <li>Vuetify 3 UI framework</li>
              <li>Vue 3 Composition API</li>
              <li>Axios API communication</li>
              <li>Dynamic pagination</li>
              <li>Interactive threat triage table</li>
            </ul>
          </v-col>

          <v-col cols="12" md="6">
            <ul class="pl-6">
              <li>Expandable explainability panels</li>
              <li>Persistent cached analysis sessions</li>
              <li>Real-time threat filtering</li>
              <li>Confidence-based sorting</li>
              <li>Responsive dashboard design</li>
            </ul>
          </v-col>
        </v-row>
      </v-card-text>
    </v-card>

    <!-- API ENDPOINTS -->
    <v-card class="mb-6" elevation="2" border>
      <v-card-title>Backend API Endpoints</v-card-title>

      <v-table>
        <thead>
          <tr>
            <th>Method</th>
            <th>Endpoint</th>
            <th>Description</th>
          </tr>
        </thead>

        <tbody>
          <tr v-for="api in apiEndpoints" :key="api.endpoint">
            <td>
              <v-chip
                :color="api.method === 'GET' ? 'success' : 'primary'"
                size="small"
              >
                {{ api.method }}
              </v-chip>
            </td>

            <td>
              <code>{{ api.endpoint }}</code>
            </td>

            <td>{{ api.description }}</td>
          </tr>
        </tbody>
      </v-table>
    </v-card>

    <!-- SYSTEM WORKFLOW -->
    <v-card class="mb-6" elevation="2" border>
      <v-card-title>Threat Analysis Workflow</v-card-title>

      <v-card-text>
        <ol class="pl-6">
          <li>User uploads CSV dataset or selects sample profile</li>
          <li>Frontend validates request input</li>
          <li>Axios sends request to Django REST backend</li>
          <li>Backend preprocesses behavioral data</li>
          <li>Machine learning model performs inference</li>
          <li>Explainability engine generates insights</li>
          <li>LLM generates human-readable threat summaries</li>
          <li>Frontend renders threat triage dashboard</li>
        </ol>
      </v-card-text>
    </v-card>

    <!-- TECHNOLOGY STACK -->
    <v-card class="mb-6" elevation="2" border>
      <v-card-title>Technology Stack</v-card-title>

      <v-card-text>
        <v-row>
          <v-col cols="12" md="4">
            <v-card variant="outlined" class="pa-4 text-center">
              <div><b>Frontend</b></div>
              <div class="mt-2">
                Vue 3 <br />
                Vuetify 3 <br />
                Axios <br />
                Vite
              </div>
            </v-card>
          </v-col>

          <v-col cols="12" md="4">
            <v-card variant="outlined" class="pa-4 text-center">
              <div><b>Backend</b></div>

              <div class="mt-2">
                Django REST Framework <br />
                drf-spectacular <br />
                Pandas <br />
                NumPy
              </div>
            </v-card>
          </v-col>

          <v-col cols="12" md="4">
            <v-card variant="outlined" class="pa-4 text-center">
              <div><b>AI/ML</b></div>

              <div class="mt-2">
                Scikit-learn <br />
                Explainability Engine <br />
                LLM Summarization <br />
                Threat Classification
              </div>
            </v-card>
          </v-col>
        </v-row>
      </v-card-text>
    </v-card>
  </v-container>
</template>
