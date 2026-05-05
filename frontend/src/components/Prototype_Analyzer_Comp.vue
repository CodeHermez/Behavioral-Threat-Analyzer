<script setup>
import { ref, watch, computed } from "vue";
import axios from "axios";

const file = ref(null);
const sampleId = ref(null);
const loading = ref(false);
const error = ref(null);
const analysisType = ref(null);
const url = import.meta.env.VITE_API_BASE_URL;
const evaluation = ref(null);
const results = ref(null);
const summary = ref(null);
const insights = ref(null);
const page = ref(1);
const itemsPerPage = ref(10);
const filter = ref("all"); // all | malicious | normal
const sortBy = ref("confidence");
const order = ref("desc");
const totalPages = ref(0);
const totalItems = ref(0);
const analysisId = ref(null);
const sampleOptions = [
  { title: "Sample 1: Standard Employee (Normal)", value: "sample_normal" },
  {
    title: "Sample 2: High-Risk Activity (Suspicious)",
    value: "sample_suspicious",
  },
];
const filterOptions = [
  { title: "All", value: "all" },
  { title: "Malicious", value: "malicious" },
  { title: "Normal", value: "normal" },
];
const resetForm = () => {
  file.value = null;
  sampleId.value = null;
  results.value = null;
  summary.value = null;
  insights.value = null;
  analysisId.value = null;
  page.value = 1;
};

// This is the structure of the sample profiles in object form instead of csv form.
const sampleProfiles = {
  sample_normal: {
    display_info: {
      title: "Standard Office Worker",
      department: "Engineering Department",
    },
    payload: {
      index: 0,
      employee_seniority_years: 22,
      employee_classification: 2,
      has_criminal_record: 0,
      total_printed_pages: 5,
      num_printed_pages_off_hours: 0,
      total_files_burned: 0,
      burned_from_other: 0,
      is_abroad: 0,
      trip_day_number: 0.0,
      hostility_country_level: 0,
      num_entries: 1,
      num_unique_campus: 1,
      late_exit_flag: 0,
      entry_during_weekend: 0,
      is_malicious: 0,
      "categ_Engineering Department": true,
      "categ_Executive Management": false,
      categ_Finance: false,
      "categ_Human Resources": false,
      "categ_Information Technology": false,
    },
  },
  sample_suspicious: {
    display_info: {
      title: "Contractor / Off-Hours Activity",
      department: "Information Technology",
    },
    payload: {
      index: 1,
      employee_seniority_years: 2,
      employee_classification: 1,
      has_criminal_record: 0,
      total_printed_pages: 150,
      num_printed_pages_off_hours: 45,
      total_files_burned: 25,
      burned_from_other: 1,
      is_abroad: 0,
      trip_day_number: 0.0,
      hostility_country_level: 0,
      num_entries: 3,
      num_unique_campus: 2,
      late_exit_flag: 1,
      entry_during_weekend: 1,
      is_malicious: 0,
      "categ_Engineering Department": false,
      "categ_Executive Management": false,
      categ_Finance: false,
      "categ_Human Resources": false,
      "categ_Information Technology": true,
    },
  },
};

// Helper to format feature names for the UI
const formatFeatureName = (name) =>
  name.replace(/_/g, " ").replace(/\b\w/g, (l) => l.toUpperCase());
const fetchResults = async () => {
  if (!analysisId.value) return;

  loading.value = true;

  try {
    const { data } = await axios.get(`${url}modal-csv/results/`, {
      params: {
        analysis_id: analysisId.value,
        page: page.value,
        page_size: itemsPerPage.value,
        filter: filter.value,
        sort_by: sortBy.value,
        order: order.value,
      },
    });

    results.value = data.data;
    totalPages.value = data.pagination.total_pages;
    totalItems.value = data.pagination.total;
  } catch (err) {
    console.error(err);
    error.value = "Failed to fetch paginated results";
  } finally {
    loading.value = false;
  }
};
const analyzeData = async () => {
  loading.value = true;
  error.value = null;

  results.value = null;
  summary.value = null;
  insights.value = null;

  try {
    if (file.value) {
      analysisType.value = "csv";

      const formData = new FormData();
      const actualFile = Array.isArray(file.value) ? file.value[0] : file.value;

      if (actualFile) formData.append("csvFile", actualFile);

      const { data } = await axios.post(`${url}modal-csv/analyze/`, formData);

      if (data) {
        analysisId.value = data.analysis_id;

        results.value = data.data;
        summary.value = data.summary;
        insights.value = data.feature_insights;
        totalPages.value = data.pagination.total_pages;

        evaluation.value = data.summary.evaluation;
      }
      // if (data?.status === "success") {
      //   results.value = data.data;
      //   summary.value = data.summary;
      //   insights.value = data.feature_insights;
      //   totalPages.value = data.pagination.total_pages;
      //   totalItems.value = data.pagination.total;
      //   evaluation.value = data.summary.evaluation;
      // }
      else {
        throw new Error("Unexpected response structure");
      }
    } else if (sampleId.value) {
      analysisType.value = "single";

      const payload = sampleProfiles[sampleId.value].payload;

      const { data } = await axios.post(`${url}modal-sample/`, payload, {
        headers: { "Content-Type": "application/json" },
      });

      if (data?.status === "success") {
        results.value = data.data;
      } else {
        throw new Error("Unexpected response structure");
      }
    }
  } catch (err) {
    console.error(err);
    error.value =
      err.response?.data?.error ||
      err.response?.data?.message ||
      err.message ||
      "Server connection failed";
  } finally {
    loading.value = false;
  }
};

let isFetching = false;

watch([page, itemsPerPage, filter, sortBy, order], async () => {
  if (analysisType.value !== "csv") return;
  await fetchResults();
});
watch([filter, sortBy, order], () => {
  page.value = 1;
});
</script>

<template>
  <v-container max-width="1200" class="py-8">
    <div class="text-center mb-8">
      <h1 class="text-h3 font-weight-bold mb-2">Behavioral Threat Analyzer</h1>
      <p class="text-subtitle-1 text-medium-emphasis">
        Upload a dataset for csv triage, or select a sample profile for deep
        analysis.
      </p>
    </div>

    <v-card class="mb-6" elevation="2" border>
      <v-card-text>
        <v-form @submit.prevent="analyzeData">
          <v-row>
            <v-col cols="12" md="6">
              <div class="text-subtitle-2 font-weight-bold mb-2">
                Option 1: Upload Dataset
              </div>
              <v-file-input
                v-model="file"
                accept=".csv"
                label="Upload Evaluation Dataset (.csv)"
                prepend-icon="mdi-file-delimited"
                variant="outlined"
                density="comfortable"
                clearable
                :disabled="!!sampleId"
                hint="For scanning large batches of logs"
                persistent-hint
              />
              <v-select
                v-model="filter"
                :items="filterOptions"
                label="Filter"
                density="compact"
              />
              <v-select
                v-model="sortBy"
                :items="[
                  { title: 'Confidence', value: 'confidence' },
                  { title: 'Prediction', value: 'prediction' },
                ]"
                label="Sort By"
                density="compact"
              />

              <v-select
                v-model="order"
                :items="[
                  { title: 'Descending', value: 'desc' },
                  { title: 'Ascending', value: 'asc' },
                ]"
                label="Order"
                density="compact"
              />
            </v-col>

            <v-col cols="12" md="6">
              <div class="text-subtitle-2 font-weight-bold mb-2">
                Option 2: Select Sample Profile
              </div>
              <v-select
                v-model="sampleId"
                :items="sampleOptions"
                item-title="title"
                item-value="value"
                label="-- Choose a sample --"
                prepend-icon="mdi-account-search"
                variant="outlined"
                density="comfortable"
                clearable
                :disabled="!!file"
                hint="For evaluating individual risk profiles"
                persistent-hint
              />
            </v-col>
          </v-row>

          <v-divider class="my-4" />

          <v-row>
            <v-col cols="12" md="6" class="d-flex justify-end">
              <v-btn
                type="submit"
                color="primary"
                size="large"
                :loading="loading"
                :disabled="!file && !sampleId"
                prepend-icon="mdi-brain"
              >
                Run Threat Analysis
              </v-btn>
            </v-col>
            <v-col cols="12" md="6">
              <v-btn @click="resetForm" variant="text">Reset</v-btn>
            </v-col>
          </v-row>
        </v-form>
      </v-card-text>
    </v-card>

    <v-alert
      v-if="error"
      type="error"
      title="Analysis Failed"
      :text="error"
      closable
      class="mb-6"
      @click:close="error = null"
    />

    <v-expand-transition>
      <div v-if="results && !loading" class="mt-6">
        <div v-if="analysisType === 'csv' && summary && insights">
          <v-row class="mb-4">
            <v-col cols="12" sm="6" md="3">
              <v-card elevation="2" border class="h-100 bg-blue-grey-lighten-5">
                <v-card-text>
                  <div class="text-overline mb-1">Logs Scanned</div>
                  <div class="text-h3 font-weight-bold">
                    {{ summary.total_scanned }}
                  </div>
                </v-card-text>
              </v-card>
            </v-col>

            <v-col cols="12" sm="6" md="3">
              <v-card
                elevation="2"
                border
                variant="tonal"
                color="error"
                class="h-100"
              >
                <v-card-text>
                  <div class="text-overline mb-1">Threats Detected</div>
                  <div class="text-h3 font-weight-bold">
                    {{ summary.threats_found }}
                  </div>
                  <div class="text-caption font-weight-bold">
                    {{ summary.threat_percentage }}% of batch
                  </div>
                </v-card-text>
              </v-card>
            </v-col>

            <v-col cols="12" sm="6" md="3">
              <v-card elevation="2" border class="h-100">
                <v-card-text>
                  <div class="text-overline mb-1">Threat Severity</div>
                  <div class="d-flex align-center mt-2">
                    <v-badge dot color="error" class="mr-3"></v-badge>
                    <span class="font-weight-bold"
                      >High: {{ summary.high_risk }}</span
                    >
                  </div>
                  <div class="d-flex align-center mt-3">
                    <v-badge dot color="warning" class="mr-3"></v-badge>
                    <span class="font-weight-bold"
                      >Med: {{ summary.medium_risk }}</span
                    >
                  </div>
                </v-card-text>
              </v-card>
            </v-col>

            <v-col cols="12" sm="6" md="3">
              <v-card elevation="2" border class="h-100">
                <v-card-text>
                  <div class="text-overline mb-1">Top AI Drivers</div>
                  <ul class="text-caption pl-4 text-medium-emphasis">
                    <li
                      v-for="insight in insights"
                      :key="insight.feature"
                      class="mb-1"
                    >
                      {{ formatFeatureName(insight.feature) }} <br />
                      <strong
                        >{{ (insight.importance * 100).toFixed(0) }}%
                        weight</strong
                      >
                    </li>
                  </ul>
                </v-card-text>
              </v-card>
            </v-col>
          </v-row>

          <v-card class="mb-6" elevation="2" border>
            <v-card-title class="bg-grey-lighten-4">
              <v-icon class="me-2">mdi-brain</v-icon>
              AI Threat Summary
            </v-card-title>

            <v-card-text>
              <div v-if="summary?.llm_explanation">
                {{ summary.llm_explanation }}
              </div>

              <div v-else class="text-caption text-medium-emphasis">
                No batch-level explanation generated.
              </div>
            </v-card-text>
          </v-card>

          <v-card elevation="2" border>
            <v-card-title class="bg-grey-lighten-4 d-flex align-center">
              <v-icon
                icon="mdi-shield-alert"
                color="error"
                class="mr-2"
              ></v-icon>
              Triage Roster (Sorted by Risk)
            </v-card-title>
            <v-table density="comfortable" hover>
              <thead>
                <tr>
                  <th class="text-left font-weight-bold">Row ID</th>
                  <th class="text-left font-weight-bold">ML Classification</th>
                  <th class="text-left font-weight-bold">Confidence</th>
                  <th class="text-left font-weight-bold">
                    Key Risk Indicators
                  </th>
                </tr>
              </thead>
              <tbody>
                <template v-for="row in results" :key="row.row_index">
                  <tr
                    :class="
                      row.prediction === 'Malicious' ? 'bg-red-lighten-5' : ''
                    "
                    @click="row.expanded = !row.expanded"
                    style="cursor: pointer"
                  >
                    <td class="font-weight-bold">#{{ row.row_index }}</td>

                    <td>
                      <v-chip
                        :color="
                          row.prediction === 'Malicious' ? 'error' : 'success'
                        "
                        size="small"
                      >
                        {{ row.prediction }}
                      </v-chip>
                    </td>

                    <td>{{ (row.confidence * 100).toFixed(1) }}%</td>

                    <td>
                      <div v-for="risk in row.risk_indicators" :key="risk">
                        • {{ risk }}
                      </div>
                    </td>
                  </tr>

                  <!--<tr v-if="row.expanded">
                    <td colspan="4">
                      <v-card class="pa-4 bg-grey-lighten-4">
                        <div v-if="row.llm_explanation" class="mt-4">
                          <v-divider class="mb-3" />

                          <div class="text-subtitle-1 font-weight-bold mb-2">
                            AI Explanation
                          </div>

                          <v-alert type="info" variant="tonal">
                            {{ row.llm_explanation }}
                          </v-alert>
                        </div>
                        <div v-else class="text-caption text-medium-emphasis">
                          No AI explanation generated (low risk or not
                          prioritised).
                        </div>
                      </v-card>
                    </td>
                  </tr>-->
                </template>
              </tbody>
            </v-table>
            <div class="d-flex justify-center mt-4">
              <v-pagination
                v-model="page"
                :length="totalPages"
                total-visible="7"
              />
            </div>
          </v-card>
          <v-card class="mb-6" elevation="2" border>
            <v-card-title class="bg-grey-lighten-4">
              Model Evaluation
            </v-card-title>

            <v-card-text v-if="evaluation">
              <v-row>
                <v-col cols="6" md="3">
                  <v-card class="pa-3 text-center">
                    <div class="text-overline">True Positives</div>
                    <div class="text-h5 font-weight-bold text-success">
                      {{ evaluation.true_positives }}
                    </div>
                  </v-card>
                </v-col>

                <v-col cols="6" md="3">
                  <v-card class="pa-3 text-center">
                    <div class="text-overline">False Positives</div>
                    <div class="text-h5 font-weight-bold text-warning">
                      {{ evaluation.false_positives }}
                    </div>
                  </v-card>
                </v-col>

                <v-col cols="6" md="3">
                  <v-card class="pa-3 text-center">
                    <div class="text-overline">False Negatives</div>
                    <div class="text-h5 font-weight-bold text-error">
                      {{ evaluation.false_negatives }}
                    </div>
                  </v-card>
                </v-col>

                <v-col cols="6" md="3">
                  <v-card class="pa-3 text-center">
                    <div class="text-overline">True Negatives</div>
                    <div class="text-h5 font-weight-bold text-primary">
                      {{ evaluation.true_negatives }}
                    </div>
                  </v-card>
                </v-col>
              </v-row>

              <v-divider class="my-4" />

              <v-row>
                <v-col cols="12" md="6">
                  <v-alert type="info" variant="tonal">
                    <strong>Precision:</strong>
                    {{ (evaluation.precision * 100).toFixed(1) }}%
                    <br />
                    How many flagged threats were actually malicious.
                  </v-alert>
                </v-col>

                <v-col cols="12" md="6">
                  <v-alert type="info" variant="tonal">
                    <strong>Recall:</strong>
                    {{ (evaluation.recall * 100).toFixed(1) }}%
                    <br />
                    How many real threats the system successfully detected.
                  </v-alert>
                </v-col>
              </v-row>
            </v-card-text>
          </v-card>
          <v-alert type="warning" variant="tonal" class="mt-4">
            <strong>Analysis Insight:</strong><br />

            <span
              v-if="evaluation.false_positives > evaluation.false_negatives"
            >
              The system tends to over-flag normal behavior as threats (higher
              false positives). This may lead to unnecessary investigations.
            </span>

            <span
              v-else-if="
                evaluation.false_negatives > evaluation.false_positives
              "
            >
              The system is missing some malicious activities (higher false
              negatives), which poses a potential security risk.
            </span>

            <span v-else>
              The system maintains a balanced detection performance, but further
              tuning may still improve accuracy.
            </span>
          </v-alert>
        </div>

        <div v-else-if="analysisType === 'single'">
          <v-card class="pt-4 border" elevation="1">
            <v-card-title class="d-flex align-center py-3">
              <v-avatar color="primary" size="48" class="mr-4">
                <v-icon icon="mdi-account-tie" color="white" />
              </v-avatar>
              <div>
                <div class="text-h6 font-weight-bold">
                  {{ sampleProfiles[sampleId].display_info.title }}
                </div>
                <div class="text-subtitle-2 text-medium-emphasis">
                  {{ sampleProfiles[sampleId].display_info.department }}
                </div>
              </div>
            </v-card-title>

            <v-card-text class="pt-4">
              <v-row>
                <v-col cols="12" md="6">
                  <div class="text-overline mb-2 text-primary">
                    Identity & Background
                  </div>
                  <v-list density="compact" class="pa-0">
                    <v-list-item class="px-0">
                      <template v-slot:prepend
                        ><v-icon icon="mdi-clock-outline" size="small"
                      /></template>
                      <v-list-item-title class="text-body-2">
                        <strong>Seniority:</strong>
                        {{
                          sampleProfiles[sampleId].payload
                            .employee_seniority_years
                        }}
                        Years
                      </v-list-item-title>
                    </v-list-item>
                    <v-list-item class="px-0">
                      <template v-slot:prepend
                        ><v-icon icon="mdi-shield-account-outline" size="small"
                      /></template>
                      <v-list-item-title class="text-body-2">
                        <strong>Classification Level:</strong>
                        {{
                          sampleProfiles[sampleId].payload
                            .employee_classification
                        }}
                      </v-list-item-title>
                    </v-list-item>
                  </v-list>
                  <div class="mt-3">
                    <v-chip
                      v-if="
                        sampleProfiles[sampleId].payload.has_criminal_record ==
                        1
                      "
                      size="small"
                      color="error"
                      variant="flat"
                      class="mr-2 mb-2"
                      >Criminal Record</v-chip
                    >
                  </div>
                </v-col>

                <v-col cols="12" md="6">
                  <div class="text-overline mb-2 text-primary">
                    Behavioral Actions (Recorded)
                  </div>
                  <v-row dense>
                    <v-col cols="6">
                      <v-card
                        variant="outlined"
                        class="bg-grey-lighten-5 pa-3 text-center rounded-lg"
                      >
                        <div class="text-h5 font-weight-bold">
                          {{
                            sampleProfiles[sampleId].payload.total_files_burned
                          }}
                        </div>
                        <div class="text-caption text-medium-emphasis">
                          Files Burned (USB)
                        </div>
                      </v-card>
                    </v-col>
                    <v-col cols="6">
                      <v-card
                        variant="outlined"
                        class="bg-grey-lighten-5 pa-3 text-center rounded-lg"
                      >
                        <div class="text-h5 font-weight-bold">
                          {{
                            sampleProfiles[sampleId].payload
                              .num_printed_pages_off_hours
                          }}
                        </div>
                        <div class="text-caption text-medium-emphasis">
                          Off-Hours Prints
                        </div>
                      </v-card>
                    </v-col>
                    <v-col cols="6">
                      <v-card
                        variant="outlined"
                        class="bg-grey-lighten-5 pa-3 text-center rounded-lg"
                      >
                        <div
                          class="text-h5 font-weight-bold"
                          :class="{
                            'text-error':
                              sampleProfiles[sampleId].payload
                                .entry_during_weekend == 1,
                          }"
                        >
                          {{
                            sampleProfiles[sampleId].payload
                              .entry_during_weekend == 1
                              ? "Yes"
                              : "No"
                          }}
                        </div>
                        <div class="text-caption text-medium-emphasis">
                          Weekend Entry
                        </div>
                      </v-card>
                    </v-col>
                    <v-col cols="6">
                      <v-card
                        variant="outlined"
                        class="bg-grey-lighten-5 pa-3 text-center rounded-lg"
                      >
                        <div
                          class="text-h5 font-weight-bold"
                          :class="{
                            'text-error':
                              sampleProfiles[sampleId].payload.late_exit_flag ==
                              1,
                          }"
                        >
                          {{
                            sampleProfiles[sampleId].payload.late_exit_flag == 1
                              ? "Yes"
                              : "No"
                          }}
                        </div>
                        <div class="text-caption text-medium-emphasis">
                          Late Exit
                        </div>
                      </v-card>
                    </v-col>
                  </v-row>
                </v-col>
              </v-row>
            </v-card-text>
          </v-card>

          <v-card
            :color="results.prediction === 'Malicious' ? 'error' : 'success'"
            class="mt-4"
            elevation="1"
            variant="tonal"
            border
          >
            <v-card-title
              class="d-flex align-center justify-space-between pb-0"
            >
              <div>
                <div class="text-overline mb-1">Model Classification</div>
                <div class="text-h4 font-weight-bold">
                  {{ results.prediction }}
                </div>
              </div>
              <div class="text-right">
                <div class="text-overline mb-1">Confidence Score</div>
                <div class="text-h4 font-weight-bold text-high-emphasis">
                  {{ (results.confidence * 100).toFixed(1) }}%
                </div>
              </div>
            </v-card-title>
            <v-card-text class="pt-4">
              <div
                class="text-subtitle-1 font-weight-bold mb-2 text-high-emphasis"
              >
                Key Risk Indicators:
              </div>
              <v-chip
                v-for="(indicator, index) in results.risk_indicators"
                :key="index"
                class="mr-2 mb-2"
                :color="
                  results.prediction === 'Malicious' ? 'error' : 'success'
                "
                variant="flat"
              >
                {{ indicator }}
              </v-chip>
            </v-card-text>
            <v-divider class="my-4" />

            <v-card class="mt-4" elevation="1" border>
              <v-card-title class="text-subtitle-1 font-weight-bold">
                AI Explanation
              </v-card-title>

              <v-card-text class="text-body-2">
                {{ results.llm_explanation }}
              </v-card-text>
            </v-card>
          </v-card>
        </div>
      </div>
    </v-expand-transition>
  </v-container>
</template>

<style scoped>
.overflow-x-auto {
  overflow-x: auto;
}
</style>
