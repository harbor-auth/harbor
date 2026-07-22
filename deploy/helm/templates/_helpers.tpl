{{/*
Harbor chart template helpers.
*/}}

{{/* Chart name (overridable via nameOverride is intentionally omitted for simplicity). */}}
{{- define "harbor.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Fully-qualified app name: <release>-<chart>, trimmed to 63 chars. If the release
name already contains the chart name, we don't double it up.
*/}}
{{- define "harbor.fullname" -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{/* Chart name + version, sanitized for use as a label value. */}}
{{- define "harbor.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Common labels shared by every resource. Includes chart provenance and any
user-supplied extraLabels.
*/}}
{{- define "harbor.labels" -}}
helm.sh/chart: {{ include "harbor.chart" . }}
app.kubernetes.io/part-of: harbor
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
{{- with .Values.extraLabels }}
{{ toYaml . }}
{{- end }}
{{- end -}}

{{/* ---- harbor-hot labels / selectors ---- */}}

{{/* Immutable selector subset for harbor-hot (safe for .spec.selector). */}}
{{- define "harbor.hot.selectorLabels" -}}
app.kubernetes.io/name: harbor-hot
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{/* Full label set for harbor-hot resources. */}}
{{- define "harbor.hot.labels" -}}
{{ include "harbor.labels" . }}
{{ include "harbor.hot.selectorLabels" . }}
app.kubernetes.io/component: hot-path
{{- end -}}

{{/* ---- harbor-mgmt labels / selectors ---- */}}

{{/* Immutable selector subset for harbor-mgmt (safe for .spec.selector). */}}
{{- define "harbor.mgmt.selectorLabels" -}}
app.kubernetes.io/name: harbor-mgmt
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{/* Full label set for harbor-mgmt resources. */}}
{{- define "harbor.mgmt.labels" -}}
{{ include "harbor.labels" . }}
{{ include "harbor.mgmt.selectorLabels" . }}
app.kubernetes.io/component: cold-path
{{- end -}}

{{/* ---- ServiceAccount names ---- */}}

{{- define "harbor.hot.serviceAccountName" -}}
{{- printf "%s-hot-sa" (include "harbor.fullname" .) -}}
{{- end -}}

{{- define "harbor.mgmt.serviceAccountName" -}}
{{- printf "%s-mgmt-sa" (include "harbor.fullname" .) -}}
{{- end -}}

{{/* ---- Secret names (honor existingSecret) ---- */}}

{{- define "harbor.hot.secretName" -}}
{{- if .Values.hot.secrets.existingSecret -}}
{{- .Values.hot.secrets.existingSecret -}}
{{- else -}}
{{- printf "%s-hot-secrets" (include "harbor.fullname" .) -}}
{{- end -}}
{{- end -}}

{{- define "harbor.mgmt.secretName" -}}
{{- if .Values.mgmt.secrets.existingSecret -}}
{{- .Values.mgmt.secrets.existingSecret -}}
{{- else -}}
{{- printf "%s-mgmt-secrets" (include "harbor.fullname" .) -}}
{{- end -}}
{{- end -}}

{{/* ---- Image references ---- */}}

{{/*
Build the harbor-hot image reference. Prefers a per-component digest (immutable)
over the shared tag.
*/}}
{{- define "harbor.hot.image" -}}
{{- $registry := .Values.global.image.registry -}}
{{- $repo := .Values.hot.image.repository -}}
{{- if .Values.hot.image.digest -}}
{{- printf "%s/%s@%s" $registry $repo (trimPrefix "@" .Values.hot.image.digest) -}}
{{- else -}}
{{- printf "%s/%s:%s" $registry $repo .Values.global.image.tag -}}
{{- end -}}
{{- end -}}

{{- define "harbor.mgmt.image" -}}
{{- $registry := .Values.global.image.registry -}}
{{- $repo := .Values.mgmt.image.repository -}}
{{- if .Values.mgmt.image.digest -}}
{{- printf "%s/%s@%s" $registry $repo (trimPrefix "@" .Values.mgmt.image.digest) -}}
{{- else -}}
{{- printf "%s/%s:%s" $registry $repo .Values.global.image.tag -}}
{{- end -}}
{{- end -}}

{{- define "harbor.migrate.image" -}}
{{- $registry := .Values.global.image.registry -}}
{{- $repo := .Values.migrate.image.repository -}}
{{- if .Values.migrate.image.digest -}}
{{- printf "%s/%s@%s" $registry $repo (trimPrefix "@" .Values.migrate.image.digest) -}}
{{- else -}}
{{- printf "%s/%s:%s" $registry $repo .Values.global.image.tag -}}
{{- end -}}
{{- end -}}

{{/*
Secret the migrate Job reads DATABASE_URL from. Defaults to harbor-hot's Secret
(both binaries share one database); override via migrate.secrets.existingSecret.
*/}}
{{- define "harbor.migrate.secretName" -}}
{{- if .Values.migrate.secrets.existingSecret -}}
{{- .Values.migrate.secrets.existingSecret -}}
{{- else -}}
{{- include "harbor.hot.secretName" . -}}
{{- end -}}
{{- end -}}

{{/* Full label set for the migrate Job. */}}
{{- define "harbor.migrate.labels" -}}
{{ include "harbor.labels" . }}
app.kubernetes.io/name: harbor-migrate
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: migrate
{{- end -}}
