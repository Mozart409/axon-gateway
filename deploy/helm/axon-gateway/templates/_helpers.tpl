{{- define "axon-gateway.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "axon-gateway.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{- define "axon-gateway.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "axon-gateway.labels" -}}
helm.sh/chart: {{ include "axon-gateway.chart" . }}
{{ include "axon-gateway.selectorLabels" . }}
app.kubernetes.io/version: {{ .Values.image.tag | default .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{- define "axon-gateway.selectorLabels" -}}
app.kubernetes.io/name: {{ include "axon-gateway.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{- define "axon-gateway.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "axon-gateway.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Environment of database mode: the database URL from a Secret, the public URL,
the listen address, stdio switch and the optional bootstrap OIDC provider.
Rendered as list items; indent with nindent.
*/}}
{{- define "axon-gateway.databaseModeEnv" -}}
{{ include "axon-gateway.databaseUrlEnv" . }}
- name: AXON_BASE_URL
  value: {{ required "baseUrl is required when database.enabled" .Values.baseUrl | quote }}
- name: AXON_BIND
  value: {{ .Values.bind | quote }}
{{- if .Values.allowStdio }}
- name: AXON_ALLOW_STDIO
  value: "true"
{{- end }}
{{- if .Values.oidc.issuer }}
- name: AXON_OIDC_ISSUER
  value: {{ .Values.oidc.issuer | quote }}
- name: AXON_OIDC_CLIENT_ID
  value: {{ required "oidc.clientId is required with oidc.issuer" .Values.oidc.clientId | quote }}
{{- if .Values.oidc.clientSecret.existingSecret }}
- name: AXON_OIDC_CLIENT_SECRET_FILE
  value: /etc/axon-oidc/{{ .Values.oidc.clientSecret.key }}
{{- end }}
{{- if .Values.oidc.adminGroups }}
- name: AXON_OIDC_ADMIN_GROUPS
  value: {{ join "," .Values.oidc.adminGroups | quote }}
{{- end }}
{{- if .Values.oidc.id }}
- name: AXON_OIDC_ID
  value: {{ .Values.oidc.id | quote }}
{{- end }}
{{- if .Values.oidc.displayName }}
- name: AXON_OIDC_DISPLAY_NAME
  value: {{ .Values.oidc.displayName | quote }}
{{- end }}
{{- end }}
{{- end }}

{{/* AXON_DATABASE_URL from the database Secret, as a list item */}}
{{- define "axon-gateway.databaseUrlEnv" -}}
- name: AXON_DATABASE_URL
  valueFrom:
    secretKeyRef:
      name: {{ required "database.existingSecret is required when database.enabled" .Values.database.existingSecret }}
      key: {{ .Values.database.key }}
{{- end }}
