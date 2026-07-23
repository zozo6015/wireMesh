{{- define "wiremesh-operator.name" -}}
wiremesh-operator
{{- end -}}

{{- define "wiremesh-operator.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default "wiremesh-operator" .Values.serviceAccount.name -}}
{{- else -}}
{{- required "serviceAccount.name is required when serviceAccount.create=false" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{- define "wiremesh-operator.image" -}}
{{- printf "%s/%s/wiremesh-operator:%s" .Values.image.registry .Values.image.owner .Values.image.tag -}}
{{- end -}}

{{- define "wiremesh-operator.labels" -}}
app.kubernetes.io/name: wiremesh
app.kubernetes.io/component: operator
app.kubernetes.io/part-of: wiremesh
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ .Chart.Name }}-{{ .Chart.Version }}
{{- end -}}

{{- define "wiremesh-operator.selectorLabels" -}}
app.kubernetes.io/name: wiremesh
app.kubernetes.io/component: operator
{{- end -}}

{{- define "wiremesh-operator.controllerRouteLabels" -}}
app.kubernetes.io/name: wiremesh
app.kubernetes.io/component: controller
app.kubernetes.io/part-of: wiremesh
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ .Chart.Name }}-{{ .Chart.Version }}
{{- end -}}
