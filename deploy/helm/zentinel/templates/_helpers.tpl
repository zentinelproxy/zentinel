{{/*
Expand the name of the chart.
*/}}
{{- define "zentinel.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "zentinel.fullname" -}}
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

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "zentinel.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "zentinel.labels" -}}
helm.sh/chart: {{ include "zentinel.chart" . }}
{{ include "zentinel.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "zentinel.selectorLabels" -}}
app.kubernetes.io/name: {{ include "zentinel.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "zentinel.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "zentinel.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Return the proper image name for the proxy
*/}}
{{- define "zentinel.proxyImage" -}}
{{- $registryName := .Values.proxy.image.registry | default .Values.global.imageRegistry -}}
{{- $repositoryName := .Values.proxy.image.repository -}}
{{- $tag := .Values.proxy.image.tag | default .Chart.AppVersion -}}
{{- if $registryName }}
{{- printf "%s/%s:%s" $registryName $repositoryName $tag -}}
{{- else }}
{{- printf "%s:%s" $repositoryName $tag -}}
{{- end }}
{{- end }}

{{/*
Return the proper image name for the ratelimit agent
*/}}
{{- define "zentinel.ratelimitImage" -}}
{{- $registryName := .Values.ratelimit.image.registry | default .Values.global.imageRegistry -}}
{{- $repositoryName := .Values.ratelimit.image.repository -}}
{{- $tag := .Values.ratelimit.image.tag | default .Chart.AppVersion -}}
{{- if $registryName }}
{{- printf "%s/%s:%s" $registryName $repositoryName $tag -}}
{{- else }}
{{- printf "%s:%s" $repositoryName $tag -}}
{{- end }}
{{- end }}

{{/*
Return the proper image name for the WAF agent
*/}}
{{- define "zentinel.wafImage" -}}
{{- $registryName := .Values.waf.image.registry | default .Values.global.imageRegistry -}}
{{- $repositoryName := .Values.waf.image.repository -}}
{{- $tag := .Values.waf.image.tag | default .Chart.AppVersion -}}
{{- if $registryName }}
{{- printf "%s/%s:%s" $registryName $repositoryName $tag -}}
{{- else }}
{{- printf "%s:%s" $repositoryName $tag -}}
{{- end }}
{{- end }}

{{/*
Return the proper image name for the denylist agent
*/}}
{{- define "zentinel.denylistImage" -}}
{{- $registryName := .Values.denylist.image.registry | default .Values.global.imageRegistry -}}
{{- $repositoryName := .Values.denylist.image.repository -}}
{{- $tag := .Values.denylist.image.tag | default .Chart.AppVersion -}}
{{- if $registryName }}
{{- printf "%s/%s:%s" $registryName $repositoryName $tag -}}
{{- else }}
{{- printf "%s:%s" $repositoryName $tag -}}
{{- end }}
{{- end }}

{{/*
Return the proper image name for the echo agent
*/}}
{{- define "zentinel.echoImage" -}}
{{- $registryName := .Values.echo.image.registry | default .Values.global.imageRegistry -}}
{{- $repositoryName := .Values.echo.image.repository -}}
{{- $tag := .Values.echo.image.tag | default .Chart.AppVersion -}}
{{- if $registryName }}
{{- printf "%s/%s:%s" $registryName $repositoryName $tag -}}
{{- else }}
{{- printf "%s:%s" $repositoryName $tag -}}
{{- end }}
{{- end }}

{{/*
Return the proper storage class
*/}}
{{- define "zentinel.storageClass" -}}
{{- $storageClass := .Values.global.storageClass | default .Values.storageClass -}}
{{- if $storageClass -}}
{{- if (eq "-" $storageClass) -}}
{{- printf "storageClassName: \"\"" -}}
{{- else }}
{{- printf "storageClassName: %s" $storageClass -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/*
Return the appropriate apiVersion for HorizontalPodAutoscaler
*/}}
{{- define "zentinel.hpa.apiVersion" -}}
{{- if .Capabilities.APIVersions.Has "autoscaling/v2" -}}
autoscaling/v2
{{- else if .Capabilities.APIVersions.Has "autoscaling/v2beta2" -}}
autoscaling/v2beta2
{{- else -}}
autoscaling/v2beta1
{{- end -}}
{{- end -}}

{{/*
Return the appropriate apiVersion for PodDisruptionBudget
*/}}
{{- define "zentinel.pdb.apiVersion" -}}
{{- if .Capabilities.APIVersions.Has "policy/v1" -}}
policy/v1
{{- else -}}
policy/v1beta1
{{- end -}}
{{- end -}}

{{/*
Return the appropriate apiVersion for NetworkPolicy
*/}}
{{- define "zentinel.networkPolicy.apiVersion" -}}
{{- if .Capabilities.APIVersions.Has "networking.k8s.io/v1" -}}
networking.k8s.io/v1
{{- else -}}
extensions/v1beta1
{{- end -}}
{{- end -}}

{{/*
Return the appropriate apiVersion for Ingress
*/}}
{{- define "zentinel.ingress.apiVersion" -}}
{{- if .Capabilities.APIVersions.Has "networking.k8s.io/v1" -}}
networking.k8s.io/v1
{{- else if .Capabilities.APIVersions.Has "networking.k8s.io/v1beta1" -}}
networking.k8s.io/v1beta1
{{- else -}}
extensions/v1beta1
{{- end -}}
{{- end -}}

{{/*
Return true if Ingress is stable
*/}}
{{- define "zentinel.ingress.isStable" -}}
{{- eq (include "zentinel.ingress.apiVersion" .) "networking.k8s.io/v1" -}}
{{- end -}}

{{/*
Return true if Ingress supports pathType
*/}}
{{- define "zentinel.ingress.supportsPathType" -}}
{{- or (eq (include "zentinel.ingress.isStable" .) "true") (eq (include "zentinel.ingress.apiVersion" .) "networking.k8s.io/v1beta1") -}}
{{- end -}}

{{/*
Create a default TLS certificate secret name
*/}}
{{- define "zentinel.tlsSecretName" -}}
{{- if .Values.security.tls.existingSecret -}}
{{- .Values.security.tls.existingSecret -}}
{{- else -}}
{{- printf "%s-tls" (include "zentinel.fullname" .) -}}
{{- end -}}
{{- end -}}

{{/*
Generate backends string for proxy config
*/}}
{{- define "zentinel.proxy.backends" -}}
{{- range $upstream := .Values.proxy.upstreams }}
upstream {{ $upstream.name | quote }} {
    {{- range $endpoint := $upstream.endpoints }}
    endpoint {{ $endpoint | quote }}
    {{- end }}
    {{- if $upstream.healthCheck }}
    health-check {
        path {{ $upstream.healthCheck.path | quote }}
        interval {{ $upstream.healthCheck.interval | default 10 }}
        timeout {{ $upstream.healthCheck.timeout | default 3 }}
    }
    {{- end }}
}
{{- end }}
{{- end }}

{{/*
Generate agent configuration for proxy
*/}}
{{- define "zentinel.proxy.agents" -}}
{{- if .Values.ratelimit.enabled }}
agent "ratelimit-agent" {
    type "rate_limit"
    {{- if .Values.agents.unixSocket.enabled }}
    transport "unix_socket" {
        path "{{ .Values.agents.unixSocket.directory }}/ratelimit.sock"
    }
    {{- else }}
    transport "grpc" {
        endpoint "{{ include "zentinel.fullname" . }}-ratelimit:{{ .Values.ratelimit.service.port }}"
        {{- if .Values.agents.network.tls.enabled }}
        tls {
            enabled true
            {{- if .Values.agents.network.tls.certSecret }}
            cert "/etc/zentinel/agent-tls/tls.crt"
            key "/etc/zentinel/agent-tls/tls.key"
            ca "/etc/zentinel/agent-tls/ca.crt"
            {{- end }}
        }
        {{- end }}
    }
    {{- end }}
    events ["request_headers"]
    timeout-ms 100
    failure-mode "open"
}
{{- end }}

{{- if .Values.waf.enabled }}
agent "waf-agent" {
    type "waf"
    {{- if .Values.agents.unixSocket.enabled }}
    transport "unix_socket" {
        path "{{ .Values.agents.unixSocket.directory }}/waf.sock"
    }
    {{- else }}
    transport "grpc" {
        endpoint "{{ include "zentinel.fullname" . }}-waf:{{ .Values.waf.service.port }}"
        {{- if .Values.agents.network.tls.enabled }}
        tls {
            enabled true
            {{- if .Values.agents.network.tls.certSecret }}
            cert "/etc/zentinel/agent-tls/tls.crt"
            key "/etc/zentinel/agent-tls/tls.key"
            ca "/etc/zentinel/agent-tls/ca.crt"
            {{- end }}
        }
        {{- end }}
    }
    {{- end }}
    events ["request_headers" "request_body"]
    timeout-ms 100
    failure-mode {{ .Values.waf.failureMode | default "open" | quote }}
}
{{- end }}

{{- if .Values.denylist.enabled }}
agent "denylist-agent" {
    type "denylist"
    {{- if .Values.agents.unixSocket.enabled }}
    transport "unix_socket" {
        path "{{ .Values.agents.unixSocket.directory }}/denylist.sock"
    }
    {{- else }}
    transport "grpc" {
        endpoint "{{ include "zentinel.fullname" . }}-denylist:{{ .Values.denylist.service.port }}"
        {{- if .Values.agents.network.tls.enabled }}
        tls {
            enabled true
            {{- if .Values.agents.network.tls.certSecret }}
            cert "/etc/zentinel/agent-tls/tls.crt"
            key "/etc/zentinel/agent-tls/tls.key"
            ca "/etc/zentinel/agent-tls/ca.crt"
            {{- end }}
        }
        {{- end }}
    }
    {{- end }}
    events ["request_headers"]
    timeout-ms 50
    failure-mode "closed"
}
{{- end }}

{{- if .Values.echo.enabled }}
agent "echo-agent" {
    type "echo"
    {{- if .Values.agents.unixSocket.enabled }}
    transport "unix_socket" {
        path "{{ .Values.agents.unixSocket.directory }}/echo.sock"
    }
    {{- else }}
    transport "grpc" {
        endpoint "{{ include "zentinel.fullname" . }}-echo:{{ .Values.echo.service.port }}"
    }
    {{- end }}
    events ["request_headers"]
    timeout-ms 50
    failure-mode "open"
}
{{- end }}
{{- end }}

{{/*
Validate values and fail with useful error messages
*/}}
{{- define "zentinel.validateValues" -}}
{{- if and .Values.proxy.enabled (not .Values.proxy.config.kdl) (not .Values.proxy.config.externalConfig.enabled) -}}
  {{- fail "Proxy is enabled but no configuration provided. Set proxy.config.kdl or proxy.config.externalConfig" -}}
{{- end -}}
{{- if and .Values.security.tls.enabled (not .Values.security.tls.existingSecret) (not .Values.security.tls.certManager.enabled) (not .Values.security.tls.cert) -}}
  {{- fail "TLS is enabled but no certificate provided. Set security.tls.existingSecret, security.tls.certManager, or provide security.tls.cert and security.tls.key" -}}
{{- end -}}
{{- end -}}
