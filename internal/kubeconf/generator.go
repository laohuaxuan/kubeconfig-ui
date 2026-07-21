package kubeconf

import (
	"fmt"
	"strings"
)

type PermissionRule struct {
	APIGroup string   `json:"api_group"`
	Resource string   `json:"resource"`
	Verbs    []string `json:"verbs"`
}

// BuildKubeconfig builds a usable kubeconfig.
// clusterRef should be the cluster ID (e.g. cls-xxx), not a display name that may contain non-ASCII characters.
func BuildKubeconfig(clusterRef, apiServer, caCert, token, namespace string) (string, error) {
	ref := strings.TrimSpace(clusterRef)
	if ref == "" {
		return "", fmt.Errorf("cluster id is required for kubeconfig names")
	}
	tok := strings.TrimSpace(token)
	if tok == "" {
		return "", fmt.Errorf("service account token is required")
	}
	ns := strings.TrimSpace(namespace)
	if ns == "" {
		ns = "default"
	}
	userName := ref + "-user"
	contextName := ref + "-context"
	return fmt.Sprintf(`apiVersion: v1
kind: Config
clusters:
- cluster:
    certificate-authority-data: %s
    server: %s
  name: %s
contexts:
- context:
    cluster: %s
    namespace: %s
    user: %s
  name: %s
current-context: %s
users:
- name: %s
  user:
    token: %s
`, strings.TrimSpace(caCert), strings.TrimSpace(apiServer), ref, ref, ns, userName, contextName, contextName, userName, tok), nil
}

// BuildRBACYaml generates SA + Role/ClusterRole + Binding YAML.
// saNamespace: ServiceAccount namespace
// roleNamespace: Role/RoleBinding namespace (required when roleKind=Role; ignored for ClusterRole)
func BuildRBACYaml(serviceAccountName, saNamespace, roleNamespace, roleKind string, rules []PermissionRule) (string, error) {
	sa := strings.TrimSpace(serviceAccountName)
	saNS := strings.TrimSpace(saNamespace)
	roleNS := strings.TrimSpace(roleNamespace)
	kind := strings.TrimSpace(roleKind)
	if sa == "" || saNS == "" {
		return "", fmt.Errorf("service_account_name and sa_namespace are required")
	}
	if kind != "Role" && kind != "ClusterRole" {
		return "", fmt.Errorf("role_kind must be Role or ClusterRole")
	}
	if kind == "Role" && roleNS == "" {
		return "", fmt.Errorf("role_namespace is required when role_kind is Role")
	}
	normalized, err := NormalizeRules(rules)
	if err != nil {
		return "", err
	}
	if kind == "Role" {
		for _, rule := range normalized {
			base := strings.Split(rule.Resource, "/")[0]
			if IsClusterScopedResource(base) {
				return "", fmt.Errorf("Role cannot grant cluster-scoped resource %q, use ClusterRole", base)
			}
		}
	}

	var b strings.Builder
	b.WriteString(fmt.Sprintf(`apiVersion: v1
kind: ServiceAccount
metadata:
  name: %s
  namespace: %s
---
`, sa, saNS))

	roleName := sa + "-role"
	bindingName := sa + "-rolebinding"
	b.WriteString("apiVersion: rbac.authorization.k8s.io/v1\n")
	b.WriteString("kind: " + kind + "\n")
	b.WriteString("metadata:\n")
	b.WriteString("  name: " + roleName + "\n")
	if kind == "Role" {
		b.WriteString("  namespace: " + roleNS + "\n")
	}
	b.WriteString("rules:\n")
	for _, rule := range normalized {
		apiGroup := rule.APIGroup
		b.WriteString(fmt.Sprintf("- apiGroups: [%s]\n", quoteJoin([]string{apiGroup})))
		b.WriteString(fmt.Sprintf("  resources: [%s]\n", quoteJoin([]string{rule.Resource})))
		b.WriteString(fmt.Sprintf("  verbs: [%s]\n", quoteJoin(rule.Verbs)))
	}

	bindingKind := "RoleBinding"
	if kind == "ClusterRole" {
		bindingKind = "ClusterRoleBinding"
	}
	b.WriteString("---\n")
	b.WriteString("apiVersion: rbac.authorization.k8s.io/v1\n")
	b.WriteString("kind: " + bindingKind + "\n")
	b.WriteString("metadata:\n")
	b.WriteString("  name: " + bindingName + "\n")
	if kind == "Role" {
		b.WriteString("  namespace: " + roleNS + "\n")
	}
	b.WriteString(fmt.Sprintf(`subjects:
- kind: ServiceAccount
  name: %s
  namespace: %s
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: %s
  name: %s
`, sa, saNS, kind, roleName))

	return b.String(), nil
}

func NormalizeRules(rules []PermissionRule) ([]PermissionRule, error) {
	if len(rules) == 0 {
		return nil, fmt.Errorf("at least one permission rule is required")
	}
	out := make([]PermissionRule, 0, len(rules))
	for _, rule := range rules {
		resource := strings.TrimSpace(rule.Resource)
		if resource == "" {
			return nil, fmt.Errorf("resource cannot be empty")
		}
		if !IsValidK8sResourceName(resource) {
			return nil, fmt.Errorf("invalid resource name: %s", resource)
		}
		verbs := uniqueNonEmpty(rule.Verbs)
		if len(verbs) == 0 {
			return nil, fmt.Errorf("resource %s requires at least one verb", resource)
		}
		for _, verb := range verbs {
			if !IsValidVerb(verb) {
				return nil, fmt.Errorf("invalid verb %q for resource %s", verb, resource)
			}
		}
		out = append(out, PermissionRule{
			APIGroup: strings.TrimSpace(rule.APIGroup),
			Resource: resource,
			Verbs:    verbs,
		})
	}
	return out, nil
}

func IsValidK8sResourceName(name string) bool {
	name = strings.TrimSpace(name)
	if name == "" || name == "*" {
		return name == "*"
	}
	parts := strings.Split(name, "/")
	if len(parts) > 2 {
		return false
	}
	for _, part := range parts {
		if !isDNS1123Label(part) {
			return false
		}
	}
	return true
}

func IsValidVerb(verb string) bool {
	switch strings.TrimSpace(verb) {
	case "get", "list", "watch", "create", "update", "patch", "delete", "deletecollection", "*":
		return true
	default:
		return false
	}
}

func IsClusterScopedResource(resource string) bool {
	switch strings.TrimSpace(resource) {
	case "nodes", "namespaces", "persistentvolumes", "componentstatuses",
		"storageclasses", "csidrivers", "csinodes", "priorityclasses", "runtimeclasses",
		"clusterroles", "clusterrolebindings", "customresourcedefinitions", "apiservices",
		"mutatingwebhookconfigurations", "validatingwebhookconfigurations":
		return true
	default:
		return false
	}
}

func isDNS1123Label(value string) bool {
	if value == "" || len(value) > 63 {
		return false
	}
	for i := 0; i < len(value); i++ {
		c := value[i]
		isAlphaNum := (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
		if i == 0 || i == len(value)-1 {
			if !isAlphaNum {
				return false
			}
			continue
		}
		if !isAlphaNum && c != '-' {
			return false
		}
	}
	return true
}

func quoteJoin(items []string) string {
	quoted := make([]string, 0, len(items))
	for _, item := range items {
		v := strings.TrimSpace(item)
		quoted = append(quoted, fmt.Sprintf(`"%s"`, v))
	}
	return strings.Join(quoted, ", ")
}

func uniqueNonEmpty(items []string) []string {
	seen := make(map[string]struct{}, len(items))
	out := make([]string, 0, len(items))
	for _, item := range items {
		v := strings.TrimSpace(item)
		if v == "" {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}
