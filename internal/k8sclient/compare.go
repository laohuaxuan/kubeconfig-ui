package k8sclient

import (
	"fmt"
	"sort"
	"strings"

	rbacv1 "k8s.io/api/rbac/v1"
)

func policyRulesEqual(a, b []rbacv1.PolicyRule) bool {
	na := normalizePolicyRules(a)
	nb := normalizePolicyRules(b)
	if len(na) != len(nb) {
		return false
	}
	for i := range na {
		if !stringSlicesEqual(na[i].APIGroups, nb[i].APIGroups) ||
			!stringSlicesEqual(na[i].Resources, nb[i].Resources) ||
			!stringSlicesEqual(na[i].Verbs, nb[i].Verbs) ||
			!stringSlicesEqual(na[i].ResourceNames, nb[i].ResourceNames) ||
			!stringSlicesEqual(na[i].NonResourceURLs, nb[i].NonResourceURLs) {
			return false
		}
	}
	return true
}

func subjectsEqual(a, b []rbacv1.Subject) bool {
	na := normalizeSubjects(a)
	nb := normalizeSubjects(b)
	if len(na) != len(nb) {
		return false
	}
	for i := range na {
		if na[i].Kind != nb[i].Kind ||
			na[i].Name != nb[i].Name ||
			na[i].Namespace != nb[i].Namespace ||
			normalizeAPIGroup(na[i].Kind, na[i].APIGroup) != normalizeAPIGroup(nb[i].Kind, nb[i].APIGroup) {
			return false
		}
	}
	return true
}

func roleRefsEqual(a, b rbacv1.RoleRef) bool {
	return a.Kind == b.Kind &&
		a.Name == b.Name &&
		strings.TrimSpace(a.APIGroup) == strings.TrimSpace(b.APIGroup)
}

func normalizePolicyRules(rules []rbacv1.PolicyRule) []rbacv1.PolicyRule {
	out := make([]rbacv1.PolicyRule, 0, len(rules))
	for _, rule := range rules {
		out = append(out, rbacv1.PolicyRule{
			APIGroups:       normalizeStringSlice(rule.APIGroups),
			Resources:       normalizeStringSlice(rule.Resources),
			Verbs:           normalizeStringSlice(rule.Verbs),
			ResourceNames:   normalizeStringSlice(rule.ResourceNames),
			NonResourceURLs: normalizeStringSlice(rule.NonResourceURLs),
		})
	}
	sort.Slice(out, func(i, j int) bool {
		return policyRuleKey(out[i]) < policyRuleKey(out[j])
	})
	return out
}

func policyRuleKey(rule rbacv1.PolicyRule) string {
	return fmt.Sprintf("%v|%v|%v|%v|%v",
		rule.APIGroups, rule.Resources, rule.Verbs, rule.ResourceNames, rule.NonResourceURLs)
}

func normalizeSubjects(subjects []rbacv1.Subject) []rbacv1.Subject {
	out := make([]rbacv1.Subject, 0, len(subjects))
	for _, s := range subjects {
		out = append(out, rbacv1.Subject{
			Kind:      strings.TrimSpace(s.Kind),
			APIGroup:  normalizeAPIGroup(s.Kind, s.APIGroup),
			Name:      strings.TrimSpace(s.Name),
			Namespace: strings.TrimSpace(s.Namespace),
		})
	}
	sort.Slice(out, func(i, j int) bool {
		return fmt.Sprintf("%s/%s/%s/%s", out[i].Kind, out[i].Namespace, out[i].Name, out[i].APIGroup) <
			fmt.Sprintf("%s/%s/%s/%s", out[j].Kind, out[j].Namespace, out[j].Name, out[j].APIGroup)
	})
	return out
}

func normalizeAPIGroup(kind, apiGroup string) string {
	apiGroup = strings.TrimSpace(apiGroup)
	if kind == "ServiceAccount" && apiGroup == "" {
		return ""
	}
	return apiGroup
}

func normalizeStringSlice(items []string) []string {
	if len(items) == 0 {
		return []string{}
	}
	out := make([]string, 0, len(items))
	seen := map[string]struct{}{}
	for _, item := range items {
		v := strings.TrimSpace(item)
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

func stringSlicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
