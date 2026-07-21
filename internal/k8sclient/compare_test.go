package k8sclient

import (
	"testing"

	rbacv1 "k8s.io/api/rbac/v1"
)

func TestPolicyRulesEqualIgnoresOrder(t *testing.T) {
	a := []rbacv1.PolicyRule{
		{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"list", "get"}},
		{APIGroups: []string{"apps"}, Resources: []string{"deployments"}, Verbs: []string{"get"}},
	}
	b := []rbacv1.PolicyRule{
		{APIGroups: []string{"apps"}, Resources: []string{"deployments"}, Verbs: []string{"get"}},
		{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get", "list"}},
	}
	if !policyRulesEqual(a, b) {
		t.Fatal("expected equal after normalize")
	}
}

func TestSubjectsEqual(t *testing.T) {
	a := []rbacv1.Subject{{Kind: "ServiceAccount", Name: "demo", Namespace: "default"}}
	b := []rbacv1.Subject{{Kind: "ServiceAccount", Name: "demo", Namespace: "default", APIGroup: ""}}
	if !subjectsEqual(a, b) {
		t.Fatal("expected subjects equal")
	}
}
