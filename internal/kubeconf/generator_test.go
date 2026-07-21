package kubeconf

import (
	"strings"
	"testing"
)

func TestBuildRBACYamlRole(t *testing.T) {
	yaml, err := BuildRBACYaml("demo-sa", "sa-ns", "role-ns", "Role", []PermissionRule{
		{APIGroup: "", Resource: "pods", Verbs: []string{"get", "list"}},
		{APIGroup: "apps", Resource: "deployments", Verbs: []string{"get"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(yaml, "kind: Role\n") {
		t.Fatalf("expected Role, got:\n%s", yaml)
	}
	if !strings.Contains(yaml, "kind: RoleBinding\n") {
		t.Fatalf("expected RoleBinding, got:\n%s", yaml)
	}
	if !strings.Contains(yaml, "namespace: sa-ns\n") {
		t.Fatalf("expected SA namespace, got:\n%s", yaml)
	}
	if !strings.Contains(yaml, "kind: Role\nmetadata:\n  name: demo-sa-role\n  namespace: role-ns\n") {
		t.Fatalf("expected Role namespace role-ns, got:\n%s", yaml)
	}
	if !strings.Contains(yaml, `resources: ["pods"]`) || !strings.Contains(yaml, `verbs: ["get", "list"]`) {
		t.Fatalf("unexpected rules:\n%s", yaml)
	}
}

func TestBuildRBACYamlClusterRole(t *testing.T) {
	yaml, err := BuildRBACYaml("demo-sa", "kube-system", "", "ClusterRole", []PermissionRule{
		{APIGroup: "", Resource: "nodes", Verbs: []string{"get", "list"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(yaml, "kind: ClusterRole\n") {
		t.Fatalf("expected ClusterRole, got:\n%s", yaml)
	}
	if !strings.Contains(yaml, "kind: ClusterRoleBinding\n") {
		t.Fatalf("expected ClusterRoleBinding, got:\n%s", yaml)
	}
	if strings.Contains(yaml, "kind: ClusterRole\nmetadata:\n  name: demo-sa-role\n  namespace:") {
		t.Fatalf("ClusterRole should not have namespace:\n%s", yaml)
	}
	if !strings.Contains(yaml, "namespace: kube-system\n") {
		t.Fatalf("expected SA namespace kube-system, got:\n%s", yaml)
	}
}

func TestBuildKubeconfigUsesClusterID(t *testing.T) {
	content, err := BuildKubeconfig("cls-64b499e14ad86128", "https://127.0.0.1:6443", "Y2EtZGF0YQ==", "real-token", "default")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(content, "新开发集群") {
		t.Fatalf("should not contain Chinese cluster name:\n%s", content)
	}
	if !strings.Contains(content, "name: cls-64b499e14ad86128\n") {
		t.Fatalf("expected cluster id name:\n%s", content)
	}
	if !strings.Contains(content, "name: cls-64b499e14ad86128-context\n") {
		t.Fatalf("expected cluster-id context:\n%s", content)
	}
	if !strings.Contains(content, "name: cls-64b499e14ad86128-user\n") {
		t.Fatalf("expected cluster-id user:\n%s", content)
	}
	if !strings.Contains(content, "token: real-token\n") {
		t.Fatalf("expected real token:\n%s", content)
	}
}

func TestBuildKubeconfigRejectsEmptyToken(t *testing.T) {
	if _, err := BuildKubeconfig("cls-1", "https://127.0.0.1:6443", "Y2E=", "", "default"); err == nil {
		t.Fatal("expected error for empty token")
	}
}

func TestIsValidK8sResourceName(t *testing.T) {
	cases := map[string]bool{
		"pods":         true,
		"pods/log":     true,
		"my-resources": true,
		"Pods":         false,
		"-bad":         false,
		"bad-":         false,
		"a/b/c":        false,
		"*":            true,
	}
	for name, want := range cases {
		if got := IsValidK8sResourceName(name); got != want {
			t.Fatalf("%q => %v, want %v", name, got, want)
		}
	}
}
