package kubeconf

import "testing"

func TestExtractClusterEndpoint(t *testing.T) {
	raw := `apiVersion: v1
kind: Config
clusters:
- cluster:
    certificate-authority-data: Y2EtZGF0YQ==
    server: https://example.com:6443
  name: demo
contexts:
- context:
    cluster: demo
    user: demo-user
  name: demo-context
current-context: demo-context
users:
- name: demo-user
  user:
    token: abc
`
	apiServer, caCert, err := ExtractClusterEndpoint(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if apiServer != "https://example.com:6443" {
		t.Fatalf("apiServer = %q", apiServer)
	}
	if caCert != "Y2EtZGF0YQ==" {
		t.Fatalf("caCert = %q", caCert)
	}
}
