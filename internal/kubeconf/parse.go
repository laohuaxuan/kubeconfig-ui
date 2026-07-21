package kubeconf

import (
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

type parsedKubeconfig struct {
	Clusters []struct {
		Name    string `yaml:"name"`
		Cluster struct {
			Server                   string `yaml:"server"`
			CertificateAuthorityData string `yaml:"certificate-authority-data"`
		} `yaml:"cluster"`
	} `yaml:"clusters"`
	Contexts []struct {
		Name    string `yaml:"name"`
		Context struct {
			Cluster string `yaml:"cluster"`
		} `yaml:"context"`
	} `yaml:"contexts"`
	CurrentContext string `yaml:"current-context"`
}

// ExtractClusterEndpoint 从 kubeconfig 中提取 APIServer 与 CA 证书（base64）。
func ExtractClusterEndpoint(kubeconfig string) (apiServer, caCert string, err error) {
	content := strings.TrimSpace(kubeconfig)
	if content == "" {
		return "", "", fmt.Errorf("kubeconfig is required")
	}

	var cfg parsedKubeconfig
	if err := yaml.Unmarshal([]byte(content), &cfg); err != nil {
		return "", "", fmt.Errorf("invalid kubeconfig yaml: %w", err)
	}
	if len(cfg.Clusters) == 0 {
		return "", "", fmt.Errorf("kubeconfig has no clusters")
	}

	preferred := strings.TrimSpace(cfg.CurrentContext)
	if preferred == "" && len(cfg.Contexts) > 0 {
		preferred = strings.TrimSpace(cfg.Contexts[0].Name)
	}
	clusterName := ""
	for _, ctx := range cfg.Contexts {
		if preferred != "" && strings.TrimSpace(ctx.Name) != preferred {
			continue
		}
		clusterName = strings.TrimSpace(ctx.Context.Cluster)
		if clusterName != "" {
			break
		}
	}

	for _, item := range cfg.Clusters {
		if clusterName != "" && strings.TrimSpace(item.Name) != clusterName {
			continue
		}
		apiServer = strings.TrimSpace(item.Cluster.Server)
		caCert = strings.TrimSpace(item.Cluster.CertificateAuthorityData)
		if apiServer != "" && caCert != "" {
			return apiServer, caCert, nil
		}
	}

	// fallback: first cluster with both fields
	for _, item := range cfg.Clusters {
		apiServer = strings.TrimSpace(item.Cluster.Server)
		caCert = strings.TrimSpace(item.Cluster.CertificateAuthorityData)
		if apiServer != "" && caCert != "" {
			return apiServer, caCert, nil
		}
	}
	if apiServer == "" {
		return "", "", fmt.Errorf("kubeconfig missing cluster.server")
	}
	return "", "", fmt.Errorf("kubeconfig missing cluster.certificate-authority-data")
}
