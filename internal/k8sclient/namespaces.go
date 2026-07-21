package k8sclient

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

func ListNamespaces(kubeconfigContent string) ([]string, error) {
	raw := strings.TrimSpace(kubeconfigContent)
	if raw == "" {
		return nil, fmt.Errorf("cluster kubeconfig is empty, please re-add cluster with kubeconfig")
	}
	cfg, err := clientcmd.RESTConfigFromKubeConfig([]byte(raw))
	if err != nil {
		return nil, fmt.Errorf("parse kubeconfig failed: %w", err)
	}
	cfg.Timeout = 15 * time.Second

	clientset, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("create kubernetes client failed: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	list, err := clientset.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list namespaces failed: %w", err)
	}

	names := make([]string, 0, len(list.Items))
	for _, item := range list.Items {
		name := strings.TrimSpace(item.Name)
		if name == "" {
			continue
		}
		names = append(names, name)
	}
	sort.Strings(names)
	return names, nil
}
