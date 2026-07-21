package k8sclient

import (
	"context"
	"fmt"
	"strings"
	"time"

	"kubeconfig-ui/internal/kubeconf"

	authv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/utils/ptr"
)

type applyTracker struct {
	saCreated      bool
	roleCreated    bool
	bindingCreated bool
	secretCreated  bool
}

// ApplyRBACAndGetToken creates ServiceAccount + Role/ClusterRole + Binding on the target
// cluster, then returns a usable ServiceAccount token. On failure it rolls back resources
// created in this call (best effort) and returns an error.
// expirationSeconds controls TokenRequest TTL; allowSecretFallback enables legacy Secret tokens
// (typically for long-lived issuance when TokenRequest max TTL is insufficient).
func ApplyRBACAndGetToken(
	kubeconfigContent string,
	saName, saNamespace, roleNamespace, roleKind string,
	rules []kubeconf.PermissionRule,
	expirationSeconds int64,
	allowSecretFallback bool,
) (string, error) {
	saName = strings.TrimSpace(saName)
	saNamespace = strings.TrimSpace(saNamespace)
	roleNamespace = strings.TrimSpace(roleNamespace)
	roleKind = strings.TrimSpace(roleKind)
	if saName == "" || saNamespace == "" {
		return "", fmt.Errorf("service_account_name and sa_namespace are required")
	}
	if roleKind != "Role" && roleKind != "ClusterRole" {
		return "", fmt.Errorf("role_kind must be Role or ClusterRole")
	}
	if roleKind == "Role" && roleNamespace == "" {
		return "", fmt.Errorf("role_namespace is required when role_kind is Role")
	}

	normalized, err := kubeconf.NormalizeRules(rules)
	if err != nil {
		return "", err
	}
	if roleKind == "Role" {
		for _, rule := range normalized {
			base := strings.Split(rule.Resource, "/")[0]
			if kubeconf.IsClusterScopedResource(base) {
				return "", fmt.Errorf("Role cannot grant cluster-scoped resource %q, use ClusterRole", base)
			}
		}
	}

	clientset, err := clientsetFromKubeconfig(kubeconfigContent)
	if err != nil {
		return "", err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	roleName := saName + "-role"
	bindingName := saName + "-rolebinding"
	secretName := saName + "-token"
	policyRules := toPolicyRules(normalized)

	tracker := &applyTracker{}
	var applyErr error
	defer func() {
		if applyErr != nil {
			cleanupCreated(context.Background(), clientset, saName, saNamespace, roleNamespace, roleKind, roleName, bindingName, secretName, tracker)
		}
	}()

	if err := ensureServiceAccount(ctx, clientset, saName, saNamespace, tracker); err != nil {
		applyErr = err
		return "", applyErr
	}
	if roleKind == "Role" {
		if err := ensureRole(ctx, clientset, roleName, roleNamespace, policyRules, tracker); err != nil {
			applyErr = err
			return "", applyErr
		}
		if err := ensureRoleBinding(ctx, clientset, bindingName, roleName, roleNamespace, saName, saNamespace, tracker); err != nil {
			applyErr = err
			return "", applyErr
		}
	} else {
		if err := ensureClusterRole(ctx, clientset, roleName, policyRules, tracker); err != nil {
			applyErr = err
			return "", applyErr
		}
		if err := ensureClusterRoleBinding(ctx, clientset, bindingName, roleName, saName, saNamespace, tracker); err != nil {
			applyErr = err
			return "", applyErr
		}
	}

	token, err := createServiceAccountToken(ctx, clientset, saName, saNamespace, secretName, expirationSeconds, allowSecretFallback, tracker)
	if err != nil {
		applyErr = err
		return "", applyErr
	}
	return token, nil
}

func clientsetFromKubeconfig(kubeconfigContent string) (*kubernetes.Clientset, error) {
	raw := strings.TrimSpace(kubeconfigContent)
	if raw == "" {
		return nil, fmt.Errorf("cluster kubeconfig is empty, please re-add cluster with kubeconfig")
	}
	cfg, err := clientcmd.RESTConfigFromKubeConfig([]byte(raw))
	if err != nil {
		return nil, fmt.Errorf("parse cluster kubeconfig failed: %w", err)
	}
	cfg.Timeout = 30 * time.Second
	clientset, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("create kubernetes client failed: %w", err)
	}
	return clientset, nil
}

func toPolicyRules(rules []kubeconf.PermissionRule) []rbacv1.PolicyRule {
	out := make([]rbacv1.PolicyRule, 0, len(rules))
	for _, rule := range rules {
		out = append(out, rbacv1.PolicyRule{
			APIGroups: []string{rule.APIGroup},
			Resources: []string{rule.Resource},
			Verbs:     append([]string{}, rule.Verbs...),
		})
	}
	return out
}

func ensureServiceAccount(ctx context.Context, clientset *kubernetes.Clientset, name, namespace string, tracker *applyTracker) error {
	_, getErr := clientset.CoreV1().ServiceAccounts(namespace).Get(ctx, name, metav1.GetOptions{})
	if getErr == nil {
		// Already exists; SA has no mutable fields from our create form.
		return nil
	}
	if !apierrors.IsNotFound(getErr) {
		return fmt.Errorf("get ServiceAccount %s/%s failed: %w", namespace, name, getErr)
	}
	_, err := clientset.CoreV1().ServiceAccounts(namespace).Create(ctx, &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
	}, metav1.CreateOptions{})
	if err == nil {
		tracker.saCreated = true
		return nil
	}
	if apierrors.IsAlreadyExists(err) {
		return nil
	}
	return fmt.Errorf("create ServiceAccount %s/%s failed: %w", namespace, name, err)
}

func ensureRole(ctx context.Context, clientset *kubernetes.Clientset, name, namespace string, rules []rbacv1.PolicyRule, tracker *applyTracker) error {
	obj := &rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Rules:      rules,
	}
	existing, getErr := clientset.RbacV1().Roles(namespace).Get(ctx, name, metav1.GetOptions{})
	if getErr == nil {
		if policyRulesEqual(existing.Rules, rules) {
			return nil
		}
		existing.Rules = rules
		if _, err := clientset.RbacV1().Roles(namespace).Update(ctx, existing, metav1.UpdateOptions{}); err != nil {
			return fmt.Errorf("update Role %s/%s failed: %w", namespace, name, err)
		}
		return nil
	}
	if !apierrors.IsNotFound(getErr) {
		return fmt.Errorf("get Role %s/%s failed: %w", namespace, name, getErr)
	}
	_, err := clientset.RbacV1().Roles(namespace).Create(ctx, obj, metav1.CreateOptions{})
	if err == nil {
		tracker.roleCreated = true
		return nil
	}
	if apierrors.IsAlreadyExists(err) {
		existing, getErr = clientset.RbacV1().Roles(namespace).Get(ctx, name, metav1.GetOptions{})
		if getErr != nil {
			return fmt.Errorf("get existing Role %s/%s failed: %w", namespace, name, getErr)
		}
		if policyRulesEqual(existing.Rules, rules) {
			return nil
		}
		existing.Rules = rules
		if _, err := clientset.RbacV1().Roles(namespace).Update(ctx, existing, metav1.UpdateOptions{}); err != nil {
			return fmt.Errorf("update Role %s/%s failed: %w", namespace, name, err)
		}
		return nil
	}
	return fmt.Errorf("create Role %s/%s failed: %w", namespace, name, err)
}

func ensureClusterRole(ctx context.Context, clientset *kubernetes.Clientset, name string, rules []rbacv1.PolicyRule, tracker *applyTracker) error {
	obj := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Rules:      rules,
	}
	existing, getErr := clientset.RbacV1().ClusterRoles().Get(ctx, name, metav1.GetOptions{})
	if getErr == nil {
		if policyRulesEqual(existing.Rules, rules) {
			return nil
		}
		existing.Rules = rules
		if _, err := clientset.RbacV1().ClusterRoles().Update(ctx, existing, metav1.UpdateOptions{}); err != nil {
			return fmt.Errorf("update ClusterRole %s failed: %w", name, err)
		}
		return nil
	}
	if !apierrors.IsNotFound(getErr) {
		return fmt.Errorf("get ClusterRole %s failed: %w", name, getErr)
	}
	_, err := clientset.RbacV1().ClusterRoles().Create(ctx, obj, metav1.CreateOptions{})
	if err == nil {
		tracker.roleCreated = true
		return nil
	}
	if apierrors.IsAlreadyExists(err) {
		existing, getErr = clientset.RbacV1().ClusterRoles().Get(ctx, name, metav1.GetOptions{})
		if getErr != nil {
			return fmt.Errorf("get existing ClusterRole %s failed: %w", name, getErr)
		}
		if policyRulesEqual(existing.Rules, rules) {
			return nil
		}
		existing.Rules = rules
		if _, err := clientset.RbacV1().ClusterRoles().Update(ctx, existing, metav1.UpdateOptions{}); err != nil {
			return fmt.Errorf("update ClusterRole %s failed: %w", name, err)
		}
		return nil
	}
	return fmt.Errorf("create ClusterRole %s failed: %w", name, err)
}

func ensureRoleBinding(ctx context.Context, clientset *kubernetes.Clientset, name, roleName, namespace, saName, saNamespace string, tracker *applyTracker) error {
	obj := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Subjects: []rbacv1.Subject{{
			Kind:      "ServiceAccount",
			Name:      saName,
			Namespace: saNamespace,
		}},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "Role",
			Name:     roleName,
		},
	}
	existing, getErr := clientset.RbacV1().RoleBindings(namespace).Get(ctx, name, metav1.GetOptions{})
	if getErr == nil {
		if roleRefsEqual(existing.RoleRef, obj.RoleRef) && subjectsEqual(existing.Subjects, obj.Subjects) {
			return nil
		}
		if !roleRefsEqual(existing.RoleRef, obj.RoleRef) {
			if err := clientset.RbacV1().RoleBindings(namespace).Delete(ctx, name, metav1.DeleteOptions{}); err != nil {
				return fmt.Errorf("recreate RoleBinding %s/%s delete failed: %w", namespace, name, err)
			}
			if _, err := clientset.RbacV1().RoleBindings(namespace).Create(ctx, obj, metav1.CreateOptions{}); err != nil {
				return fmt.Errorf("recreate RoleBinding %s/%s failed: %w", namespace, name, err)
			}
			tracker.bindingCreated = true
			return nil
		}
		existing.Subjects = obj.Subjects
		if _, err := clientset.RbacV1().RoleBindings(namespace).Update(ctx, existing, metav1.UpdateOptions{}); err != nil {
			return fmt.Errorf("update RoleBinding %s/%s failed: %w", namespace, name, err)
		}
		return nil
	}
	if !apierrors.IsNotFound(getErr) {
		return fmt.Errorf("get RoleBinding %s/%s failed: %w", namespace, name, getErr)
	}
	_, err := clientset.RbacV1().RoleBindings(namespace).Create(ctx, obj, metav1.CreateOptions{})
	if err == nil {
		tracker.bindingCreated = true
		return nil
	}
	if apierrors.IsAlreadyExists(err) {
		return ensureRoleBinding(ctx, clientset, name, roleName, namespace, saName, saNamespace, tracker)
	}
	return fmt.Errorf("create RoleBinding %s/%s failed: %w", namespace, name, err)
}

func ensureClusterRoleBinding(ctx context.Context, clientset *kubernetes.Clientset, name, roleName, saName, saNamespace string, tracker *applyTracker) error {
	obj := &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Subjects: []rbacv1.Subject{{
			Kind:      "ServiceAccount",
			Name:      saName,
			Namespace: saNamespace,
		}},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     roleName,
		},
	}
	existing, getErr := clientset.RbacV1().ClusterRoleBindings().Get(ctx, name, metav1.GetOptions{})
	if getErr == nil {
		if roleRefsEqual(existing.RoleRef, obj.RoleRef) && subjectsEqual(existing.Subjects, obj.Subjects) {
			return nil
		}
		if !roleRefsEqual(existing.RoleRef, obj.RoleRef) {
			if err := clientset.RbacV1().ClusterRoleBindings().Delete(ctx, name, metav1.DeleteOptions{}); err != nil {
				return fmt.Errorf("recreate ClusterRoleBinding %s delete failed: %w", name, err)
			}
			if _, err := clientset.RbacV1().ClusterRoleBindings().Create(ctx, obj, metav1.CreateOptions{}); err != nil {
				return fmt.Errorf("recreate ClusterRoleBinding %s failed: %w", name, err)
			}
			tracker.bindingCreated = true
			return nil
		}
		existing.Subjects = obj.Subjects
		if _, err := clientset.RbacV1().ClusterRoleBindings().Update(ctx, existing, metav1.UpdateOptions{}); err != nil {
			return fmt.Errorf("update ClusterRoleBinding %s failed: %w", name, err)
		}
		return nil
	}
	if !apierrors.IsNotFound(getErr) {
		return fmt.Errorf("get ClusterRoleBinding %s failed: %w", name, getErr)
	}
	_, err := clientset.RbacV1().ClusterRoleBindings().Create(ctx, obj, metav1.CreateOptions{})
	if err == nil {
		tracker.bindingCreated = true
		return nil
	}
	if apierrors.IsAlreadyExists(err) {
		return ensureClusterRoleBinding(ctx, clientset, name, roleName, saName, saNamespace, tracker)
	}
	return fmt.Errorf("create ClusterRoleBinding %s failed: %w", name, err)
}

func createServiceAccountToken(
	ctx context.Context,
	clientset *kubernetes.Clientset,
	saName, saNamespace, secretName string,
	expirationSeconds int64,
	allowSecretFallback bool,
	tracker *applyTracker,
) (string, error) {
	if expirationSeconds < 600 {
		expirationSeconds = 600 // TokenRequest 通常要求最短约 10 分钟
	}
	// Prefer TokenRequest API (works on modern clusters without legacy secret tokens).
	tr, err := clientset.CoreV1().ServiceAccounts(saNamespace).CreateToken(ctx, saName, &authv1.TokenRequest{
		Spec: authv1.TokenRequestSpec{
			ExpirationSeconds: ptr.To(expirationSeconds),
		},
	}, metav1.CreateOptions{})
	if err == nil && strings.TrimSpace(tr.Status.Token) != "" {
		return tr.Status.Token, nil
	}
	tokenRequestErr := err
	if !allowSecretFallback {
		if tokenRequestErr != nil {
			return "", fmt.Errorf("签发 Token 失败（有效期 %d 秒）: %w", expirationSeconds, tokenRequestErr)
		}
		return "", fmt.Errorf("签发 Token 失败：TokenRequest 未返回 token")
	}

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretName,
			Namespace: saNamespace,
			Annotations: map[string]string{
				corev1.ServiceAccountNameKey: saName,
			},
		},
		Type: corev1.SecretTypeServiceAccountToken,
	}
	_, err = clientset.CoreV1().Secrets(saNamespace).Create(ctx, secret, metav1.CreateOptions{})
	if err == nil {
		tracker.secretCreated = true
	} else if !apierrors.IsAlreadyExists(err) {
		if tokenRequestErr != nil {
			return "", fmt.Errorf("create ServiceAccount token failed (TokenRequest: %v; Secret: %w)", tokenRequestErr, err)
		}
		return "", fmt.Errorf("create ServiceAccount token Secret failed: %w", err)
	}

	deadline := time.Now().Add(45 * time.Second)
	for time.Now().Before(deadline) {
		got, getErr := clientset.CoreV1().Secrets(saNamespace).Get(ctx, secretName, metav1.GetOptions{})
		if getErr == nil {
			if raw, ok := got.Data[corev1.ServiceAccountTokenKey]; ok && len(raw) > 0 {
				return string(raw), nil
			}
		}
		select {
		case <-ctx.Done():
			return "", fmt.Errorf("wait ServiceAccount token timed out: %w", ctx.Err())
		case <-time.After(1 * time.Second):
		}
	}
	if tokenRequestErr != nil {
		return "", fmt.Errorf("ServiceAccount token unavailable (TokenRequest: %v; Secret token not populated in time)", tokenRequestErr)
	}
	return "", fmt.Errorf("ServiceAccount token Secret %s/%s was not populated in time", saNamespace, secretName)
}

func cleanupCreated(
	ctx context.Context,
	clientset *kubernetes.Clientset,
	saName, saNamespace, roleNamespace, roleKind, roleName, bindingName, secretName string,
	tracker *applyTracker,
) {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()

	if tracker.secretCreated {
		_ = clientset.CoreV1().Secrets(saNamespace).Delete(ctx, secretName, metav1.DeleteOptions{})
	}
	if tracker.bindingCreated {
		if roleKind == "Role" {
			_ = clientset.RbacV1().RoleBindings(roleNamespace).Delete(ctx, bindingName, metav1.DeleteOptions{})
		} else {
			_ = clientset.RbacV1().ClusterRoleBindings().Delete(ctx, bindingName, metav1.DeleteOptions{})
		}
	}
	if tracker.roleCreated {
		if roleKind == "Role" {
			_ = clientset.RbacV1().Roles(roleNamespace).Delete(ctx, roleName, metav1.DeleteOptions{})
		} else {
			_ = clientset.RbacV1().ClusterRoles().Delete(ctx, roleName, metav1.DeleteOptions{})
		}
	}
	if tracker.saCreated {
		_ = clientset.CoreV1().ServiceAccounts(saNamespace).Delete(ctx, saName, metav1.DeleteOptions{})
	}
}

// DeleteRBACResources removes SA / Role|ClusterRole / Binding (and token secret) created for a kubeconfig.
// Missing resources are treated as success.
func DeleteRBACResources(
	kubeconfigContent string,
	saName, saNamespace, roleNamespace, roleKind string,
) error {
	saName = strings.TrimSpace(saName)
	saNamespace = strings.TrimSpace(saNamespace)
	roleNamespace = strings.TrimSpace(roleNamespace)
	roleKind = strings.TrimSpace(roleKind)
	if saName == "" || saNamespace == "" {
		return fmt.Errorf("service_account_name and sa_namespace are required")
	}
	if roleKind != "Role" && roleKind != "ClusterRole" {
		return fmt.Errorf("role_kind must be Role or ClusterRole")
	}
	if roleKind == "Role" && roleNamespace == "" {
		return fmt.Errorf("role_namespace is required when role_kind is Role")
	}

	clientset, err := clientsetFromKubeconfig(kubeconfigContent)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	roleName := saName + "-role"
	bindingName := saName + "-rolebinding"
	secretName := saName + "-token"

	var errs []string
	deleteIgnoreNotFound := func(err error, label string) {
		if err == nil || apierrors.IsNotFound(err) {
			return
		}
		errs = append(errs, fmt.Sprintf("%s: %v", label, err))
	}

	if roleKind == "Role" {
		deleteIgnoreNotFound(
			clientset.RbacV1().RoleBindings(roleNamespace).Delete(ctx, bindingName, metav1.DeleteOptions{}),
			"delete RoleBinding",
		)
		deleteIgnoreNotFound(
			clientset.RbacV1().Roles(roleNamespace).Delete(ctx, roleName, metav1.DeleteOptions{}),
			"delete Role",
		)
	} else {
		deleteIgnoreNotFound(
			clientset.RbacV1().ClusterRoleBindings().Delete(ctx, bindingName, metav1.DeleteOptions{}),
			"delete ClusterRoleBinding",
		)
		deleteIgnoreNotFound(
			clientset.RbacV1().ClusterRoles().Delete(ctx, roleName, metav1.DeleteOptions{}),
			"delete ClusterRole",
		)
	}
	deleteIgnoreNotFound(
		clientset.CoreV1().Secrets(saNamespace).Delete(ctx, secretName, metav1.DeleteOptions{}),
		"delete ServiceAccount token Secret",
	)
	deleteIgnoreNotFound(
		clientset.CoreV1().ServiceAccounts(saNamespace).Delete(ctx, saName, metav1.DeleteOptions{}),
		"delete ServiceAccount",
	)

	if len(errs) > 0 {
		return fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return nil
}
