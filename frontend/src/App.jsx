import { useEffect, useMemo, useRef, useState } from "react";

const menus = [
  { key: "datasource", label: "数据源" },
  { key: "users", label: "用户管理" },
  { key: "audit", label: "审计日志" },
  { key: "query", label: "查询数据" },
  { key: "create", label: "创建 kubeconfig" },
];

const ROLE_OPTIONS = [
  {
    value: "watcher",
    label: "观察者",
    desc: "可查询与下载 kubeconfig，不可创建或删除。",
  },
  {
    value: "operator",
    label: "操作员",
    desc: "可查询、创建与下载 kubeconfig；不可删除、管理数据源或查看审计。",
  },
  {
    value: "admin",
    label: "管理员",
    desc: "可管理数据源、查看审计、查询/创建/下载/删除 kubeconfig；可管理观察者与操作员，且仅可创建观察者账号。",
  },
  {
    value: "root",
    label: "超级管理员",
    desc: "拥有全部权限，包括创建任意角色用户与管理全部账号。",
  },
];

function roleLabel(role) {
  return ROLE_OPTIONS.find((r) => r.value === role)?.label || role || "-";
}

function canActorOperateTarget(actorRole, targetRole) {
  if (actorRole === "root") return true;
  if (actorRole === "admin") return targetRole === "watcher" || targetRole === "operator";
  return false;
}

function RolePermissionHelp({ selected, options = ROLE_OPTIONS }) {
  return (
    <div className="role-help">
      <div className="role-help-title">权限说明</div>
      {options.map((opt) => (
        <div key={opt.value} className={opt.value === selected ? "role-help-item active" : "role-help-item"}>
          <strong>{opt.label}</strong>
          <span>{opt.desc}</span>
        </div>
      ))}
    </div>
  );
}

const ACTION_LABELS = {
  login: "登录",
  logout: "登出",
  register: "注册",
  create_kubeconfig: "创建kubeconfig",
  delete_kubeconfig: "删除kubeconfig",
};

function actionLabel(action) {
  return ACTION_LABELS[action] || action || "-";
}

function resultLabel(result) {
  if (result === "success") return "成功";
  if (result === "failed") return "失败";
  return result || "-";
}

/** Convert datetime-local value to API query string. */
function toAuditTimeParam(value) {
  if (!value) return "";
  return String(value).replace("T", " ");
}

const ROLE_RESOURCE_CATALOG = [
  { resource: "pods", api_group: "" },
  { resource: "services", api_group: "" },
  { resource: "configmaps", api_group: "" },
  { resource: "secrets", api_group: "" },
  { resource: "persistentvolumeclaims", api_group: "" },
  { resource: "serviceaccounts", api_group: "" },
  { resource: "deployments", api_group: "apps" },
  { resource: "statefulsets", api_group: "apps" },
  { resource: "daemonsets", api_group: "apps" },
  { resource: "replicasets", api_group: "apps" },
  { resource: "jobs", api_group: "batch" },
  { resource: "cronjobs", api_group: "batch" },
  { resource: "ingresses", api_group: "networking.k8s.io" },
  { resource: "networkpolicies", api_group: "networking.k8s.io" },
  { resource: "roles", api_group: "rbac.authorization.k8s.io" },
  { resource: "rolebindings", api_group: "rbac.authorization.k8s.io" },
];

const CLUSTER_ROLE_RESOURCE_CATALOG = [
  { resource: "nodes", api_group: "" },
  { resource: "namespaces", api_group: "" },
  { resource: "persistentvolumes", api_group: "" },
  { resource: "componentstatuses", api_group: "" },
  { resource: "storageclasses", api_group: "storage.k8s.io" },
  { resource: "csidrivers", api_group: "storage.k8s.io" },
  { resource: "csinodes", api_group: "storage.k8s.io" },
  { resource: "priorityclasses", api_group: "scheduling.k8s.io" },
  { resource: "runtimeclasses", api_group: "node.k8s.io" },
  { resource: "clusterroles", api_group: "rbac.authorization.k8s.io" },
  { resource: "clusterrolebindings", api_group: "rbac.authorization.k8s.io" },
  { resource: "customresourcedefinitions", api_group: "apiextensions.k8s.io" },
  { resource: "apiservices", api_group: "apiregistration.k8s.io" },
  { resource: "mutatingwebhookconfigurations", api_group: "admissionregistration.k8s.io" },
  { resource: "validatingwebhookconfigurations", api_group: "admissionregistration.k8s.io" },
];

const CLUSTER_SCOPED_RESOURCES = new Set(CLUSTER_ROLE_RESOURCE_CATALOG.map((item) => item.resource));
const VERB_OPTIONS = ["get", "list", "watch", "create", "update", "patch", "delete"];
const DEFAULT_VERBS = ["get", "list", "watch"];
const DEFAULT_ROLE_RULES = [
  { resource: "pods", api_group: "", verbs: [...DEFAULT_VERBS] },
  { resource: "services", api_group: "", verbs: [...DEFAULT_VERBS] },
];
const DEFAULT_CLUSTER_ROLE_RULES = [
  { resource: "nodes", api_group: "", verbs: [...DEFAULT_VERBS] },
  { resource: "namespaces", api_group: "", verbs: [...DEFAULT_VERBS] },
];
const CLUSTER_PROVIDERS = [
  "阿里云 ACK",
  "腾讯云 TKE",
  "华为云 CCE",
  "微软云 AKS",
  "谷歌云 GKE",
  "Amazon EKS",
  "标准 Kubernetes 集群",
];
const TOAST_TTL_MS = 5000;
const TOAST_MAX = 5;

function buildBizTree(accounts) {
  const root = { children: new Map() };
  const sorted = [...accounts].sort((a, b) => String(a.name).localeCompare(String(b.name), "zh"));
  sorted.forEach((acct) => {
    const parts = String(acct.name || "")
      .split("-")
      .map((p) => p.trim())
      .filter(Boolean);
    if (!parts.length) return;
    let cursor = root;
    let path = "";
    parts.forEach((part, index) => {
      path = path ? `${path}-${part}` : part;
      if (!cursor.children.has(part)) {
        cursor.children.set(part, {
          key: path,
          label: part,
          path,
          account: null,
          children: new Map(),
        });
      }
      const node = cursor.children.get(part);
      if (index === parts.length - 1) {
        node.account = acct;
      }
      cursor = node;
    });
  });

  const toList = (map) =>
    Array.from(map.values()).map((node) => ({
      key: node.key,
      label: node.label,
      path: node.path,
      account: node.account,
      children: toList(node.children),
    }));
  return toList(root.children);
}

function collectExpandKeys(nodes, acc = []) {
  nodes.forEach((node) => {
    if (node.children?.length) {
      acc.push(node.key);
      collectExpandKeys(node.children, acc);
    }
  });
  return acc;
}

function collectAccountIDsByPath(accounts, path) {
  const prefix = `${path}-`;
  return accounts
    .filter((a) => a.name === path || String(a.name).startsWith(prefix))
    .map((a) => Number(a.id));
}

function EditIcon() {
  return (
    <svg viewBox="0 0 24 24" width="14" height="14" aria-hidden="true">
      <path
        fill="currentColor"
        d="M3 17.25V21h3.75L17.81 9.94l-3.75-3.75L3 17.25zm17.71-10.04a1.003 1.003 0 0 0 0-1.42l-2.5-2.5a1.003 1.003 0 0 0-1.42 0l-1.83 1.83 3.75 3.75 2-1.66z"
      />
    </svg>
  );
}

function isDNS1123Label(value) {
  if (!value || value.length > 63) return false;
  return /^[a-z0-9]([-a-z0-9]*[a-z0-9])?$/.test(value);
}

function isValidK8sResourceName(name) {
  const value = String(name || "").trim();
  if (!value) return false;
  if (value === "*") return true;
  const parts = value.split("/");
  if (parts.length > 2) return false;
  return parts.every((part) => isDNS1123Label(part));
}

function isValidApiGroup(group) {
  const value = String(group || "").trim();
  if (!value || value === "*") return true;
  // DNS subdomain (e.g. apps, networking.k8s.io)
  return /^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$/.test(value);
}

class AuthError extends Error {
  constructor(message = "登录已过期，请重新登录") {
    super(message);
    this.name = "AuthError";
  }
}

async function api(path, options = {}, token = "") {
  const headers = { "Content-Type": "application/json", ...(options.headers || {}) };
  if (token) headers.Authorization = `Bearer ${token}`;
  const res = await fetch(path, { ...options, headers });
  const data = await res.json().catch(() => ({}));
  if (res.status === 401 && token) {
    window.dispatchEvent(new CustomEvent("kc-auth-expired", { detail: { message: data.error || "登录已过期，请重新登录" } }));
    throw new AuthError(data.error || "登录已过期，请重新登录");
  }
  if (!res.ok) throw new Error(data.error || "request failed");
  return data;
}

function EyeToggleIcon({ open }) {
  if (open) {
    return (
      <svg className="eye-icon" viewBox="0 0 24 24" aria-hidden="true">
        <path
          fill="currentColor"
          d="M12 5c-5 0-9.27 3.11-11 7 1.73 3.89 6 7 11 7s9.27-3.11 11-7c-1.73-3.89-6-7-11-7zm0 12a5 5 0 1 1 0-10 5 5 0 0 1 0 10zm0-8a3 3 0 1 0 .001 6.001A3 3 0 0 0 12 9z"
        />
      </svg>
    );
  }
  return (
    <svg className="eye-icon" viewBox="0 0 24 24" aria-hidden="true">
      <path
        fill="currentColor"
        d="M2.1 3.51 3.51 2.1l18.38 18.39-1.41 1.41-3.05-3.05A12.4 12.4 0 0 1 12 19c-5 0-9.27-3.11-11-7a13.3 13.3 0 0 1 4.2-5.17L2.1 3.51zM12 7a5 5 0 0 1 4.9 3.96l-1.55-1.55A3 3 0 0 0 12 9c-.38 0-.74.08-1.07.21L9.3 7.58A4.9 4.9 0 0 1 12 7zm-8.86 5c.98 1.98 3.05 3.84 5.94 4.7l-1.7-1.7A5 5 0 0 1 7.1 9.96L4.4 7.26A11.5 11.5 0 0 0 3.14 12zM14.9 12.8l-2.7-2.7.1-.1a3 3 0 0 1 2.6 2.8z"
      />
    </svg>
  );
}

function ToastStack({ toasts, onClose }) {
  if (!toasts.length) return null;
  return (
    <div className="toast-stack" aria-live="polite">
      {toasts.map((t) => (
        <div key={t.id} className={`toast ${t.type}`}>
          <span className="toast-text">{t.text}</span>
          <button type="button" className="toast-close" aria-label="关闭提示" onClick={() => onClose(t.id)}>
            ×
          </button>
        </div>
      ))}
    </div>
  );
}

function useToastQueue() {
  const [toasts, setToasts] = useState([]);
  const timersRef = useRef(new Map());

  function removeToast(id) {
    setToasts((prev) => prev.filter((t) => t.id !== id));
  }

  function showMessage(text, type = "success") {
    const id = `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
    const expiresAt = Date.now() + TOAST_TTL_MS;
    setToasts((prev) => {
      const next = [...prev, { id, text, type, expiresAt }];
      return next.length > TOAST_MAX ? next.slice(next.length - TOAST_MAX) : next;
    });
  }

  useEffect(() => {
    const activeIds = new Set(toasts.map((t) => t.id));
    timersRef.current.forEach((timer, id) => {
      if (!activeIds.has(id)) {
        clearTimeout(timer);
        timersRef.current.delete(id);
      }
    });

    toasts.forEach((t) => {
      if (timersRef.current.has(t.id)) return;
      const delay = Math.max(0, (t.expiresAt || Date.now() + TOAST_TTL_MS) - Date.now());
      const timer = setTimeout(() => {
        timersRef.current.delete(t.id);
        setToasts((prev) => prev.filter((item) => item.id !== t.id));
      }, delay);
      timersRef.current.set(t.id, timer);
    });
  }, [toasts]);

  useEffect(() => {
    return () => {
      timersRef.current.forEach((timer) => clearTimeout(timer));
      timersRef.current.clear();
    };
  }, []);

  return { toasts, showMessage, removeToast };
}

const PASSWORD_RULE_HINT = "密码需包含大小写字母、数字、特殊字符，不少于6位且不超过24位";
const PASSWORD_RULE_ERROR = "密码不符合规范（需包含大小写字母、数字、特殊字符，不少于6位且不超过24位）";
const isPasswordValid = (password) =>
  password.length >= 6 &&
  password.length <= 24 &&
  /[A-Z]/.test(password) &&
  /[a-z]/.test(password) &&
  /\d/.test(password) &&
  /[^A-Za-z0-9]/.test(password);

function initialAuthView() {
  const path = window.location.pathname || "";
  if (path.startsWith("/reset-password")) return "reset";
  if (path.startsWith("/register")) return "register";
  return "login";
}

function LoginRegister({ onLogin }) {
  const [view, setView] = useState(initialAuthView);
  const { toasts, showMessage, removeToast } = useToastQueue();
  const [loginPasswordVisible, setLoginPasswordVisible] = useState(false);
  const [loading, setLoading] = useState(false);
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [captchaCode, setCaptchaCode] = useState("");
  const [captchaToken, setCaptchaToken] = useState("");
  const [captchaImageUrl, setCaptchaImageUrl] = useState("");

  const [regUsername, setRegUsername] = useState("");
  const [regUsernameValid, setRegUsernameValid] = useState(true);
  const [regUsernameMessage, setRegUsernameMessage] = useState("");
  const [regDisplayName, setRegDisplayName] = useState("");
  const [regPhone, setRegPhone] = useState("");
  const [regPhoneValid, setRegPhoneValid] = useState(true);
  const [regPhoneMessage, setRegPhoneMessage] = useState("");
  const [regEmail, setRegEmail] = useState("");
  const [regEmailValid, setRegEmailValid] = useState(true);
  const [regEmailMessage, setRegEmailMessage] = useState("");
  const [regPassword, setRegPassword] = useState("");
  const [regPasswordMessage, setRegPasswordMessage] = useState("");
  const [regConfirmPassword, setRegConfirmPassword] = useState("");
  const [regConfirmMessage, setRegConfirmMessage] = useState("");
  const [regCaptchaCode, setRegCaptchaCode] = useState("");
  const [regCaptchaToken, setRegCaptchaToken] = useState("");
  const [regCaptchaImageUrl, setRegCaptchaImageUrl] = useState("");

  const [resetToken] = useState(() => new URLSearchParams(window.location.search).get("token") || "");
  const [newPassword, setNewPassword] = useState("");
  const [confirmNewPassword, setConfirmNewPassword] = useState("");

  function goView(next) {
    setView(next);
    const path = next === "register" ? "/register" : next === "reset" ? "/reset-password" : "/login";
    const search = next === "reset" ? window.location.search : "";
    window.history.pushState({}, "", path + search);
  }

  function refreshLoginCaptcha() {
    const token = crypto.randomUUID().replace(/-/g, "");
    setCaptchaToken(token);
    setCaptchaCode("");
    setCaptchaImageUrl(`/api/captcha?token=${encodeURIComponent(token)}&t=${Date.now()}`);
  }

  function refreshRegCaptcha() {
    const token = crypto.randomUUID().replace(/-/g, "");
    setRegCaptchaToken(token);
    setRegCaptchaCode("");
    setRegCaptchaImageUrl(`/api/captcha?token=${encodeURIComponent(token)}&t=${Date.now()}`);
  }

  async function checkExists(field, value) {
    if (!value) return false;
    try {
      const data = await api(`/api/check-exists?field=${field}&value=${encodeURIComponent(value)}`);
      return !!data.exists;
    } catch {
      return false;
    }
  }

  useEffect(() => {
    const flash = sessionStorage.getItem("kc_auth_flash");
    if (flash) {
      sessionStorage.removeItem("kc_auth_flash");
      showMessage(flash, "error");
    }
    const onPop = () => setView(initialAuthView());
    window.addEventListener("popstate", onPop);
    return () => window.removeEventListener("popstate", onPop);
  }, []);

  useEffect(() => {
    if (view === "login") refreshLoginCaptcha();
    if (view === "register") refreshRegCaptcha();
  }, [view]);

  async function submitLogin(e) {
    e.preventDefault();
    if (!captchaToken || !captchaCode) {
      showMessage("请输入验证码", "error");
      return;
    }
    if (!/^\d{4}$/.test(captchaCode)) {
      showMessage("验证码必须为4位数字", "error");
      return;
    }
    setLoading(true);
    try {
      const data = await api("/api/login", {
        method: "POST",
        body: JSON.stringify({
          username,
          password,
          captcha_token: captchaToken,
          captcha_code: captchaCode,
        }),
      });
      window.history.replaceState({}, "", "/");
      onLogin(data);
    } catch (err) {
      showMessage(err.message, "error");
      refreshLoginCaptcha();
    } finally {
      setLoading(false);
    }
  }

  async function handleResetPassword() {
    if (!username.trim()) {
      showMessage("请先输入用户名或手机号", "error");
      return;
    }
    try {
      const data = await api("/api/reset-password", {
        method: "POST",
        body: JSON.stringify({ account: username.trim() }),
      });
      showMessage(data.message || "重置链接已发送到该账号绑定邮箱，请检查邮箱。", "success");
    } catch (err) {
      showMessage(err.message, "error");
    }
  }

  async function validateUsername(value) {
    setRegUsername(value);
    if (value === "") {
      setRegUsernameValid(true);
      setRegUsernameMessage("");
      return;
    }
    if (value.length < 3) {
      setRegUsernameValid(false);
      setRegUsernameMessage("用户名最少3个字符");
      return;
    }
    if (value.length > 24) {
      setRegUsernameValid(false);
      setRegUsernameMessage("用户名最长不超过24个字符");
      return;
    }
    const adminBlacklist = ["root", "admin", "administrator", "superadmin", "super_admin", "admin_root", "root_admin", "system", "adminstrator"];
    if (adminBlacklist.includes(value.toLowerCase())) {
      setRegUsernameValid(false);
      setRegUsernameMessage("该用户名不允许注册");
      return;
    }
    if (!/^[a-z0-9]+$/.test(value)) {
      setRegUsernameValid(false);
      setRegUsernameMessage("用户名只能包含小写字母和数字");
      return;
    }
    const exists = await checkExists("username", value);
    if (exists) {
      setRegUsernameValid(false);
      setRegUsernameMessage("系统已存在该用户名");
    } else {
      setRegUsernameValid(true);
      setRegUsernameMessage("用户名格式正确");
    }
  }

  async function validatePhone(value) {
    setRegPhone(value);
    if (value === "") {
      setRegPhoneValid(true);
      setRegPhoneMessage("");
      return;
    }
    if (!/^1[3-9]\d{9}$/.test(value)) {
      setRegPhoneValid(false);
      setRegPhoneMessage("请输入有效的手机号码");
      return;
    }
    const exists = await checkExists("phone", value);
    if (exists) {
      setRegPhoneValid(false);
      setRegPhoneMessage("系统已存在该手机号");
    } else {
      setRegPhoneValid(true);
      setRegPhoneMessage("手机号格式正确");
    }
  }

  async function validateEmail(value) {
    setRegEmail(value);
    if (value === "") {
      setRegEmailValid(true);
      setRegEmailMessage("");
      return;
    }
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value)) {
      setRegEmailValid(false);
      setRegEmailMessage("请输入有效的邮箱地址");
      return;
    }
    const exists = await checkExists("email", value);
    if (exists) {
      setRegEmailValid(false);
      setRegEmailMessage("系统已存在该邮箱");
    } else {
      setRegEmailValid(true);
      setRegEmailMessage("邮箱格式正确");
    }
  }

  function validateRegConfirm(password, confirm) {
    if (!confirm) {
      setRegConfirmMessage("");
      return;
    }
    setRegConfirmMessage(password === confirm ? "两次密码一致" : "两次输入的密码不一致");
  }

  function onRegPasswordChange(value) {
    setRegPassword(value);
    if (!value) {
      setRegPasswordMessage("");
    } else {
      setRegPasswordMessage(isPasswordValid(value) ? "密码格式正确" : PASSWORD_RULE_ERROR);
    }
    validateRegConfirm(value, regConfirmPassword);
  }

  function onRegConfirmPasswordChange(value) {
    setRegConfirmPassword(value);
    validateRegConfirm(regPassword, value);
  }

  async function submitRegister(e) {
    e.preventDefault();
    if (!regUsername || !regDisplayName.trim() || !regPhone || !regEmail || !regPassword || !regConfirmPassword) {
      showMessage("请填写所有字段", "error");
      return;
    }
    if (!regUsernameValid) {
      showMessage(regUsernameMessage || "用户名无效", "error");
      return;
    }
    if (!regPhoneValid) {
      showMessage(regPhoneMessage || "手机号无效", "error");
      return;
    }
    if (!regEmailValid) {
      showMessage(regEmailMessage || "邮箱无效", "error");
      return;
    }
    if (regPassword !== regConfirmPassword) {
      setRegConfirmMessage("两次输入的密码不一致");
      showMessage("两次输入的密码不一致", "error");
      return;
    }
    if (!isPasswordValid(regPassword)) {
      setRegPasswordMessage(PASSWORD_RULE_ERROR);
      showMessage(PASSWORD_RULE_ERROR, "error");
      return;
    }
    if (!regCaptchaToken || !regCaptchaCode) {
      showMessage("请输入验证码", "error");
      return;
    }
    if (!/^\d{4}$/.test(regCaptchaCode)) {
      showMessage("验证码必须为4位数字", "error");
      return;
    }
    setLoading(true);
    try {
      await api("/api/register", {
        method: "POST",
        body: JSON.stringify({
          username: regUsername,
          display_name: regDisplayName.trim(),
          phone: regPhone,
          email: regEmail,
          password: regPassword,
          captcha_token: regCaptchaToken,
          captcha_code: regCaptchaCode,
        }),
      });
      showMessage("注册成功，请登录", "success");
      goView("login");
    } catch (err) {
      showMessage(err.message, "error");
      refreshRegCaptcha();
    } finally {
      setLoading(false);
    }
  }

  async function submitChangePassword(e) {
    e.preventDefault();
    if (!resetToken) {
      showMessage("重置链接无效，请重新发起找回密码。", "error");
      return;
    }
    if (!isPasswordValid(newPassword)) {
      showMessage(PASSWORD_RULE_ERROR, "error");
      return;
    }
    if (newPassword !== confirmNewPassword) {
      showMessage("两次输入的密码不一致。", "error");
      return;
    }
    setLoading(true);
    try {
      await api("/api/change-password", {
        method: "POST",
        body: JSON.stringify({ token: resetToken, new_password: newPassword }),
      });
      setNewPassword("");
      setConfirmNewPassword("");
      showMessage("密码已重置成功，请返回登录。", "success");
    } catch (err) {
      showMessage(err.message || "密码重置失败", "error");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="auth-container">
      <ToastStack toasts={toasts} onClose={removeToast} />
      <div className="auth-card">
        {view === "login" && (
          <>
            <h1>欢迎登录Kubeconfig管理系统</h1>
            <h2>登录</h2>
            <form onSubmit={submitLogin}>
              <div>
                <label>用户名/手机号</label>
                <input
                  type="text"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  required
                  placeholder="请输入用户名或手机号"
                />
              </div>
              <div>
                <label>密码</label>
                <div className="password-input-row auth-password-row">
                  <input
                    type={loginPasswordVisible ? "text" : "password"}
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    required
                    placeholder="请输入密码"
                  />
                  <button
                    type="button"
                    className="password-toggle-btn"
                    title={loginPasswordVisible ? "隐藏密码" : "显示密码"}
                    aria-label={loginPasswordVisible ? "隐藏密码" : "显示密码"}
                    onClick={() => setLoginPasswordVisible((v) => !v)}
                  >
                    <EyeToggleIcon open={loginPasswordVisible} />
                  </button>
                </div>
              </div>
              <div className="captcha-section">
                <label>验证码</label>
                <div className="captcha-row">
                  <input
                    type="text"
                    value={captchaCode}
                    onChange={(e) => setCaptchaCode(e.target.value.replace(/\D/g, "").slice(0, 4))}
                    required
                    placeholder="请输入4位数字验证码"
                    className="captcha-input"
                    inputMode="numeric"
                    maxLength={4}
                  />
                  <img
                    src={captchaImageUrl}
                    alt="验证码"
                    className="captcha-img"
                    onClick={refreshLoginCaptcha}
                    title="点击刷新验证码"
                  />
                </div>
              </div>
              <button type="submit" disabled={loading}>
                {loading ? "登录中..." : "登录"}
              </button>
            </form>
            <div className="auth-links">
              <button type="button" className="link-btn" onClick={handleResetPassword}>
                忘记密码？
              </button>
              <span>或</span>
              <button type="button" className="link-btn" onClick={() => goView("register")}>
                注册新账号
              </button>
            </div>
          </>
        )}

        {view === "register" && (
          <>
            <h1>欢迎注册Kubeconfig管理系统</h1>
            <h2>注册</h2>
            <form onSubmit={submitRegister}>
              <div>
                <label>用户名</label>
                <input
                  type="text"
                  value={regUsername}
                  onChange={(e) => validateUsername(e.target.value)}
                  required
                  placeholder="请输入用户名（最少3个至多24个字符，小写字母和数字）"
                  className={!regUsernameValid ? "invalid" : ""}
                />
                {regUsernameMessage && (
                  <span className={`hint-text ${regUsernameValid ? "valid" : "invalid"}`}>{regUsernameMessage}</span>
                )}
              </div>
              <div>
                <label>显示名</label>
                <input
                  type="text"
                  value={regDisplayName}
                  onChange={(e) => setRegDisplayName(e.target.value)}
                  required
                  placeholder="请输入显示名"
                  maxLength={120}
                />
              </div>
              <div>
                <label>手机号</label>
                <input
                  type="tel"
                  value={regPhone}
                  onChange={(e) => validatePhone(e.target.value)}
                  required
                  placeholder="请输入手机号"
                  className={!regPhoneValid ? "invalid" : ""}
                />
                {regPhoneMessage && (
                  <span className={`hint-text ${regPhoneValid ? "valid" : "invalid"}`}>{regPhoneMessage}</span>
                )}
              </div>
              <div>
                <label>邮箱</label>
                <input
                  type="email"
                  value={regEmail}
                  onChange={(e) => validateEmail(e.target.value)}
                  required
                  placeholder="请输入邮箱"
                  className={!regEmailValid ? "invalid" : ""}
                />
                {regEmailMessage && (
                  <span className={`hint-text ${regEmailValid ? "valid" : "invalid"}`}>{regEmailMessage}</span>
                )}
              </div>
              <div>
                <label>密码</label>
                <input
                  type="password"
                  value={regPassword}
                  onChange={(e) => onRegPasswordChange(e.target.value)}
                  required
                  placeholder="请输入密码（6-24位，含大小写、数字、特殊字符）"
                  maxLength={24}
                  className={regPassword && !isPasswordValid(regPassword) ? "invalid" : ""}
                />
                <span className={`hint-text ${regPasswordMessage ? (isPasswordValid(regPassword) ? "valid" : "invalid") : ""}`}>
                  {regPasswordMessage || PASSWORD_RULE_HINT}
                </span>
              </div>
              <div>
                <label>确认密码</label>
                <input
                  type="password"
                  value={regConfirmPassword}
                  onChange={(e) => onRegConfirmPasswordChange(e.target.value)}
                  required
                  placeholder="请再次输入密码"
                  maxLength={24}
                  className={regConfirmPassword && regConfirmPassword !== regPassword ? "invalid" : ""}
                />
                {regConfirmMessage && (
                  <span className={`hint-text ${regConfirmPassword === regPassword ? "valid" : "invalid"}`}>
                    {regConfirmMessage}
                  </span>
                )}
              </div>
              <div className="captcha-section">
                <label>验证码</label>
                <div className="captcha-row">
                  <input
                    type="text"
                    value={regCaptchaCode}
                    onChange={(e) => setRegCaptchaCode(e.target.value.replace(/\D/g, "").slice(0, 4))}
                    required
                    placeholder="请输入4位数字验证码"
                    className="captcha-input"
                    inputMode="numeric"
                    maxLength={4}
                  />
                  <img
                    src={regCaptchaImageUrl}
                    alt="验证码"
                    className="captcha-img"
                    onClick={refreshRegCaptcha}
                    title="点击刷新验证码"
                  />
                </div>
              </div>
              <button type="submit" disabled={loading}>
                {loading ? "注册中..." : "注册"}
              </button>
            </form>
            <div className="auth-links">
              <span>已有账号？</span>
              <button type="button" className="link-btn" onClick={() => goView("login")}>
                立即登录
              </button>
            </div>
          </>
        )}

        {view === "reset" && (
          <>
            <h1>设置新密码</h1>
            <h2>找回密码</h2>
            <form onSubmit={submitChangePassword}>
              <div>
                <label>新密码</label>
                <input
                  type="password"
                  value={newPassword}
                  onChange={(e) => setNewPassword(e.target.value)}
                  required
                  placeholder="请输入新密码（6-24位，含大小写、数字、特殊字符）"
                  maxLength={24}
                  className={newPassword && !isPasswordValid(newPassword) ? "invalid" : ""}
                />
                <span className={`hint-text ${newPassword && !isPasswordValid(newPassword) ? "invalid" : ""}`}>
                  {newPassword && !isPasswordValid(newPassword) ? PASSWORD_RULE_ERROR : PASSWORD_RULE_HINT}
                </span>
              </div>
              <div>
                <label>确认新密码</label>
                <input
                  type="password"
                  value={confirmNewPassword}
                  onChange={(e) => setConfirmNewPassword(e.target.value)}
                  required
                  placeholder="请再次输入新密码"
                  maxLength={24}
                />
              </div>
              <button type="submit" disabled={loading}>
                {loading ? "提交中..." : "确认修改"}
              </button>
            </form>
            <div className="auth-links">
              <button type="button" className="link-btn" onClick={() => goView("login")}>
                返回登录
              </button>
            </div>
          </>
        )}
      </div>
    </div>
  );
}

export default function App() {
  const [token, setToken] = useState(localStorage.getItem("kc_token") || "");
  const [user, setUser] = useState({
    id: Number(localStorage.getItem("kc_user_id") || 0),
    name: localStorage.getItem("kc_name") || "",
    display_name: localStorage.getItem("kc_display_name") || localStorage.getItem("kc_name") || "",
    phone: localStorage.getItem("kc_phone") || "",
    email: localStorage.getItem("kc_email") || "",
    role: localStorage.getItem("kc_role") || "",
  });
  const [activeMenu, setActiveMenu] = useState("query");
  const { toasts, showMessage, removeToast } = useToastQueue();
  const [rbacModal, setRbacModal] = useState(null);
  const [createUserModal, setCreateUserModal] = useState(false);
  const [editUserModal, setEditUserModal] = useState(null);
  const [resetPasswordResult, setResetPasswordResult] = useState(null);
  const [profileModal, setProfileModal] = useState(null);

  const [accounts, setAccounts] = useState([]);
  const [clusters, setClusters] = useState([]);
  const [records, setRecords] = useState([]);
  const [recordsTotal, setRecordsTotal] = useState(0);
  const [recordsPage, setRecordsPage] = useState(1);
  const [recordsSize, setRecordsSize] = useState(20);
  const [users, setUsers] = useState([]);
  const [usersTotal, setUsersTotal] = useState(0);
  const [usersPage, setUsersPage] = useState(1);
  const [usersSize] = useState(10);
  const [userKeyword, setUserKeyword] = useState("");
  const [audits, setAudits] = useState([]);
  const [auditTotal, setAuditTotal] = useState(0);
  const [auditPage, setAuditPage] = useState(1);
  const [auditSize] = useState(10);
  const [auditFilter, setAuditFilter] = useState({
    keyword: "",
    start_at: "",
    end_at: "",
  });
  const [userMenuOpen, setUserMenuOpen] = useState(false);
  const userMenuCloseTimer = useRef(null);

  const [queryFilter, setQueryFilter] = useState({ account_id: "", cluster_id: "" });
  const [datasourceKeyword, setDatasourceKeyword] = useState("");
  const [selectedAccountId, setSelectedAccountId] = useState("");
  const [selectedPath, setSelectedPath] = useState("");
  const [expandedKeys, setExpandedKeys] = useState([]);
  const [bizPaneWidth, setBizPaneWidth] = useState(260);
  const [addAccountModal, setAddAccountModal] = useState(false);
  const [editAccountModal, setEditAccountModal] = useState(false);
  const [addClusterModal, setAddClusterModal] = useState(false);
  const [editClusterModal, setEditClusterModal] = useState(false);
  const [editingAccount, setEditingAccount] = useState(null);
  const [editingCluster, setEditingCluster] = useState(null);
  const [accountForm, setAccountForm] = useState({ name: "" });
  const [clusterForm, setClusterForm] = useState({
    account_id: "",
    name: "",
    version: "",
    provider: "阿里云 ACK",
    api_server: "",
    ca_cert: "",
    uploaded_kubeconfig: "",
  });
  const [createdClusterInfo, setCreatedClusterInfo] = useState(null);
  const [createdKubeconfigInfo, setCreatedKubeconfigInfo] = useState(null);

  function extractFromKubeconfig(text) {
    const content = String(text || "");
    const serverMatch = content.match(/^\s*server:\s*["']?([^\s"']+)["']?\s*$/m);
    const caMatch = content.match(/^\s*certificate-authority-data:\s*["']?([^\s"']+)["']?\s*$/m);
    return {
      api_server: serverMatch ? serverMatch[1].trim() : "",
      ca_cert: caMatch ? caMatch[1].trim() : "",
    };
  }

  function onKubeconfigChange(value) {
    const extracted = extractFromKubeconfig(value);
    setClusterForm((prev) => ({
      ...prev,
      uploaded_kubeconfig: value,
      api_server: extracted.api_server,
      ca_cert: extracted.ca_cert,
    }));
  }
  const [kubeForm, setKubeForm] = useState({
    name: "",
    account_id: "",
    cluster_id: "",
    service_account_name: "",
    sa_namespace: "",
    role_namespace: "",
    role_kind: "Role",
    token_ttl_mode: "temporary",
    token_ttl_days: "3",
    rules: DEFAULT_ROLE_RULES.map((r) => ({ ...r, verbs: [...r.verbs] })),
  });
  const [clusterNamespaces, setClusterNamespaces] = useState([]);
  const [namespacesLoading, setNamespacesLoading] = useState(false);
  const [kubeCreating, setKubeCreating] = useState(false);
  const [customResourceInput, setCustomResourceInput] = useState({ resource: "", api_group: "" });
  const [createUserForm, setCreateUserForm] = useState({
    username: "",
    display_name: "",
    phone: "",
    email: "",
    password: "",
    role: "watcher",
  });

  const role = user.role;
  const canManageDatasource = role === "admin" || role === "root";
  const canManageUsers = role === "admin" || role === "root";
  const canCreateUsers = role === "admin" || role === "root";
  const canViewAudit = role === "admin" || role === "root";
  const canCreateKubeconfig = role === "operator" || role === "admin" || role === "root";
  const canDownloadKubeconfig = role === "watcher" || role === "operator" || role === "admin" || role === "root";
  const canDeleteKubeconfig = role === "admin" || role === "root";
  const createRoleOptions = useMemo(
    () => (role === "admin" ? ROLE_OPTIONS.filter((opt) => opt.value === "watcher") : ROLE_OPTIONS),
    [role]
  );
  const editableRoleOptions = useMemo(
    () => (role === "admin" ? ROLE_OPTIONS.filter((opt) => opt.value === "watcher" || opt.value === "operator") : ROLE_OPTIONS),
    [role]
  );
  const canAccessMenu = (key) => {
    if (key === "datasource") return canManageDatasource;
    if (key === "users") return canManageUsers;
    if (key === "audit") return canViewAudit;
    if (key === "create") return canCreateKubeconfig;
    return true; // query
  };
  const activeResourceCatalog = kubeForm.role_kind === "ClusterRole" ? CLUSTER_ROLE_RESOURCE_CATALOG : ROLE_RESOURCE_CATALOG;
  const filteredClustersForCreate = useMemo(() => {
    const aid = Number(kubeForm.account_id || 0);
    return clusters.filter((c) => c.account_id === aid);
  }, [clusters, kubeForm.account_id]);
  const filteredClustersForQuery = useMemo(() => {
    const aid = Number(queryFilter.account_id || 0);
    return clusters.filter((c) => c.account_id === aid);
  }, [clusters, queryFilter.account_id]);

  const filteredAccounts = useMemo(() => {
    const keyword = datasourceKeyword.trim().toLowerCase();
    if (!keyword) return accounts;
    const matchedAccountIDs = new Set();
    accounts.forEach((acct) => {
      if (String(acct.name || "").toLowerCase().includes(keyword)) {
        matchedAccountIDs.add(Number(acct.id));
      }
    });
    clusters.forEach((cluster) => {
      if (String(cluster.name || "").toLowerCase().includes(keyword)) {
        matchedAccountIDs.add(Number(cluster.account_id));
      }
    });
    return accounts.filter((acct) => matchedAccountIDs.has(Number(acct.id)));
  }, [accounts, clusters, datasourceKeyword]);

  const bizTree = useMemo(() => buildBizTree(filteredAccounts), [filteredAccounts]);

  const selectedClusters = useMemo(() => {
    if (!selectedPath) return [];
    const ids = new Set(collectAccountIDsByPath(accounts, selectedPath));
    return clusters.filter((c) => ids.has(Number(c.account_id)));
  }, [accounts, clusters, selectedPath]);

  useEffect(() => {
    setExpandedKeys((prev) => {
      const next = collectExpandKeys(bizTree);
      if (!prev.length) return next;
      const keep = prev.filter((k) => next.includes(k) || bizTree.some((n) => n.key === k));
      return Array.from(new Set([...keep, ...next]));
    });
  }, [bizTree]);

  useEffect(() => {
    if (!filteredAccounts.length) {
      setSelectedAccountId("");
      setSelectedPath("");
      return;
    }
    const pathStillValid =
      selectedPath &&
      (accounts.some((a) => a.name === selectedPath || String(a.name).startsWith(`${selectedPath}-`)) ||
        filteredAccounts.some((a) => a.name === selectedPath || String(a.name).startsWith(`${selectedPath}-`)));
    if (!pathStillValid) {
      const first = filteredAccounts[0];
      setSelectedPath(first.name);
      setSelectedAccountId(String(first.id));
    }
  }, [filteredAccounts, accounts, selectedPath]);

  async function loadAccountsAndClusters() {
    const [a, c] = await Promise.all([api("/api/accounts", {}, token), api("/api/clusters", {}, token)]);
    setAccounts(a.accounts || []);
    setClusters(c.clusters || []);
  }

  async function loadUsers() {
    if (!canManageUsers) return;
    const params = new URLSearchParams({
      page: String(usersPage),
      size: String(usersSize),
      keyword: userKeyword,
    });
    const data = await api(`/api/users?${params.toString()}`, {}, token);
    setUsers(data.users || []);
    setUsersTotal(data.total || 0);
  }

  async function loadAudits() {
    const params = new URLSearchParams({
      page: String(auditPage),
      size: String(auditSize),
    });
    if (auditFilter.keyword) params.set("keyword", auditFilter.keyword);
    const startAt = toAuditTimeParam(auditFilter.start_at);
    const endAt = toAuditTimeParam(auditFilter.end_at);
    if (startAt) params.set("start_at", startAt);
    if (endAt) params.set("end_at", endAt);
    const data = await api(`/api/audit-logs?${params.toString()}`, {}, token);
    setAudits(data.items || []);
    setAuditTotal(data.total || 0);
  }

  function openUserMenu() {
    if (userMenuCloseTimer.current) {
      clearTimeout(userMenuCloseTimer.current);
      userMenuCloseTimer.current = null;
    }
    setUserMenuOpen(true);
  }

  function scheduleCloseUserMenu() {
    if (userMenuCloseTimer.current) {
      clearTimeout(userMenuCloseTimer.current);
    }
    userMenuCloseTimer.current = setTimeout(() => {
      setUserMenuOpen(false);
      userMenuCloseTimer.current = null;
    }, 3000);
  }

  async function loadRecords() {
    const params = new URLSearchParams({
      page: String(recordsPage),
      size: String(recordsSize),
    });
    if (queryFilter.account_id) params.set("account_id", queryFilter.account_id);
    if (queryFilter.cluster_id) params.set("cluster_id", queryFilter.cluster_id);
    const data = await api(`/api/kubeconfigs?${params.toString()}`, {}, token);
    setRecords(data.kubeconfigs || []);
    setRecordsTotal(data.total || 0);
  }

  async function downloadAuthorizedFile(path, filename) {
    const res = await fetch(path, {
      headers: { Authorization: `Bearer ${token}` },
    });
    if (res.status === 401) {
      const data = await res.json().catch(() => ({}));
      window.dispatchEvent(
        new CustomEvent("kc-auth-expired", { detail: { message: data.error || "登录已过期，请重新登录" } })
      );
      return;
    }
    if (!res.ok) {
      const data = await res.json().catch(() => ({}));
      throw new Error(data.error || "下载失败");
    }
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  }

  async function downloadKubeconfigFile(id, name) {
    try {
      await downloadAuthorizedFile(
        `/api/kubeconfigs/${id}/download`,
        `${String(name || `kubeconfig-${id}`).replace(/\s+/g, "_")}.yaml`
      );
    } catch (err) {
      showMessage(err.message, "error");
    }
  }

  async function openRBACYamlModal(id, name) {
    setRbacModal({ id, name, yaml: "", loading: true });
    try {
      const data = await api(`/api/kubeconfigs/${id}/rbac-yaml`, {}, token);
      setRbacModal({ id, name, yaml: data.rbac_yaml || "", loading: false });
    } catch (err) {
      setRbacModal(null);
      showMessage(err.message, "error");
    }
  }

  async function copyRBACYaml() {
    const text = rbacModal?.yaml || "";
    if (!text) {
      showMessage("暂无内容可复制", "error");
      return;
    }
    try {
      await navigator.clipboard.writeText(text);
      showMessage("RBAC YAML 已复制", "success");
    } catch {
      showMessage("复制失败，请手动选择复制", "error");
    }
  }

  async function deleteKubeconfigRecord(id, name) {
    if (!window.confirm(`确认删除 kubeconfig「${name}」？将同时删除集群上的 SA / Role(Binding) 或 ClusterRole(Binding)。`)) {
      return;
    }
    try {
      await api(`/api/kubeconfigs/${id}`, { method: "DELETE" }, token);
      showMessage("删除成功", "success");
      const tasks = [loadRecords()];
      if (canViewAudit) tasks.push(loadAudits());
      await Promise.all(tasks);
    } catch (err) {
      showMessage(err.message, "error");
    }
  }

  function formatRulesDisplay(rules) {
    if (!Array.isArray(rules) || rules.length === 0) return "-";
    return rules
      .map((rule) => {
        const resource = rule.api_group ? `${rule.api_group}/${rule.resource}` : rule.resource;
        const verbs = Array.isArray(rule.verbs) ? rule.verbs.join(",") : "";
        return `${resource}: ${verbs}`;
      })
      .join("\n");
  }

  function formatTokenExpiresAt(value) {
    if (!value) return "";
    const d = new Date(value);
    if (Number.isNaN(d.getTime())) return String(value);
    return d.toLocaleString();
  }

  function formatRemainingDays(value, expiresAt) {
    if (value === null || value === undefined || value === "") return "-";
    const days = Number(value);
    if (Number.isNaN(days)) return "-";
    if (days <= 0) return "已过期";
    const tip = expiresAt ? `过期时间：${formatTokenExpiresAt(expiresAt)}` : "";
    return tip ? <span title={tip}>{days} 天</span> : `${days} 天`;
  }

  function startResizeBizPane(e) {
    e.preventDefault();
    const startX = e.clientX;
    const startWidth = bizPaneWidth;
    function onMove(ev) {
      const next = Math.min(480, Math.max(180, startWidth + (ev.clientX - startX)));
      setBizPaneWidth(next);
    }
    function onUp() {
      window.removeEventListener("mousemove", onMove);
      window.removeEventListener("mouseup", onUp);
      document.body.style.cursor = "";
      document.body.style.userSelect = "";
    }
    document.body.style.cursor = "col-resize";
    document.body.style.userSelect = "none";
    window.addEventListener("mousemove", onMove);
    window.addEventListener("mouseup", onUp);
  }

  async function loadAll() {
    try {
      await loadAccountsAndClusters();
      const tasks = [loadRecords()];
      if (canViewAudit) tasks.push(loadAudits());
      if (canManageUsers) tasks.push(loadUsers());
      await Promise.all(tasks);
    } catch (err) {
      showMessage(err.message, "error");
    }
  }

  useEffect(() => {
    if (!token) return;
    loadAll();

    function refreshUserInfo() {
      return api("/api/user-info", {}, token)
        .then((data) => {
          const next = {
            id: data.user_id || 0,
            name: data.name || "",
            display_name: data.display_name || data.name || "",
            phone: data.phone || "",
            email: data.email || "",
            role: data.role || "",
          };
          setUser(next);
          localStorage.setItem("kc_user_id", String(next.id || ""));
          localStorage.setItem("kc_name", next.name);
          localStorage.setItem("kc_display_name", next.display_name);
          localStorage.setItem("kc_phone", next.phone);
          localStorage.setItem("kc_email", next.email);
          localStorage.setItem("kc_role", next.role);
        })
        .catch(() => {});
    }

    refreshUserInfo();
    // 定时校验会话，用户被下线后尽快断开
    const timer = setInterval(refreshUserInfo, 5000);
    return () => clearInterval(timer);
  }, [token]);

  useEffect(() => {
    if (!canAccessMenu(activeMenu)) {
      const first = menus.find((m) => canAccessMenu(m.key));
      if (first) setActiveMenu(first.key);
    }
  }, [role, activeMenu]);

  useEffect(() => {
    if (!token || !canManageUsers) return;
    loadUsers().catch((err) => showMessage(err.message, "error"));
  }, [usersPage, userKeyword, canManageUsers]);

  useEffect(() => {
    if (!token) return;
    loadRecords().catch((err) => showMessage(err.message, "error"));
  }, [queryFilter.account_id, queryFilter.cluster_id, recordsPage, recordsSize]);

  useEffect(() => {
    if (!token || !canViewAudit) return;
    loadAudits().catch((err) => showMessage(err.message, "error"));
  }, [auditPage, auditFilter.keyword, auditFilter.start_at, auditFilter.end_at, canViewAudit]);

  useEffect(() => {
    return () => {
      if (userMenuCloseTimer.current) clearTimeout(userMenuCloseTimer.current);
    };
  }, []);

  function onLogin(data) {
    localStorage.setItem("kc_token", data.token);
    localStorage.setItem("kc_user_id", String(data.user_id || ""));
    localStorage.setItem("kc_name", data.name);
    localStorage.setItem("kc_display_name", data.display_name || data.name || "");
    localStorage.setItem("kc_phone", data.phone || "");
    localStorage.setItem("kc_email", data.email || "");
    localStorage.setItem("kc_role", data.role);
    setToken(data.token);
    setUser({
      id: data.user_id || 0,
      name: data.name,
      display_name: data.display_name || data.name || "",
      phone: data.phone || "",
      email: data.email || "",
      role: data.role,
    });
    showMessage("登录成功", "success");
  }

  async function logout(options = {}) {
    const { reason, skipAudit } = options;
    const currentToken = token || localStorage.getItem("kc_token") || "";
    if (!skipAudit && currentToken) {
      try {
        await api("/api/logout", { method: "POST" }, currentToken);
      } catch {
        // ignore logout audit failures
      }
    }
    if (userMenuCloseTimer.current) {
      clearTimeout(userMenuCloseTimer.current);
      userMenuCloseTimer.current = null;
    }
    setUserMenuOpen(false);
    localStorage.removeItem("kc_token");
    localStorage.removeItem("kc_user_id");
    localStorage.removeItem("kc_name");
    localStorage.removeItem("kc_display_name");
    localStorage.removeItem("kc_phone");
    localStorage.removeItem("kc_email");
    localStorage.removeItem("kc_role");
    setToken("");
    setUser({ id: 0, name: "", display_name: "", phone: "", email: "", role: "" });
    if (reason) {
      sessionStorage.setItem("kc_auth_flash", reason);
    }
  }

  useEffect(() => {
    function handleAuthExpired(event) {
      const reason = event?.detail?.message || "登录已过期，请重新登录";
      logout({ reason, skipAudit: true });
    }
    window.addEventListener("kc-auth-expired", handleAuthExpired);
    return () => window.removeEventListener("kc-auth-expired", handleAuthExpired);
  }, []);

  async function submitAccount() {
    try {
      const name = String(accountForm.name || "").trim();
      if (!name) {
        showMessage("请输入业务组名称", "error");
        return;
      }
      const data = await api("/api/accounts", { method: "POST", body: JSON.stringify({ name }) }, token);
      setAccountForm({ name: "" });
      setAddAccountModal(false);
      setSelectedPath(name);
      if (data?.id) setSelectedAccountId(String(data.id));
      showMessage("业务组创建成功", "success");
      await loadAccountsAndClusters();
    } catch (err) {
      showMessage(err.message, "error");
    }
  }

  async function submitEditAccount() {
    if (!editingAccount) return;
    try {
      const name = String(accountForm.name || "").trim();
      if (!name) {
        showMessage("请输入业务组名称", "error");
        return;
      }
      await api(`/api/accounts/${editingAccount.id}`, { method: "PUT", body: JSON.stringify({ name }) }, token);
      setEditAccountModal(false);
      setEditingAccount(null);
      setAccountForm({ name: "" });
      setSelectedPath(name);
      setSelectedAccountId(String(editingAccount.id));
      showMessage("业务组更新成功", "success");
      await loadAccountsAndClusters();
    } catch (err) {
      showMessage(err.message, "error");
    }
  }

  function resetClusterForm(accountID = "") {
    setClusterForm({
      account_id: accountID ? String(accountID) : "",
      name: "",
      version: "",
      provider: "阿里云 ACK",
      api_server: "",
      ca_cert: "",
      uploaded_kubeconfig: "",
    });
  }

  async function submitCluster() {
    try {
      if (!String(clusterForm.uploaded_kubeconfig || "").trim()) {
        showMessage("请粘贴原始 kubeconfig", "error");
        return;
      }
      const clusterName = clusterForm.name;
      const accountID = clusterForm.account_id;
      const data = await api(
        "/api/clusters",
        {
          method: "POST",
          body: JSON.stringify({
            account_id: Number(clusterForm.account_id),
            name: clusterForm.name,
            version: clusterForm.version,
            provider: clusterForm.provider,
            uploaded_kubeconfig: clusterForm.uploaded_kubeconfig,
          }),
        },
        token
      );
      resetClusterForm();
      setAddClusterModal(false);
      setCreatedClusterInfo({
        cluster_id: data.cluster_id,
        api_server: data.api_server,
        name: clusterName,
      });
      if (accountID) {
        setSelectedAccountId(String(accountID));
        const acct = accounts.find((a) => Number(a.id) === Number(accountID));
        if (acct) setSelectedPath(acct.name);
      }
      showMessage(`集群创建成功，集群ID：${data.cluster_id}`, "success");
      await loadAccountsAndClusters();
    } catch (err) {
      showMessage(err.message, "error");
    }
  }

  async function submitEditCluster() {
    if (!editingCluster) return;
    try {
      const payload = {
        account_id: Number(clusterForm.account_id),
        name: clusterForm.name,
        version: clusterForm.version,
        provider: clusterForm.provider,
      };
      if (String(clusterForm.uploaded_kubeconfig || "").trim()) {
        payload.uploaded_kubeconfig = clusterForm.uploaded_kubeconfig;
      }
      await api(`/api/clusters/${editingCluster.id}`, { method: "PUT", body: JSON.stringify(payload) }, token);
      setEditClusterModal(false);
      setEditingCluster(null);
      resetClusterForm();
      showMessage("集群更新成功", "success");
      await loadAccountsAndClusters();
    } catch (err) {
      showMessage(err.message, "error");
    }
  }

  function openEditAccount(acct, e) {
    e?.stopPropagation?.();
    setEditingAccount(acct);
    setAccountForm({ name: acct.name || "" });
    setEditAccountModal(true);
    setAddAccountModal(false);
  }

  function openEditCluster(cluster) {
    setEditingCluster(cluster);
    setClusterForm({
      account_id: String(cluster.account_id),
      name: cluster.name || "",
      version: cluster.version || "",
      provider: cluster.provider || "阿里云 ACK",
      api_server: cluster.api_server || "",
      ca_cert: "",
      uploaded_kubeconfig: "",
    });
    setEditClusterModal(true);
    setAddClusterModal(false);
  }

  function selectBizNode(node) {
    setSelectedPath(node.path);
    if (node.account) {
      setSelectedAccountId(String(node.account.id));
    } else {
      setSelectedAccountId("");
    }
  }

  function toggleExpand(key, e) {
    e?.stopPropagation?.();
    setExpandedKeys((prev) => (prev.includes(key) ? prev.filter((k) => k !== key) : [...prev, key]));
  }

  function renderBizTree(nodes, depth = 0) {
    return nodes.map((node) => {
      const hasChildren = node.children?.length > 0;
      const expanded = expandedKeys.includes(node.key);
      const active = selectedPath === node.path;
      return (
        <div key={node.key} className="biz-tree-node">
          <div
            className={`biz-group-item ${active ? "active" : ""}`}
            style={{ paddingLeft: 12 + depth * 16 }}
            onClick={() => selectBizNode(node)}
          >
            {hasChildren ? (
              <button type="button" className="biz-tree-toggle" onClick={(e) => toggleExpand(node.key, e)}>
                {expanded ? "▾" : "▸"}
              </button>
            ) : (
              <span className="biz-tree-toggle spacer" />
            )}
            <span className="biz-group-name" title={node.path}>
              {node.label}
            </span>
            {node.account && (
              <span className="biz-group-actions">
                <button type="button" className="biz-group-edit" title="编辑业务组" onClick={(e) => openEditAccount(node.account, e)}>
                  <EditIcon />
                </button>
                <button
                  type="button"
                  className="biz-group-delete"
                  title="删除业务组"
                  onClick={(e) => {
                    e.stopPropagation();
                    deleteAccount(node.account.id);
                  }}
                >
                  删除
                </button>
              </span>
            )}
          </div>
          {hasChildren && expanded ? renderBizTree(node.children, depth + 1) : null}
        </div>
      );
    });
  }

  async function deleteAccount(accountID) {
    if (!window.confirm("确认删除该业务组及其关联集群？")) return;
    try {
      await api(`/api/accounts/${accountID}`, { method: "DELETE" }, token);
      showMessage("业务组删除成功", "success");
      await loadAccountsAndClusters();
    } catch (err) {
      showMessage(err.message, "error");
    }
  }

  async function deleteCluster(clusterID) {
    if (!window.confirm("确认删除该集群？")) return;
    try {
      await api(`/api/clusters/${clusterID}`, { method: "DELETE" }, token);
      showMessage("集群删除成功", "success");
      await loadAccountsAndClusters();
    } catch (err) {
      showMessage(err.message, "error");
    }
  }

  function openAddClusterForAccount(accountID) {
    resetClusterForm(accountID);
    setAddClusterModal(true);
    setAddAccountModal(false);
    setEditClusterModal(false);
  }

  function hasRule(resource) {
    return kubeForm.rules.some((r) => r.resource === resource);
  }

  function changeRoleKind(kind) {
    const nextRules =
      kind === "ClusterRole"
        ? DEFAULT_CLUSTER_ROLE_RULES.map((r) => ({ ...r, verbs: [...r.verbs] }))
        : DEFAULT_ROLE_RULES.map((r) => ({ ...r, verbs: [...r.verbs] }));
    setKubeForm((prev) => ({
      ...prev,
      role_kind: kind,
      rules: nextRules,
      role_namespace: kind === "Role" ? prev.role_namespace || prev.sa_namespace || "" : "",
    }));
    setCustomResourceInput({ resource: "", api_group: "" });
  }

  async function loadClusterNamespaces(clusterID) {
    if (!clusterID) {
      setClusterNamespaces([]);
      return;
    }
    setNamespacesLoading(true);
    try {
      const data = await api(`/api/clusters/${clusterID}/namespaces`, {}, token);
      const list = data.namespaces || [];
      setClusterNamespaces(list);
      setKubeForm((prev) => {
        const next = { ...prev };
        if (list.length) {
          if (!list.includes(prev.sa_namespace)) next.sa_namespace = list.includes("default") ? "default" : list[0];
          if (prev.role_kind === "Role" && !list.includes(prev.role_namespace)) {
            next.role_namespace = list.includes("default") ? "default" : list[0];
          }
        }
        return next;
      });
    } catch (err) {
      setClusterNamespaces([]);
      showMessage(err.message || "获取命名空间失败", "error");
    } finally {
      setNamespacesLoading(false);
    }
  }

  function togglePresetResource(item) {
    setKubeForm((prev) => {
      const exists = prev.rules.some((r) => r.resource === item.resource);
      if (exists) {
        return { ...prev, rules: prev.rules.filter((r) => r.resource !== item.resource) };
      }
      return {
        ...prev,
        rules: [...prev.rules, { resource: item.resource, api_group: item.api_group, verbs: [...DEFAULT_VERBS] }],
      };
    });
  }

  function toggleRuleVerb(resource, verb) {
    setKubeForm((prev) => ({
      ...prev,
      rules: prev.rules.map((rule) => {
        if (rule.resource !== resource) return rule;
        const has = rule.verbs.includes(verb);
        const verbs = has ? rule.verbs.filter((v) => v !== verb) : [...rule.verbs, verb];
        return { ...rule, verbs };
      }),
    }));
  }

  function removeRule(resource) {
    setKubeForm((prev) => ({ ...prev, rules: prev.rules.filter((r) => r.resource !== resource) }));
  }

  function addCustomResource() {
    const resource = String(customResourceInput.resource || "").trim().toLowerCase();
    const apiGroup = String(customResourceInput.api_group || "").trim().toLowerCase();
    const baseResource = resource.split("/")[0];
    if (!resource) {
      showMessage("请输入资源名称", "error");
      return;
    }
    if (!isValidK8sResourceName(resource)) {
      showMessage("资源名称不符合 Kubernetes 规范（小写字母/数字/-，可含 subresource）", "error");
      return;
    }
    if (!isValidApiGroup(apiGroup)) {
      showMessage("API Group 不符合 Kubernetes DNS subdomain 规范", "error");
      return;
    }
    if (kubeForm.role_kind === "Role" && CLUSTER_SCOPED_RESOURCES.has(baseResource)) {
      showMessage("Role 不能授权集群级资源（如 nodes、namespaces），请改用 ClusterRole", "error");
      return;
    }
    if (hasRule(resource)) {
      showMessage("该资源权限已存在", "error");
      return;
    }
    setKubeForm((prev) => ({
      ...prev,
      rules: [...prev.rules, { resource, api_group: apiGroup, verbs: [...DEFAULT_VERBS] }],
    }));
    setCustomResourceInput({ resource: "", api_group: "" });
  }

  async function submitKubeconfig(e) {
    e.preventDefault();
    if (kubeCreating) return;
    try {
      if (!String(kubeForm.sa_namespace || "").trim()) {
        showMessage("请选择 ServiceAccount 命名空间", "error");
        return;
      }
      if (kubeForm.role_kind === "Role" && !String(kubeForm.role_namespace || "").trim()) {
        showMessage("请选择 Role/RoleBinding 命名空间", "error");
        return;
      }
      if (!kubeForm.rules.length) {
        showMessage("请至少选择一个资源权限", "error");
        return;
      }
      for (const rule of kubeForm.rules) {
        if (!rule.verbs?.length) {
          showMessage(`资源 ${rule.resource} 请至少选择一个操作权限`, "error");
          return;
        }
        const baseResource = String(rule.resource || "").split("/")[0];
        if (kubeForm.role_kind === "Role" && CLUSTER_SCOPED_RESOURCES.has(baseResource)) {
          showMessage(`Role 不能包含集群级资源 ${baseResource}`, "error");
          return;
        }
      }
      const ttlMode = kubeForm.token_ttl_mode || "temporary";
      let ttlDays = 3;
      if (ttlMode === "custom") {
        const rawDays = String(kubeForm.token_ttl_days || "").trim();
        if (!/^\d+$/.test(rawDays)) {
          showMessage("指定有效期天数必须为正整数", "error");
          return;
        }
        ttlDays = Number(rawDays);
        if (ttlDays < 1) {
          showMessage("指定有效期天数必须大于等于 1", "error");
          return;
        }
        if (ttlDays > 3650) {
          showMessage("指定有效期天数不能超过 3650 天", "error");
          return;
        }
      }
      setKubeCreating(true);
      const createdName = kubeForm.name;
      const data = await api(
        "/api/kubeconfigs",
        {
          method: "POST",
          body: JSON.stringify({
            name: kubeForm.name,
            account_id: Number(kubeForm.account_id),
            cluster_id: Number(kubeForm.cluster_id),
            service_account_name: kubeForm.service_account_name,
            sa_namespace: kubeForm.sa_namespace,
            role_namespace: kubeForm.role_kind === "Role" ? kubeForm.role_namespace : "",
            role_kind: kubeForm.role_kind,
            token_ttl_mode: ttlMode,
            token_ttl_days: ttlMode === "custom" ? ttlDays : ttlMode === "temporary" ? 3 : 0,
            rules: kubeForm.rules,
          }),
        },
        token
      );
      setKubeForm((prev) => ({
        ...prev,
        name: "",
        service_account_name: "",
        role_kind: "Role",
        token_ttl_mode: "temporary",
        token_ttl_days: "3",
        sa_namespace: prev.sa_namespace,
        role_namespace: prev.role_namespace || prev.sa_namespace,
        rules: DEFAULT_ROLE_RULES.map((r) => ({ ...r, verbs: [...r.verbs] })),
      }));
      setCreatedKubeconfigInfo({
        id: data.id,
        name: data.name || createdName,
        download_url: data.download_url || `/api/kubeconfigs/${data.id}/download`,
        token_expires_at: data.token_expires_at || "",
        token_ttl_mode: data.token_ttl_mode || ttlMode,
      });
      showMessage("kubeconfig 创建成功", "success");
      const tasks = [loadRecords()];
      if (canViewAudit) tasks.push(loadAudits());
      await Promise.all(tasks);
    } catch (err) {
      showMessage(err.message, "error");
    } finally {
      setKubeCreating(false);
    }
  }

  async function submitCreateUser(e) {
    e.preventDefault();
    try {
      await api(
        "/api/users",
        {
          method: "POST",
          body: JSON.stringify({
            username: createUserForm.username,
            display_name: createUserForm.display_name,
            phone: createUserForm.phone,
            email: createUserForm.email,
            password: createUserForm.password,
            role: createUserForm.role,
          }),
        },
        token
      );
      setCreateUserForm({ username: "", display_name: "", phone: "", email: "", password: "", role: "watcher" });
      setCreateUserModal(false);
      showMessage("用户创建成功", "success");
      await loadUsers();
    } catch (err) {
      showMessage(err.message, "error");
    }
  }

  async function submitEditUser(e) {
    e.preventDefault();
    if (!editUserModal) return;
    try {
      await api(
        `/api/users/${editUserModal.id}`,
        {
          method: "PUT",
          body: JSON.stringify({
            display_name: editUserModal.display_name,
            phone: editUserModal.phone,
            email: editUserModal.email,
            role: editUserModal.role,
          }),
        },
        token
      );
      setEditUserModal(null);
      showMessage("用户信息已更新", "success");
      await loadUsers();
    } catch (err) {
      showMessage(err.message, "error");
    }
  }

  async function toggleUserOffline(u) {
    const nextStatus = u.status === "disabled" ? "active" : "disabled";
    const actionLabel = nextStatus === "disabled" ? "下线" : "上线";
    if (!window.confirm(`确认${actionLabel}用户「${u.display_name || u.name}」？`)) return;
    try {
      await api(`/api/users/${u.id}/status`, { method: "PUT", body: JSON.stringify({ status: nextStatus }) }, token);
      showMessage(`用户已${actionLabel}`, "success");
      await loadUsers();
    } catch (err) {
      showMessage(err.message, "error");
    }
  }

  async function handleResetPassword(u) {
    const label = u.display_name || u.name;
    if (!window.confirm(`确认重置用户「${label}」的密码？将生成新的随机密码。`)) return;
    try {
      const data = await api(`/api/users/${u.id}/reset-password`, { method: "PUT", body: "{}" }, token);
      setResetPasswordResult({
        username: u.name,
        display_name: label,
        password: data.password || "",
      });
      showMessage("密码重置成功，请妥善保存新密码", "success");
    } catch (err) {
      showMessage(err.message, "error");
    }
  }

  async function deleteUser(userID, name) {
    if (!window.confirm(`确认删除用户「${name}」？此操作不可撤销。`)) return;
    try {
      await api(`/api/users/${userID}`, { method: "DELETE" }, token);
      showMessage("用户删除成功", "success");
      await loadUsers();
    } catch (err) {
      showMessage(err.message, "error");
    }
  }

  async function openProfileModal() {
    try {
      const data = await api("/api/user-info", {}, token);
      const next = {
        id: data.user_id || user.id,
        name: data.name || user.name,
        display_name: data.display_name || data.name || user.name,
        phone: data.phone || "",
        email: data.email || "",
        role: data.role || user.role,
      };
      setUser(next);
      localStorage.setItem("kc_user_id", String(next.id || ""));
      localStorage.setItem("kc_name", next.name);
      localStorage.setItem("kc_display_name", next.display_name);
      localStorage.setItem("kc_phone", next.phone);
      localStorage.setItem("kc_email", next.email);
      localStorage.setItem("kc_role", next.role);
      setProfileModal({
        name: next.name,
        display_name: next.display_name,
        phone: next.phone,
        email: next.email,
        new_password: "",
        confirm_password: "",
        password_message: "",
        confirm_message: "",
      });
    } catch {
      setProfileModal({
        name: user.name,
        display_name: user.display_name || user.name,
        phone: user.phone || "",
        email: user.email || "",
        new_password: "",
        confirm_password: "",
        password_message: "",
        confirm_message: "",
      });
    }
  }

  function onProfilePasswordChange(value) {
    const nextPwd = value.slice(0, 24);
    const passwordMessage = !nextPwd ? "" : isPasswordValid(nextPwd) ? "密码格式正确" : PASSWORD_RULE_ERROR;
    const confirm = profileModal?.confirm_password || "";
    const confirmMessage = !confirm ? "" : nextPwd === confirm ? "两次密码一致" : "两次输入的密码不一致";
    setProfileModal({
      ...profileModal,
      new_password: nextPwd,
      password_message: passwordMessage,
      confirm_message: confirmMessage,
    });
  }

  function onProfileConfirmPasswordChange(value) {
    const nextConfirm = value.slice(0, 24);
    const pwd = profileModal?.new_password || "";
    const confirmMessage = !nextConfirm ? "" : pwd === nextConfirm ? "两次密码一致" : "两次输入的密码不一致";
    setProfileModal({
      ...profileModal,
      confirm_password: nextConfirm,
      confirm_message: confirmMessage,
    });
  }

  async function submitProfile(e) {
    e.preventDefault();
    if (!profileModal) return;
    const newPassword = (profileModal.new_password || "").trim();
    const confirmPassword = (profileModal.confirm_password || "").trim();
    if (newPassword || confirmPassword) {
      if (!isPasswordValid(newPassword)) {
        setProfileModal({ ...profileModal, password_message: PASSWORD_RULE_ERROR });
        showMessage(PASSWORD_RULE_ERROR, "error");
        return;
      }
      if (newPassword !== confirmPassword) {
        setProfileModal({ ...profileModal, confirm_message: "两次输入的密码不一致" });
        showMessage("两次输入的密码不一致", "error");
        return;
      }
    }
    try {
      const payload = {
        display_name: profileModal.display_name,
        phone: profileModal.phone,
        email: profileModal.email,
      };
      if (newPassword) {
        payload.new_password = newPassword;
        payload.confirm_password = confirmPassword;
      }
      const data = await api(
        "/api/user-profile",
        {
          method: "PUT",
          body: JSON.stringify(payload),
        },
        token
      );
      const next = {
        ...user,
        display_name: data.display_name || profileModal.display_name,
        phone: data.phone || profileModal.phone,
        email: data.email || profileModal.email,
      };
      setUser(next);
      localStorage.setItem("kc_display_name", next.display_name);
      localStorage.setItem("kc_phone", next.phone);
      localStorage.setItem("kc_email", next.email);
      setProfileModal(null);
      showMessage(newPassword ? "个人信息与密码已更新" : "个人信息已更新", "success");
      if (canManageUsers) {
        await loadUsers().catch(() => {});
      }
    } catch (err) {
      showMessage(err.message, "error");
    }
  }

  const forceAuthView = typeof window !== "undefined" && window.location.pathname.startsWith("/reset-password");
  if (!token || forceAuthView) return <LoginRegister onLogin={onLogin} />;

  return (
    <div className="layout">
      <aside className="sidebar">
        <div className="brand">Kubeconfig UI</div>
        {menus.map((m) => {
          if (!canAccessMenu(m.key)) return null;
          return (
            <button key={m.key} className={activeMenu === m.key ? "menu active" : "menu"} onClick={() => setActiveMenu(m.key)}>
              {m.label}
            </button>
          );
        })}
      </aside>

      <main className="content">
        <header className="topbar">
          <div className="topbar-left">
            <h2>{menus.find((m) => m.key === activeMenu)?.label || "Kubeconfig UI"}</h2>
          </div>
          <div className="topbar-right">
            <div
              className={`user-menu${userMenuOpen ? " keep-open" : ""}`}
              onMouseEnter={openUserMenu}
              onMouseLeave={scheduleCloseUserMenu}
            >
              <button type="button" className="user-btn" onClick={openProfileModal}>
                <span className="avatar">{(user.display_name || user.name || "U").charAt(0).toUpperCase()}</span>
                <span className="user-details">
                  <span className="user-name">{user.display_name || user.name}</span>
                  <span className="user-role">{roleLabel(user.role)}</span>
                </span>
              </button>
              <div className="user-dropdown" onMouseEnter={openUserMenu} onMouseLeave={scheduleCloseUserMenu}>
                <button
                  type="button"
                  className="dropdown-item"
                  onClick={() => {
                    openUserMenu();
                    openProfileModal();
                  }}
                >
                  个人设置
                </button>
                <button type="button" className="dropdown-item logout-btn" onClick={() => logout()}>
                  退出登录
                </button>
              </div>
            </div>
          </div>
        </header>
        <ToastStack toasts={toasts} onClose={removeToast} />

        {activeMenu === "datasource" && canManageDatasource && (
          <>
            <section className="card datasource-split">
              <aside className="biz-group-pane" style={{ width: bizPaneWidth }}>
                <div className="biz-group-pane-head">
                  <h2>业务组</h2>
                  <button
                    type="button"
                    className="biz-group-add-btn"
                    title="新增业务组"
                    onClick={() => {
                      setAccountForm({ name: "" });
                      setAddAccountModal(true);
                      setEditAccountModal(false);
                      setAddClusterModal(false);
                    }}
                  >
                    +
                  </button>
                </div>
                <div className="biz-group-search">
                  <input
                    placeholder="请输入搜索关键字"
                    value={datasourceKeyword}
                    onChange={(e) => setDatasourceKeyword(e.target.value)}
                  />
                </div>
                <div className="biz-group-list">
                  {renderBizTree(bizTree)}
                  {bizTree.length === 0 && (
                    <div className="biz-group-empty">
                      {datasourceKeyword ? "未找到匹配的业务组" : "暂无业务组，请先添加"}
                    </div>
                  )}
                </div>
              </aside>

              <div className="datasource-resizer" onMouseDown={startResizeBizPane} title="拖动调整宽度" />

              <div className="biz-cluster-pane">
                <div className="table-head">
                  <h2>
                    Kubernetes集群信息列表
                    {selectedPath ? <span className="biz-cluster-subtitle">（{selectedPath}）</span> : null}
                  </h2>
                  <button
                    type="button"
                    disabled={!selectedAccountId}
                    onClick={() => openAddClusterForAccount(selectedAccountId)}
                  >
                    添加集群
                  </button>
                </div>
                <table>
                  <thead>
                    <tr>
                      <th>集群名称</th>
                      <th>集群ID</th>
                      <th>集群版本</th>
                      <th>APIServer</th>
                      <th>集群提供商</th>
                      <th>操作</th>
                    </tr>
                  </thead>
                  <tbody>
                    {selectedClusters.map((c) => (
                      <tr key={c.id}>
                        <td>{c.name}</td>
                        <td>{c.cluster_id}</td>
                        <td>{c.version || "-"}</td>
                        <td className="ellipsis-cell" title={c.api_server}>
                          {c.api_server}
                        </td>
                        <td>{c.provider || "-"}</td>
                        <td>
                          <button type="button" className="link-btn" onClick={() => openEditCluster(c)}>
                            编辑
                          </button>
                          <span className="btn-spacing">|</span>
                          <button type="button" className="link-btn error-text" onClick={() => deleteCluster(c.id)}>
                            删除
                          </button>
                        </td>
                      </tr>
                    ))}
                    {selectedClusters.length === 0 && (
                      <tr>
                        <td colSpan={6} className="empty-cell">
                          {selectedPath ? "该业务组暂无集群信息" : "请选择左侧业务组"}
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
            </section>

            {addAccountModal && (
              <div
                className="modal-overlay"
                onClick={() => setAddAccountModal(false)}
              >
                <div className="modal" onClick={(e) => e.stopPropagation()}>
                  <h3>添加业务组</h3>
                  <div className="form-group">
                    <label>业务组名称</label>
                    <input
                      value={accountForm.name}
                      onChange={(e) => setAccountForm({ ...accountForm, name: e.target.value })}
                      placeholder="例如：p_cluster-gpu"
                    />
                  </div>
                  <p className="form-hint">使用 “-” 分层，如 p_cluster-gpu 会显示为 p_cluster → gpu。</p>
                  <div className="modal-actions">
                    <button type="button" className="btn-secondary" onClick={() => setAddAccountModal(false)}>
                      取消
                    </button>
                    <button type="button" onClick={submitAccount}>
                      确认添加
                    </button>
                  </div>
                </div>
              </div>
            )}

            {editAccountModal && editingAccount && (
              <div className="modal-overlay" onClick={() => setEditAccountModal(false)}>
                <div className="modal" onClick={(e) => e.stopPropagation()}>
                  <h3>编辑业务组</h3>
                  <div className="form-group">
                    <label>业务组名称</label>
                    <input
                      value={accountForm.name}
                      onChange={(e) => setAccountForm({ ...accountForm, name: e.target.value })}
                      placeholder="例如：p_cluster-gpu"
                    />
                  </div>
                  <p className="form-hint">使用 “-” 分层，修改后左侧树结构会同步更新。</p>
                  <div className="modal-actions">
                    <button
                      type="button"
                      className="btn-secondary"
                      onClick={() => {
                        setEditAccountModal(false);
                        setEditingAccount(null);
                      }}
                    >
                      取消
                    </button>
                    <button type="button" onClick={submitEditAccount}>
                      保存
                    </button>
                  </div>
                </div>
              </div>
            )}

            {addClusterModal && (
              <div className="modal-overlay" onClick={() => setAddClusterModal(false)}>
                <div className="modal" onClick={(e) => e.stopPropagation()}>
                  <h3>添加 Kubernetes 集群</h3>
                  <div className="form-group">
                    <label>所属业务组</label>
                    <select value={clusterForm.account_id} onChange={(e) => setClusterForm({ ...clusterForm, account_id: e.target.value })}>
                      <option value="">请选择业务组</option>
                      {accounts.map((a) => (
                        <option key={a.id} value={a.id}>
                          {a.name}
                        </option>
                      ))}
                    </select>
                  </div>
                  <div className="form-group">
                    <label>集群名称</label>
                    <input value={clusterForm.name} onChange={(e) => setClusterForm({ ...clusterForm, name: e.target.value })} />
                  </div>
                  <div className="form-group">
                    <label>集群版本</label>
                    <input value={clusterForm.version} onChange={(e) => setClusterForm({ ...clusterForm, version: e.target.value })} placeholder="如 1.28.3" />
                  </div>
                  <div className="form-group">
                    <label>集群提供商</label>
                    <select value={clusterForm.provider} onChange={(e) => setClusterForm({ ...clusterForm, provider: e.target.value })}>
                      {CLUSTER_PROVIDERS.map((p) => (
                        <option key={p} value={p}>
                          {p}
                        </option>
                      ))}
                    </select>
                  </div>
                  <div className="form-group">
                    <label>原始 kubeconfig</label>
                    <textarea
                      value={clusterForm.uploaded_kubeconfig}
                      onChange={(e) => onKubeconfigChange(e.target.value)}
                      placeholder="粘贴完整 kubeconfig，系统将自动提取 APIServer 与 CA 证书"
                    />
                  </div>
                  <div className="form-group">
                    <label>APIServer（自动提取）</label>
                    <input className="readonly-input" value={clusterForm.api_server} readOnly placeholder="粘贴 kubeconfig 后自动填充" />
                  </div>
                  <div className="form-group">
                    <label>CA 证书（自动提取）</label>
                    <textarea className="readonly-input" value={clusterForm.ca_cert} readOnly placeholder="粘贴 kubeconfig 后自动填充" />
                  </div>
                  <p className="form-hint">集群 ID 将在确认添加成功后自动生成并显示。</p>
                  <div className="modal-actions">
                    <button type="button" className="btn-secondary" onClick={() => setAddClusterModal(false)}>
                      取消
                    </button>
                    <button type="button" onClick={submitCluster}>
                      确认添加
                    </button>
                  </div>
                </div>
              </div>
            )}

            {editClusterModal && editingCluster && (
              <div className="modal-overlay" onClick={() => setEditClusterModal(false)}>
                <div className="modal" onClick={(e) => e.stopPropagation()}>
                  <h3>编辑 Kubernetes 集群</h3>
                  <div className="form-group">
                    <label>所属业务组</label>
                    <select value={clusterForm.account_id} onChange={(e) => setClusterForm({ ...clusterForm, account_id: e.target.value })}>
                      <option value="">请选择业务组</option>
                      {accounts.map((a) => (
                        <option key={a.id} value={a.id}>
                          {a.name}
                        </option>
                      ))}
                    </select>
                  </div>
                  <div className="form-group">
                    <label>集群名称</label>
                    <input value={clusterForm.name} onChange={(e) => setClusterForm({ ...clusterForm, name: e.target.value })} />
                  </div>
                  <div className="form-group">
                    <label>集群ID</label>
                    <input className="readonly-input" value={editingCluster.cluster_id || ""} readOnly />
                  </div>
                  <div className="form-group">
                    <label>集群版本</label>
                    <input value={clusterForm.version} onChange={(e) => setClusterForm({ ...clusterForm, version: e.target.value })} placeholder="如 1.28.3" />
                  </div>
                  <div className="form-group">
                    <label>集群提供商</label>
                    <select value={clusterForm.provider} onChange={(e) => setClusterForm({ ...clusterForm, provider: e.target.value })}>
                      {CLUSTER_PROVIDERS.map((p) => (
                        <option key={p} value={p}>
                          {p}
                        </option>
                      ))}
                    </select>
                  </div>
                  <div className="form-group">
                    <label>APIServer</label>
                    <input className="readonly-input" value={clusterForm.api_server} readOnly />
                  </div>
                  <div className="form-group">
                    <label>更新 kubeconfig（可选）</label>
                    <textarea
                      value={clusterForm.uploaded_kubeconfig}
                      onChange={(e) => onKubeconfigChange(e.target.value)}
                      placeholder="如需更新 APIServer/CA，请粘贴新的 kubeconfig"
                    />
                  </div>
                  <div className="modal-actions">
                    <button
                      type="button"
                      className="btn-secondary"
                      onClick={() => {
                        setEditClusterModal(false);
                        setEditingCluster(null);
                      }}
                    >
                      取消
                    </button>
                    <button type="button" onClick={submitEditCluster}>
                      保存
                    </button>
                  </div>
                </div>
              </div>
            )}

            {createdClusterInfo && (
              <div className="modal-overlay" onClick={() => setCreatedClusterInfo(null)}>
                <div className="modal" onClick={(e) => e.stopPropagation()}>
                  <h3>集群添加成功</h3>
                  <div className="form-group">
                    <label>集群名称</label>
                    <input className="readonly-input" value={createdClusterInfo.name || ""} readOnly />
                  </div>
                  <div className="form-group">
                    <label>集群ID（自动生成）</label>
                    <input className="readonly-input" value={createdClusterInfo.cluster_id || ""} readOnly />
                  </div>
                  <div className="form-group">
                    <label>APIServer</label>
                    <input className="readonly-input" value={createdClusterInfo.api_server || ""} readOnly />
                  </div>
                  <div className="modal-actions">
                    <button type="button" onClick={() => setCreatedClusterInfo(null)}>
                      知道了
                    </button>
                  </div>
                </div>
              </div>
            )}
          </>
        )}

        {activeMenu === "users" && canManageUsers && (
          <section className="card">
            <div className="table-head">
              <h2>用户管理</h2>
              <div className="row">
                {canCreateUsers && (
                  <button
                    type="button"
                    onClick={() => {
                      setCreateUserForm({ username: "", display_name: "", phone: "", email: "", password: "", role: "watcher" });
                      setCreateUserModal(true);
                    }}
                  >
                    创建用户
                  </button>
                )}
                <button type="button" className="btn-secondary" onClick={() => loadUsers().catch((err) => showMessage(err.message, "error"))}>
                  刷新
                </button>
              </div>
            </div>
            <div className="toolbar">
              <input
                placeholder="搜索用户名/显示名/手机号/邮箱"
                value={userKeyword}
                onChange={(e) => {
                  setUsersPage(1);
                  setUserKeyword(e.target.value);
                }}
              />
            </div>
            <table>
              <thead>
                <tr>
                  <th>用户名</th>
                  <th>显示名</th>
                  <th>手机号</th>
                  <th>邮箱</th>
                  <th>角色</th>
                  <th>操作</th>
                </tr>
              </thead>
              <tbody>
                {users.map((u) => {
                  const isSelf = Number(u.id) === Number(user.id);
                  const offline = u.status === "disabled";
                  if (!canActorOperateTarget(role, u.role)) return null;
                  return (
                    <tr key={u.id} className={offline ? "row-disabled" : ""}>
                      <td>
                        {u.name}
                        {offline ? <span className="status-tag">已下线</span> : null}
                      </td>
                      <td>{u.display_name || u.name}</td>
                      <td>{u.phone}</td>
                      <td>{u.email}</td>
                      <td>{roleLabel(u.role)}</td>
                      <td>
                        {!isSelf && (
                          <>
                            <button type="button" className="link-btn" onClick={() => toggleUserOffline(u)}>
                              {offline ? "上线" : "下线"}
                            </button>
                            <span className="btn-spacing">|</span>
                          </>
                        )}
                        <button
                          type="button"
                          className="link-btn"
                          onClick={() =>
                            setEditUserModal({
                              id: u.id,
                              name: u.name,
                              display_name: u.display_name || u.name,
                              phone: u.phone || "",
                              email: u.email || "",
                              role: u.role,
                            })
                          }
                        >
                          修改
                        </button>
                        <span className="btn-spacing">|</span>
                        <button type="button" className="link-btn" onClick={() => handleResetPassword(u)}>
                          重置密码
                        </button>
                        {!isSelf && (
                          <>
                            <span className="btn-spacing">|</span>
                            <button
                              type="button"
                              className="link-btn danger-link"
                              onClick={() => deleteUser(u.id, u.display_name || u.name)}
                            >
                              删除
                            </button>
                          </>
                        )}
                      </td>
                    </tr>
                  );
                })}
                {users.length === 0 && (
                  <tr>
                    <td colSpan={6} className="empty-cell">
                      暂无用户
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
            <div className="pager pager-bottom">
              <button type="button" disabled={usersPage <= 1} onClick={() => setUsersPage((p) => Math.max(1, p - 1))}>
                上一页
              </button>
              <span>
                第 {usersPage} 页 / 共 {Math.max(1, Math.ceil(usersTotal / usersSize))} 页
              </span>
              <button
                type="button"
                disabled={usersPage >= Math.max(1, Math.ceil(usersTotal / usersSize))}
                onClick={() => setUsersPage((p) => p + 1)}
              >
                下一页
              </button>
            </div>

            {createUserModal && (
              <div className="modal-overlay" onClick={() => setCreateUserModal(false)}>
                <div className="modal" onClick={(e) => e.stopPropagation()}>
                  <h3>创建用户</h3>
                  <form onSubmit={submitCreateUser} className="modal-form">
                    <div className="form-group">
                      <label>用户名</label>
                      <input
                        required
                        value={createUserForm.username}
                        onChange={(e) => setCreateUserForm({ ...createUserForm, username: e.target.value })}
                        placeholder="登录用户名"
                      />
                    </div>
                    <div className="form-group">
                      <label>显示名</label>
                      <input
                        value={createUserForm.display_name}
                        onChange={(e) => setCreateUserForm({ ...createUserForm, display_name: e.target.value })}
                        placeholder="显示名称"
                      />
                    </div>
                    <div className="form-group">
                      <label>手机号</label>
                      <input
                        required
                        value={createUserForm.phone}
                        onChange={(e) => setCreateUserForm({ ...createUserForm, phone: e.target.value })}
                      />
                    </div>
                    <div className="form-group">
                      <label>邮箱</label>
                      <input
                        required
                        type="email"
                        value={createUserForm.email}
                        onChange={(e) => setCreateUserForm({ ...createUserForm, email: e.target.value })}
                      />
                    </div>
                    <div className="form-group">
                      <label>初始密码</label>
                      <input
                        required
                        type="password"
                        value={createUserForm.password}
                        onChange={(e) => setCreateUserForm({ ...createUserForm, password: e.target.value })}
                        placeholder="至少 6 位"
                      />
                    </div>
                    <div className="form-group">
                      <label>角色</label>
                      <select value={createUserForm.role} onChange={(e) => setCreateUserForm({ ...createUserForm, role: e.target.value })}>
                        {createRoleOptions.map((opt) => (
                          <option key={opt.value} value={opt.value}>
                            {opt.label}
                          </option>
                        ))}
                      </select>
                      <RolePermissionHelp selected={createUserForm.role} options={createRoleOptions} />
                    </div>
                    <div className="modal-actions">
                      <button type="button" className="btn-secondary" onClick={() => setCreateUserModal(false)}>
                        取消
                      </button>
                      <button type="submit">确认创建</button>
                    </div>
                  </form>
                </div>
              </div>
            )}

            {editUserModal && (
              <div className="modal-overlay" onClick={() => setEditUserModal(null)}>
                <div className="modal" onClick={(e) => e.stopPropagation()}>
                  <h3>修改用户 - {editUserModal.name}</h3>
                  <form onSubmit={submitEditUser} className="modal-form">
                    <div className="form-group">
                      <label>用户名</label>
                      <input className="readonly-input" value={editUserModal.name} readOnly />
                    </div>
                    <div className="form-group">
                      <label>显示名</label>
                      <input
                        required
                        value={editUserModal.display_name}
                        onChange={(e) => setEditUserModal({ ...editUserModal, display_name: e.target.value })}
                      />
                    </div>
                    <div className="form-group">
                      <label>手机号</label>
                      <input
                        required
                        value={editUserModal.phone}
                        onChange={(e) => setEditUserModal({ ...editUserModal, phone: e.target.value })}
                      />
                    </div>
                    <div className="form-group">
                      <label>邮箱</label>
                      <input
                        required
                        type="email"
                        value={editUserModal.email}
                        onChange={(e) => setEditUserModal({ ...editUserModal, email: e.target.value })}
                      />
                    </div>
                    <div className="form-group">
                      <label>角色</label>
                      <select value={editUserModal.role} onChange={(e) => setEditUserModal({ ...editUserModal, role: e.target.value })}>
                        {editableRoleOptions.map((opt) => (
                          <option key={opt.value} value={opt.value}>
                            {opt.label}
                          </option>
                        ))}
                      </select>
                      <RolePermissionHelp selected={editUserModal.role} options={editableRoleOptions} />
                    </div>
                    <p className="form-hint">修改用户信息时不可更改密码，请使用「重置密码」。</p>
                    <div className="modal-actions">
                      <button type="button" className="btn-secondary" onClick={() => setEditUserModal(null)}>
                        取消
                      </button>
                      <button type="submit">保存</button>
                    </div>
                  </form>
                </div>
              </div>
            )}

            {resetPasswordResult && (
              <div className="modal-overlay" onClick={() => setResetPasswordResult(null)}>
                <div className="modal" onClick={(e) => e.stopPropagation()}>
                  <h3>密码重置成功</h3>
                  <div className="modal-form">
                    <div className="form-group">
                      <label>用户名</label>
                      <input className="readonly-input" value={resetPasswordResult.username} readOnly />
                    </div>
                    <div className="form-group">
                      <label>显示名</label>
                      <input className="readonly-input" value={resetPasswordResult.display_name} readOnly />
                    </div>
                    <div className="form-group">
                      <label>新密码（仅显示一次，请妥善保存）</label>
                      <div className="password-input-row auth-password-row">
                        <input className="readonly-input" value={resetPasswordResult.password} readOnly />
                        <button
                          type="button"
                          className="password-toggle-btn"
                          title="复制密码"
                          onClick={async () => {
                            try {
                              await navigator.clipboard.writeText(resetPasswordResult.password);
                              showMessage("密码已复制", "success");
                            } catch {
                              showMessage("复制失败，请手动复制", "error");
                            }
                          }}
                        >
                          复制
                        </button>
                      </div>
                      <span className="hint-text">{PASSWORD_RULE_HINT}</span>
                    </div>
                    <div className="modal-actions">
                      <button type="button" onClick={() => setResetPasswordResult(null)}>
                        我已保存
                      </button>
                    </div>
                  </div>
                </div>
              </div>
            )}
          </section>
        )}

        {profileModal && (
          <div className="modal-overlay" onClick={() => setProfileModal(null)}>
            <div className="modal" onClick={(e) => e.stopPropagation()}>
              <h3>个人设置</h3>
              <form onSubmit={submitProfile} className="modal-form">
                <div className="form-group">
                  <label>用户名</label>
                  <input className="readonly-input" value={profileModal.name} readOnly />
                </div>
                <div className="form-group">
                  <label>显示名</label>
                  <input
                    required
                    value={profileModal.display_name}
                    onChange={(e) => setProfileModal({ ...profileModal, display_name: e.target.value })}
                  />
                </div>
                <div className="form-group">
                  <label>手机号</label>
                  <input
                    required
                    value={profileModal.phone}
                    onChange={(e) => setProfileModal({ ...profileModal, phone: e.target.value })}
                  />
                </div>
                <div className="form-group">
                  <label>邮箱</label>
                  <input
                    required
                    type="email"
                    value={profileModal.email}
                    onChange={(e) => setProfileModal({ ...profileModal, email: e.target.value })}
                  />
                </div>
                <div className="form-group">
                  <label>修改密码</label>
                  <input
                    type="password"
                    value={profileModal.new_password || ""}
                    onChange={(e) => onProfilePasswordChange(e.target.value)}
                    placeholder="不修改请留空"
                    maxLength={24}
                    className={profileModal.new_password && !isPasswordValid(profileModal.new_password) ? "invalid" : ""}
                  />
                  <span
                    className={`hint-text ${
                      profileModal.password_message
                        ? isPasswordValid(profileModal.new_password || "")
                          ? "valid"
                          : "invalid"
                        : ""
                    }`}
                  >
                    {profileModal.password_message || PASSWORD_RULE_HINT}
                  </span>
                </div>
                <div className="form-group">
                  <label>确认密码</label>
                  <input
                    type="password"
                    value={profileModal.confirm_password || ""}
                    onChange={(e) => onProfileConfirmPasswordChange(e.target.value)}
                    placeholder="不修改请留空"
                    maxLength={24}
                    className={
                      profileModal.confirm_password && profileModal.confirm_password !== profileModal.new_password
                        ? "invalid"
                        : ""
                    }
                  />
                  {profileModal.confirm_message && (
                    <span
                      className={`hint-text ${
                        profileModal.confirm_password === profileModal.new_password ? "valid" : "invalid"
                      }`}
                    >
                      {profileModal.confirm_message}
                    </span>
                  )}
                </div>
                <div className="modal-actions">
                  <button type="button" className="btn-secondary" onClick={() => setProfileModal(null)}>
                    取消
                  </button>
                  <button type="submit">保存</button>
                </div>
              </form>
            </div>
          </div>
        )}

        {activeMenu === "audit" && canViewAudit && (
          <section className="card">
            <div className="table-head">
              <h2>审计日志</h2>
              <button
                type="button"
                className="btn-secondary"
                onClick={() => {
                  setAuditPage(1);
                  setAuditFilter({ keyword: "", start_at: "", end_at: "" });
                }}
              >
                重置筛选
              </button>
            </div>
            <div className="toolbar audit-toolbar">
              <input
                className="audit-search"
                placeholder="搜索：用户名、显示名、动作、结果、IP、详情"
                value={auditFilter.keyword}
                onChange={(e) => {
                  setAuditPage(1);
                  setAuditFilter({ ...auditFilter, keyword: e.target.value });
                }}
              />
              <label className="audit-time-label">
                开始时间
                <input
                  type="datetime-local"
                  value={auditFilter.start_at}
                  onChange={(e) => {
                    setAuditPage(1);
                    setAuditFilter({ ...auditFilter, start_at: e.target.value });
                  }}
                />
              </label>
              <label className="audit-time-label">
                结束时间
                <input
                  type="datetime-local"
                  value={auditFilter.end_at}
                  onChange={(e) => {
                    setAuditPage(1);
                    setAuditFilter({ ...auditFilter, end_at: e.target.value });
                  }}
                />
              </label>
            </div>
            <table>
              <thead>
                <tr>
                  <th>时间</th>
                  <th>用户</th>
                  <th>显示用户</th>
                  <th>动作</th>
                  <th>结果</th>
                  <th>IP</th>
                  <th>详情</th>
                </tr>
              </thead>
              <tbody>
                {audits.map((a) => (
                  <tr key={a.id}>
                    <td>{new Date(a.created_at).toLocaleString()}</td>
                    <td>{a.username}</td>
                    <td>{a.display_name || a.username || "-"}</td>
                    <td>{actionLabel(a.action)}</td>
                    <td>{resultLabel(a.result)}</td>
                    <td>{a.ip}</td>
                    <td>{a.detail}</td>
                  </tr>
                ))}
                {audits.length === 0 && (
                  <tr>
                    <td colSpan={7} className="empty-cell">
                      暂无审计日志
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
            <div className="pager pager-bottom audit-pager">
              <button type="button" disabled={auditPage <= 1} onClick={() => setAuditPage((p) => Math.max(1, p - 1))}>
                上一页
              </button>
              <span>
                第 {auditPage} 页 / 共 {Math.max(1, Math.ceil(auditTotal / auditSize))} 页（共 {auditTotal} 条）
              </span>
              <button
                type="button"
                disabled={auditPage >= Math.max(1, Math.ceil(auditTotal / auditSize))}
                onClick={() => setAuditPage((p) => p + 1)}
              >
                下一页
              </button>
            </div>
          </section>
        )}

        {activeMenu === "query" && (
          <section className="card">
            <h2>查询数据</h2>
            <div className="toolbar">
              <div className="grid query-filters">
                <select
                  value={queryFilter.account_id}
                  onChange={(e) => {
                    setRecordsPage(1);
                    setQueryFilter({ account_id: e.target.value, cluster_id: "" });
                  }}
                >
                  <option value="">全部业务组</option>
                  {accounts.map((a) => (
                    <option key={a.id} value={a.id}>
                      {a.name}
                    </option>
                  ))}
                </select>
                <select
                  value={queryFilter.cluster_id}
                  onChange={(e) => {
                    setRecordsPage(1);
                    setQueryFilter({ ...queryFilter, cluster_id: e.target.value });
                  }}
                >
                  <option value="">全部集群</option>
                  {filteredClustersForQuery.map((c) => (
                    <option key={c.id} value={c.id}>
                      {c.name}
                    </option>
                  ))}
                </select>
              </div>
            </div>
            <table>
              <thead>
                <tr>
                  <th>ID</th>
                  <th>名称</th>
                  <th>业务组名称</th>
                  <th>集群名称</th>
                  <th>角色类型</th>
                  <th>SA</th>
                  <th>SA命名空间</th>
                  <th>Role命名空间</th>
                  <th>资源权限</th>
                  <th>剩余天数</th>
                  <th>创建人</th>
                  <th>时间</th>
                  <th>下载</th>
                  <th>操作</th>
                </tr>
              </thead>
              <tbody>
                {records.map((r) => (
                  <tr key={r.id}>
                    <td>{r.id}</td>
                    <td>{r.name}</td>
                    <td>{r.account_name || "-"}</td>
                    <td>{r.cluster_name || "-"}</td>
                    <td>{r.role_kind || "-"}</td>
                    <td>{r.service_account_name}</td>
                    <td>{r.sa_namespace || r.namespace}</td>
                    <td>{r.role_kind === "ClusterRole" ? "-" : r.role_namespace || "-"}</td>
                    <td>
                      <button
                        type="button"
                        className="link-btn permissions-link"
                        title="查看 RBAC YAML"
                        onClick={() => openRBACYamlModal(r.id, r.name)}
                      >
                        <pre className="permissions-cell">{r.permissions_text || formatRulesDisplay(r.rules)}</pre>
                      </button>
                    </td>
                    <td>{formatRemainingDays(r.remaining_days, r.token_expires_at)}</td>
                    <td>{r.created_by}</td>
                    <td>{new Date(r.created_at).toLocaleString()}</td>
                    <td>
                      {canDownloadKubeconfig ? (
                        <button type="button" className="link-btn" onClick={() => downloadKubeconfigFile(r.id, r.name)}>
                          下载 kubeconfig
                        </button>
                      ) : (
                        "-"
                      )}
                    </td>
                    <td>
                      {canDeleteKubeconfig ? (
                        <button
                          type="button"
                          className="link-btn danger-link"
                          onClick={() => deleteKubeconfigRecord(r.id, r.name)}
                        >
                          删除
                        </button>
                      ) : (
                        "-"
                      )}
                    </td>
                  </tr>
                ))}
                {records.length === 0 && (
                  <tr>
                    <td colSpan={14} className="empty-cell">
                      暂无数据
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
            <div className="pager pager-bottom">
              <label className="page-size-label">
                每页
                <select
                  value={recordsSize}
                  onChange={(e) => {
                    setRecordsPage(1);
                    setRecordsSize(Number(e.target.value));
                  }}
                >
                  {[10, 20, 50, 100].map((n) => (
                    <option key={n} value={n}>
                      {n}
                    </option>
                  ))}
                </select>
                条
              </label>
              <button type="button" disabled={recordsPage <= 1} onClick={() => setRecordsPage((p) => Math.max(1, p - 1))}>
                上一页
              </button>
              <span>
                第 {recordsPage} 页 / 共 {Math.max(1, Math.ceil(recordsTotal / recordsSize))} 页（共 {recordsTotal} 条）
              </span>
              <button
                type="button"
                disabled={recordsPage >= Math.max(1, Math.ceil(recordsTotal / recordsSize))}
                onClick={() => setRecordsPage((p) => p + 1)}
              >
                下一页
              </button>
            </div>

            {rbacModal && (
              <div className="modal-overlay" onClick={() => setRbacModal(null)}>
                <div className="modal modal-wide" onClick={(e) => e.stopPropagation()}>
                  <h3>RBAC YAML - {rbacModal.name || rbacModal.id}</h3>
                  {rbacModal.loading ? (
                    <p className="form-hint">加载中…</p>
                  ) : (
                    <textarea className="yaml-preview" value={rbacModal.yaml} readOnly rows={18} />
                  )}
                  <div className="modal-actions">
                    <button type="button" className="btn-secondary" onClick={() => setRbacModal(null)}>
                      关闭
                    </button>
                    <button type="button" disabled={rbacModal.loading || !rbacModal.yaml} onClick={copyRBACYaml}>
                      一键复制
                    </button>
                  </div>
                </div>
              </div>
            )}
          </section>
        )}

        {activeMenu === "create" && canCreateKubeconfig && (
          <section className="card">
            <h2>创建 kubeconfig</h2>
            <form onSubmit={submitKubeconfig} className="grid">
              <input placeholder="配置名称" value={kubeForm.name} onChange={(e) => setKubeForm({ ...kubeForm, name: e.target.value })} />
              <select
                value={kubeForm.account_id}
                onChange={(e) => {
                  setKubeForm({ ...kubeForm, account_id: e.target.value, cluster_id: "", sa_namespace: "", role_namespace: "" });
                  setClusterNamespaces([]);
                }}
              >
                <option value="">选择业务组</option>
                {accounts.map((a) => (
                  <option key={a.id} value={a.id}>
                    {a.name}
                  </option>
                ))}
              </select>
              <select
                value={kubeForm.cluster_id}
                onChange={(e) => {
                  const clusterID = e.target.value;
                  setKubeForm({ ...kubeForm, cluster_id: clusterID, sa_namespace: "", role_namespace: "" });
                  loadClusterNamespaces(clusterID);
                }}
              >
                <option value="">选择集群</option>
                {filteredClustersForCreate.map((c) => (
                  <option key={c.id} value={c.id}>
                    {c.name} ({c.cluster_id})
                  </option>
                ))}
              </select>
              <input placeholder="ServiceAccount 名称" value={kubeForm.service_account_name} onChange={(e) => setKubeForm({ ...kubeForm, service_account_name: e.target.value })} />

              <div className="form-group namespace-field">
                <label>ServiceAccount 命名空间</label>
                <select
                  value={kubeForm.sa_namespace}
                  disabled={!kubeForm.cluster_id || namespacesLoading}
                  onChange={(e) => setKubeForm({ ...kubeForm, sa_namespace: e.target.value })}
                >
                  <option value="">{namespacesLoading ? "加载命名空间中..." : "请选择命名空间"}</option>
                  {clusterNamespaces.map((ns) => (
                    <option key={ns} value={ns}>
                      {ns}
                    </option>
                  ))}
                </select>
                <p className="form-hint">与角色类型无关，从所选集群实时获取。</p>
              </div>

              <div className="form-group namespace-field">
                <label>证书有效期</label>
                <select
                  value={kubeForm.token_ttl_mode}
                  onChange={(e) =>
                    setKubeForm({
                      ...kubeForm,
                      token_ttl_mode: e.target.value,
                      token_ttl_days: e.target.value === "temporary" ? "3" : kubeForm.token_ttl_days || "3",
                    })
                  }
                >
                  <option value="temporary">临时有效期（默认 3 天）</option>
                  <option value="custom">指定有效期（按天数）</option>
                  <option value="long">长期有效（与集群 CA 证书期限一致）</option>
                </select>
                {kubeForm.token_ttl_mode === "custom" && (
                  <div className="ttl-days-row">
                    <input
                      type="number"
                      min={1}
                      max={3650}
                      step={1}
                      value={kubeForm.token_ttl_days}
                      onChange={(e) => setKubeForm({ ...kubeForm, token_ttl_days: e.target.value })}
                      placeholder="请输入天数"
                    />
                    <span>天</span>
                  </div>
                )}
                <p className="form-hint">
                  {kubeForm.token_ttl_mode === "temporary" && "将签发 3 天有效的 ServiceAccount Token。"}
                  {kubeForm.token_ttl_mode === "custom" && "请输入 1–3650 的正整数天数，且不得超过集群 CA 剩余有效期。"}
                  {kubeForm.token_ttl_mode === "long" && "Token 有效期对齐所选集群 CA 证书过期时间。"}
                </p>
              </div>

              <div className="check-wrap role-kind-wrap">
                <strong>角色类型</strong>
                <label>
                  <input
                    type="radio"
                    name="role_kind"
                    checked={kubeForm.role_kind === "Role"}
                    onChange={() => changeRoleKind("Role")}
                  />
                  角色（Role）
                </label>
                <label>
                  <input
                    type="radio"
                    name="role_kind"
                    checked={kubeForm.role_kind === "ClusterRole"}
                    onChange={() => changeRoleKind("ClusterRole")}
                  />
                  集群角色（ClusterRole）
                </label>
              </div>

              {kubeForm.role_kind === "Role" && (
                <div className="form-group namespace-field">
                  <label>Role/RoleBinding 命名空间</label>
                  <select
                    value={kubeForm.role_namespace}
                    disabled={!kubeForm.cluster_id || namespacesLoading}
                    onChange={(e) => setKubeForm({ ...kubeForm, role_namespace: e.target.value })}
                  >
                    <option value="">{namespacesLoading ? "加载命名空间中..." : "请选择命名空间"}</option>
                    {clusterNamespaces.map((ns) => (
                      <option key={`role-${ns}`} value={ns}>
                        {ns}
                      </option>
                    ))}
                  </select>
                  <p className="form-hint">Role 与 RoleBinding 将创建在该命名空间。</p>
                </div>
              )}

              <div className="permission-panel">
                <div className="permission-head">
                  <strong>资源权限</strong>
                  <span className="permission-scope-tip">
                    {kubeForm.role_kind === "Role" ? "仅命名空间级资源" : "集群级资源（如 nodes、namespaces）"}
                  </span>
                </div>
                <div className="resource-preset-list">
                  {activeResourceCatalog.map((item) => (
                    <label key={item.resource} className="resource-preset-item">
                      <input type="checkbox" checked={hasRule(item.resource)} onChange={() => togglePresetResource(item)} />
                      {item.resource}
                      {item.api_group ? <span className="api-group-tag">{item.api_group}</span> : null}
                    </label>
                  ))}
                </div>

                <div className="custom-resource-row">
                  <input
                    placeholder={
                      kubeForm.role_kind === "Role"
                        ? "自定义命名空间资源，如 myresources 或 pods/log"
                        : "自定义集群资源，如 nodes/status"
                    }
                    value={customResourceInput.resource}
                    onChange={(e) => setCustomResourceInput({ ...customResourceInput, resource: e.target.value })}
                  />
                  <input
                    placeholder="API Group（可选，如 apps）"
                    value={customResourceInput.api_group}
                    onChange={(e) => setCustomResourceInput({ ...customResourceInput, api_group: e.target.value })}
                  />
                  <button type="button" className="add-resource-btn" onClick={addCustomResource} title="新增资源权限">
                    +
                  </button>
                </div>

                <div className="rule-list">
                  {kubeForm.rules.map((rule) => (
                    <div key={rule.resource} className="rule-card">
                      <div className="rule-card-head">
                        <div>
                          <strong>{rule.resource}</strong>
                          <span className="api-group-tag">{rule.api_group || 'core'}</span>
                        </div>
                        <button type="button" className="link-btn error-text" onClick={() => removeRule(rule.resource)}>
                          移除
                        </button>
                      </div>
                      <div className="verb-multi">
                        <span className="verb-multi-label">操作权限</span>
                        {VERB_OPTIONS.map((verb) => (
                          <label key={`${rule.resource}-${verb}`}>
                            <input
                              type="checkbox"
                              checked={rule.verbs.includes(verb)}
                              onChange={() => toggleRuleVerb(rule.resource, verb)}
                            />
                            {verb}
                          </label>
                        ))}
                      </div>
                    </div>
                  ))}
                  {kubeForm.rules.length === 0 && <div className="empty-cell">请选择或新增资源权限</div>}
                </div>
              </div>

              <button type="submit" disabled={kubeCreating}>
                {kubeCreating ? "正在创建集群资源…" : "创建并落库"}
              </button>
            </form>

            {createdKubeconfigInfo && (
              <div className="modal-overlay" onClick={() => setCreatedKubeconfigInfo(null)}>
                <div className="modal" onClick={(e) => e.stopPropagation()}>
                  <h3>kubeconfig 创建完成</h3>
                  <div className="form-group">
                    <label>名称</label>
                    <input className="readonly-input" value={createdKubeconfigInfo.name || ""} readOnly />
                  </div>
                  <div className="form-group">
                    <label>ID</label>
                    <input className="readonly-input" value={createdKubeconfigInfo.id || ""} readOnly />
                  </div>
                  <div className="form-group">
                    <label>下载地址</label>
                    <input className="readonly-input" value={createdKubeconfigInfo.download_url || ""} readOnly />
                  </div>
                  {createdKubeconfigInfo.token_expires_at && (
                    <div className="form-group">
                      <label>Token 过期时间</label>
                      <input
                        className="readonly-input"
                        value={formatTokenExpiresAt(createdKubeconfigInfo.token_expires_at)}
                        readOnly
                      />
                    </div>
                  )}
                  <p className="form-hint">已在目标集群创建 ServiceAccount / RBAC，并生成可直接使用的 kubeconfig。</p>
                  <div className="modal-actions">
                    <button type="button" className="btn-secondary" onClick={() => setCreatedKubeconfigInfo(null)}>
                      关闭
                    </button>
                    <button
                      type="button"
                      onClick={() => downloadKubeconfigFile(createdKubeconfigInfo.id, createdKubeconfigInfo.name)}
                    >
                      下载 kubeconfig
                    </button>
                  </div>
                </div>
              </div>
            )}
          </section>
        )}
      </main>
    </div>
  );
}

