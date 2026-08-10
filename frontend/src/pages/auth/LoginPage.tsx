import { t } from "@/app/i18n";
import { Alert, Button, Card, Form, Input, Typography } from "antd";
import {
  LockKeyhole,
  LogIn,
  RefreshCw,
  ShieldCheck,
  UserPlus,
  UserRound
} from "lucide-react";
import { useCallback, useEffect, useState } from "react";
import { Navigate, useLocation, useNavigate } from "react-router";

import {
  createCaptcha,
  type CaptchaChallenge,
  type LoginPayload,
  type SetupAdminPayload
} from "@/api/auth";
import { ApiError, getApiErrorCode } from "@/api/client";
import { useAuth } from "@/app/auth";
import { platformLogoSrc, usePlatformSettings } from "@/app/platformSettings";

type LoginLocationState = {
  from?: {
    pathname?: string;
    search?: string;
  };
};

export default function LoginPage() {
  const navigate = useNavigate();
  const location = useLocation();
  const { isAuthenticated, isLoading, loginAsync, needsSetup, setupAdminAsync } =
    useAuth();
  const { settings } = usePlatformSettings();
  const [form] = Form.useForm<LoginPayload>();
  const [setupForm] = Form.useForm<
    SetupAdminPayload & { confirmPassword: string }
  >();
  const [submitting, setSubmitting] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [captcha, setCaptcha] = useState<CaptchaChallenge | null>(null);
  const [captchaLoading, setCaptchaLoading] = useState(false);
  const [blockSeconds, setBlockSeconds] = useState(0);
  const [permanentlyBlocked, setPermanentlyBlocked] = useState(false);
  const fromState = location.state as LoginLocationState | null;
  const targetPath =
    `${fromState?.from?.pathname ?? "/risk-queue"}${fromState?.from?.search ?? ""}`;

  const refreshCaptcha = useCallback(() => {
    setCaptchaLoading(true);
    setCaptcha(null);
    if (needsSetup) {
      setupForm.setFieldValue("captcha_answer", "");
    } else {
      form.setFieldValue("captcha_answer", "");
    }
    void createCaptcha()
      .then(setCaptcha)
      .catch((error: unknown) => {
        setErrorMessage(
          error instanceof Error ? error.message : t("验证码加载失败")
        );
      })
      .finally(() => setCaptchaLoading(false));
  }, [form, needsSetup, setupForm]);

  useEffect(() => {
    refreshCaptcha();
  }, [refreshCaptcha]);

  useEffect(() => {
    if (!captcha) {
      return;
    }
    const timeout = window.setTimeout(
      refreshCaptcha,
      Math.max(10, captcha.expires_in - 5) * 1000
    );
    return () => window.clearTimeout(timeout);
  }, [captcha, refreshCaptcha]);

  useEffect(() => {
    if (blockSeconds <= 0) {
      return;
    }
    const interval = window.setInterval(() => {
      setBlockSeconds((current) => {
        if (current <= 1) {
          window.clearInterval(interval);
          refreshCaptcha();
          return 0;
        }
        return current - 1;
      });
    }, 1000);
    return () => window.clearInterval(interval);
  }, [blockSeconds > 0, refreshCaptcha]);

  const handleAuthFailure = (error: unknown) => {
    const code = getApiErrorCode(error);
    if (code === "IP_BLOCKED_PERMANENT") {
      setPermanentlyBlocked(true);
      setErrorMessage(t("当前 IP 已被永久封禁，请联系管理员解封"));
      return;
    }
    if (code === "IP_BLOCKED_TEMPORARY") {
      const retryAfter = getRetryAfterSeconds(error);
      setBlockSeconds(retryAfter);
      setErrorMessage(null);
      return;
    }
    if (code === "LOGIN_RATE_LIMITED") {
      const retryAfter = getRetryAfterSeconds(error);
      setBlockSeconds(retryAfter);
      setErrorMessage(null);
      return;
    }
    setErrorMessage(error instanceof Error ? error.message : t("登录失败"));
    refreshCaptcha();
  };

  if (!isLoading && isAuthenticated) {
    return <Navigate to={targetPath} replace />;
  }

  return (
    <main className="login-shell">
      <section className="login-panel" aria-label={t("{{v0}} 登录", { v0: settings.platform_name })}>
        <div className="login-brand">
          <span className="login-brand-mark">
            <img
              src={platformLogoSrc(settings)}
              alt={`${settings.platform_name} LOGO`}
              className="login-brand-logo"
            />
          </span>
          <div>
            <Typography.Title level={1}>{settings.platform_name}</Typography.Title>
            <Typography.Text>{settings.platform_subtitle}</Typography.Text>
          </div>
        </div>

        <Card className="login-card">
          {needsSetup ? (
            <>
              <Typography.Title level={2}>{t("初始化管理员")}</Typography.Title>
              <Form
                form={setupForm}
                layout="vertical"
                requiredMark={false}
                onFinish={(values) => {
                  setSubmitting(true);
                  setErrorMessage(null);
                  void setupAdminAsync({
                    username: values.username,
                    password: values.password,
                    display_name: values.display_name || null,
                    captcha_id: captcha?.captcha_id ?? "",
                    captcha_answer: values.captcha_answer
                  })
                    .then(() => {
                      navigate(targetPath, { replace: true });
                    })
                    .catch(handleAuthFailure)
                    .finally(() => {
                      setSubmitting(false);
                    });
                }}
              >
                {errorMessage ? (
                  <Alert
                    className="login-error"
                    type="error"
                    showIcon
                    title={errorMessage}
                  />
                ) : null}

                <Form.Item
                  name="username"
                  label={t("用户名")}
                  initialValue="admin"
                  rules={[
                    { required: true, message: t("请输入用户名") },
                    { whitespace: true, message: t("用户名不能只包含空格") }
                  ]}
                >
                  <Input
                    autoComplete="username"
                    prefix={<UserRound size={17} />}
                    placeholder="admin"
                  />
                </Form.Item>

                <Form.Item name="display_name" label={t("显示名称")}>
                  <Input
                    autoComplete="name"
                    prefix={<ShieldCheck size={17} />}
                    placeholder={t("系统管理员")}
                  />
                </Form.Item>

                <Form.Item
                  name="password"
                  label={t("密码")}
                  rules={[
                    { required: true, message: t("请输入密码") },
                    { min: 8, message: t("密码至少 8 位") }
                  ]}
                >
                  <Input.Password
                    autoComplete="new-password"
                    prefix={<LockKeyhole size={17} />}
                    placeholder={t("设置管理员密码")}
                  />
                </Form.Item>

                <Form.Item
                  name="confirmPassword"
                  label={t("确认密码")}
                  dependencies={["password"]}
                  rules={[
                    { required: true, message: t("请再次输入密码") },
                    ({ getFieldValue }) => ({
                      validator(_, value) {
                        if (!value || getFieldValue("password") === value) {
                          return Promise.resolve();
                        }
                        return Promise.reject(new Error(t("两次输入的密码不一致")));
                      }
                    })
                  ]}
                >
                  <Input.Password
                    autoComplete="new-password"
                    prefix={<LockKeyhole size={17} />}
                    placeholder={t("再次输入管理员密码")}
                  />
                </Form.Item>

                <CaptchaField
                  captcha={captcha}
                  loading={captchaLoading}
                  onRefresh={refreshCaptcha}
                />

                <Form.Item shouldUpdate>
                  {() => (
                    <Button
                      block
                      type="primary"
                      htmlType="submit"
                      icon={<UserPlus size={17} />}
                      loading={submitting}
                      disabled={
                        !captcha || blockSeconds > 0 || permanentlyBlocked
                      }
                    >
                      {t("创建管理员并进入系统")}</Button>
                  )}
                </Form.Item>
              </Form>

              <Alert
                type="info"
                showIcon
                title={t("仅在系统不存在活跃超级管理员时开放初始化")}
              />
            </>
          ) : (
            <>
              <Typography.Title level={2}>{t("管理员登录")}</Typography.Title>
              <Form
                form={form}
                layout="vertical"
                requiredMark={false}
                onFinish={(values) => {
                  setSubmitting(true);
                  setErrorMessage(null);
                  void loginAsync({
                    ...values,
                    captcha_id: captcha?.captcha_id ?? ""
                  })
                    .then(() => {
                      navigate(targetPath, { replace: true });
                    })
                    .catch(handleAuthFailure)
                    .finally(() => {
                      setSubmitting(false);
                    });
                }}
              >
                {errorMessage ? (
                  <Alert
                    className="login-error"
                    type="error"
                    showIcon
                    title={errorMessage}
                  />
                ) : null}

                <Form.Item
                  name="username"
                  label={t("用户名")}
                  rules={[{ required: true, message: t("请输入用户名") }]}
                >
                  <Input
                    autoComplete="username"
                    prefix={<UserRound size={17} />}
                    placeholder="admin"
                  />
                </Form.Item>

                {blockSeconds > 0 ? (
                  <Alert
                    className="login-error"
                    type="warning"
                    showIcon
                    title={t("还需等待 {{v0}} 秒", { v0: blockSeconds })}
                  />
                ) : null}

                <Form.Item
                  name="password"
                  label={t("密码")}
                  rules={[{ required: true, message: t("请输入密码") }]}
                >
                  <Input.Password
                    autoComplete="current-password"
                    prefix={<LockKeyhole size={17} />}
                    placeholder={t("输入管理员密码")}
                  />
                </Form.Item>

                <CaptchaField
                  captcha={captcha}
                  loading={captchaLoading}
                  onRefresh={refreshCaptcha}
                />

                <Form.Item shouldUpdate>
                  {() => (
                    <Button
                      block
                      type="primary"
                      htmlType="submit"
                      icon={<LogIn size={17} />}
                      loading={submitting}
                      disabled={
                        !captcha || blockSeconds > 0 || permanentlyBlocked
                      }
                    >
                      {t("登录")}</Button>
                  )}
                </Form.Item>
              </Form>
            </>
          )}
        </Card>
      </section>
    </main>
  );
}

function CaptchaField({
  captcha,
  loading,
  onRefresh
}: {
  captcha: CaptchaChallenge | null;
  loading: boolean;
  onRefresh: () => void;
}) {
  return (
    <Form.Item label={t("验证码")} required>
      <div className="login-captcha-row">
        <Form.Item
          name="captcha_answer"
          noStyle
          rules={[{ required: true, message: t("请输入验证码") }]}
        >
          <Input
            autoComplete="off"
            maxLength={8}
            placeholder={t("输入图中字符")}
          />
        </Form.Item>
        <button
          className="login-captcha-image"
          type="button"
          onClick={onRefresh}
          aria-label={t("刷新验证码")}
          disabled={!captcha || loading}
        >
          {captcha ? (
            <img
              src={`data:image/png;base64,${captcha.image_base64}`}
              alt={t("验证码图片，点击可刷新")}
            />
          ) : (
            <span>{t("加载中")}</span>
          )}
        </button>
        <Button
          type="text"
          icon={<RefreshCw size={17} />}
          onClick={onRefresh}
          loading={loading}
          aria-label={t("刷新验证码")}
        />
      </div>
    </Form.Item>
  );
}

function getRetryAfterSeconds(error: unknown) {
  if (!(error instanceof ApiError)) {
    return 60;
  }
  const payload = error.detail;
  if (!payload || typeof payload !== "object" || !("detail" in payload)) {
    return 60;
  }
  const detail = payload.detail;
  if (
    !detail ||
    typeof detail !== "object" ||
    !("retry_after_seconds" in detail) ||
    typeof detail.retry_after_seconds !== "number"
  ) {
    return 60;
  }
  return Math.max(1, Math.ceil(detail.retry_after_seconds));
}
