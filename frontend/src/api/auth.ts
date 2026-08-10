import { request } from "@/api/client";

export interface CurrentUser {
  id: string;
  username: string;
  display_name: string | null;
  is_superuser: boolean;
}

export interface LoginPayload {
  username: string;
  password: string;
  captcha_id: string;
  captcha_answer: string;
}

export interface SetupAdminPayload {
  username: string;
  password: string;
  display_name?: string | null;
  captcha_id: string;
  captcha_answer: string;
}

export interface CaptchaChallenge {
  captcha_id: string;
  image_base64: string;
  expires_in: number;
}

export interface LoginResponse {
  user: CurrentUser;
}

export interface SetupStatus {
  needs_setup: boolean;
  has_active_superuser: boolean;
}

export function login(payload: LoginPayload) {
  return request<LoginResponse>("/api/v1/auth/login", {
    method: "POST",
    body: payload
  });
}

export function createCaptcha() {
  return request<CaptchaChallenge>("/api/v1/auth/captcha", {
    method: "POST"
  });
}

export function setupAdmin(payload: SetupAdminPayload) {
  return request<LoginResponse>("/api/v1/auth/setup-admin", {
    method: "POST",
    body: payload
  });
}

export function logout() {
  return request<void>("/api/v1/auth/logout", {
    method: "POST"
  });
}

export function getCurrentUser() {
  return request<CurrentUser>("/api/v1/auth/me");
}

export function getSetupStatus() {
  return request<SetupStatus>("/api/v1/auth/setup-status");
}
