import { request } from "@/api/client";
import type {
  MatchEvaluationRequest,
  MatchEvaluationResponse,
  MatchResultHandlingReopen,
  MatchResultHandlingUpdate,
  MatchResultDetail,
  MatchResultListPage,
  MatchResultsQuery,
  RiskConfig,
  RiskQueueQuery,
  VerificationTask,
  VerificationTaskRequest,
  EmailAction
} from "@/api/types";

export function getRiskQueue(query: RiskQueueQuery = {}) {
  return request<MatchResultListPage>("/api/v1/match-results/risk-queue", {
    query: { ...query, paged: true }
  });
}

export function getRiskConfig() {
  return request<RiskConfig>("/api/v1/match-results/risk-config");
}

export function getMatchResults(query: MatchResultsQuery = {}) {
  return request<MatchResultListPage>("/api/v1/match-results", {
    query: { ...query, paged: true }
  });
}

export function getMatchResult(matchResultId: string) {
  return request<MatchResultDetail>(`/api/v1/match-results/${matchResultId}`);
}

export function reevaluateMatchResult(matchResultId: string) {
  return request<MatchResultDetail>(
    `/api/v1/match-results/${matchResultId}/reevaluate`,
    {
      method: "POST"
    }
  );
}

export function updateMatchResultHandling(
  matchResultId: string,
  body: MatchResultHandlingUpdate
) {
  return request<MatchResultDetail>(
    `/api/v1/match-results/${matchResultId}/handling`,
    {
      method: "PATCH",
      body
    }
  );
}

export function reopenMatchResultHandling(
  matchResultId: string,
  body: MatchResultHandlingReopen
) {
  return request<MatchResultDetail>(
    `/api/v1/match-results/${matchResultId}/handling/reopen`,
    {
      method: "POST",
      body
    }
  );
}

export function evaluateMatchResults(body: MatchEvaluationRequest) {
  return request<MatchEvaluationResponse>("/api/v1/match-results/evaluate", {
    method: "POST",
    body
  });
}

export function getMatchEvaluationRun(runId: string) {
  return request<MatchEvaluationResponse>(
    `/api/v1/match-results/evaluations/${runId}`
  );
}

export function getMatchEvaluationRuns(limit = 20) {
  return request<MatchEvaluationResponse[]>("/api/v1/match-results/evaluations", {
    query: { limit }
  });
}

export function createVerificationTask(
  matchResultId: string,
  body: VerificationTaskRequest
) {
  return request<VerificationTask>(
    `/api/v1/match-results/${matchResultId}/verification-tasks`,
    {
      method: "POST",
      body
    }
  );
}

export function sendMatchResultEmailAlert(matchResultId: string) {
  return request<EmailAction>(`/api/v1/match-results/${matchResultId}/email-alert`, {
    method: "POST"
  });
}
