import { t } from "@/app/i18n";
import {
  Alert,
  Button,
  Card,
  Col,
  Collapse,
  Descriptions,
  Form,
  Input,
  message,
  Progress,
  Popconfirm,
  Row,
  Select,
  Space,
  Statistic,
  Tag,
  Tooltip,
  Typography
} from "antd";
import type { ColumnsType } from "antd/es/table";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  ArrowLeft,
  BookOpen,
  CircleHelp,
  ClipboardCheck,
  FileClock,
  Mail,
  RefreshCw,
  RotateCcw,
  Send
} from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { useNavigate, useParams, useSearchParams } from "react-router";

import {
  createVerificationTask,
  getMatchResult,
  reopenMatchResultHandling,
  sendMatchResultEmailAlert,
  updateMatchResultHandling,
  reevaluateMatchResult
} from "@/api/matchResults";
import { getVerificationTasks } from "@/api/verification";
import type {
  AssetOwnershipStatus,
  MatchResultHandlingRecord,
  MatchResultHandlingUpdate,
  MatchRuleTrace,
  RiskFactor,
  VerificationTask,
  VerificationTaskSummary
} from "@/api/types";
import ConfidenceBar from "@/components/ConfidenceBar";
import ErrorState from "@/components/ErrorState";
import EvidenceList from "@/components/EvidenceList";
import HandlingStatusTag, { handlingStatusLabel } from "@/components/HandlingStatusTag";
import LoadingBlock from "@/components/LoadingBlock";
import MatchResultHandlingModal from "@/components/MatchResultHandlingModal";
import PageHeader from "@/components/PageHeader";
import ResizableTable from "@/components/ResizableTable";
import RiskPriorityTag from "@/components/RiskPriorityTag";
import StatusTag from "@/components/StatusTag";
import { VerificationTaskStatusTag } from "@/components/ValueTags";
import { formatDateTime, formatPercent, formatScore } from "@/utils/format";

interface VerificationFormValues {
  task_type: string;
  requested_by?: string;
  package_name: string;
  target_type: VerificationTargetType;
}

type VerificationTargetType = "package" | "kernel" | "operating_system";

const defaultVerificationValues: VerificationFormValues = {
  task_type: "package_version_check",
  requested_by: "",
  package_name: "",
  target_type: "package"
};

const verificationTargetOptions: { label: string; value: VerificationTargetType }[] = [
  { label: t("普通软件包"), value: "package" },
  { label: t("Linux 内核"), value: "kernel" },
  { label: t("操作系统"), value: "operating_system" }
];

const fixedVerificationTargetMeta: Record<
  Exclude<VerificationTargetType, "package">,
  { displayName: string; submitName: string }
> = {
  kernel: {
    displayName: t("当前主机 Linux 内核版本（此项为固定对象，无法编辑）"),
    submitName: "Linux Kernel"
  },
  operating_system: {
    displayName: t("当前主机操作系统版本（此项为固定对象，无法编辑）"),
    submitName: "Operating System"
  }
};

const verificationTaskHelpText =
  t("普通软件包会在 Agent 包清单中查找；Linux 内核和操作系统会读取主机平台版本事实。");
const tracePaginationHelpText =
  t("当漏洞存在多个影响产品时，将分别执行多次匹配流程，每组流程均将产生一组结果");

const ownershipStatusMeta: Record<
  AssetOwnershipStatus,
  { label: string; color: string }
> = {
  complete: { label: t("归属完整"), color: "green" },
  unassigned: { label: t("未绑定"), color: "default" },
  system_incomplete: { label: t("关系不完整"), color: "orange" }
};

const ownershipSourceLabels: Record<string, string> = {
  manual: t("人工绑定"),
  migration: t("历史迁移"),
  agent_match: t("Agent 自动匹配")
};

function buildPackageVerificationDefaults(
  packageName?: string | null,
  matchedPackageName?: string | null
): Pick<VerificationFormValues, "package_name" | "target_type"> {
  const normalized = (matchedPackageName || packageName)?.trim() ?? "";
  const componentType = verificationComponentTypeForProduct(normalized);
  return {
    package_name: componentType
      ? fixedVerificationTargetMeta[componentType].displayName
      : normalized,
    target_type: componentType || "package"
  };
}

function matchedPackageNameFromEvidence(
  evidence?: { evidence_type: string; details: Record<string, unknown> }[]
) {
  const match = evidence?.find((item) => {
    if (!["product_match", "package_version"].includes(item.evidence_type)) {
      return false;
    }
    if (item.evidence_type === "product_match" && item.details.kind !== "component") {
      return false;
    }
    return typeof item.details.name === "string" && item.details.name.trim().length > 0;
  });
  return typeof match?.details.name === "string" ? match.details.name : null;
}

function packageFieldValueForTarget(
  targetType: VerificationTargetType,
  packageName?: string | null,
  matchedPackageName?: string | null
) {
  if (targetType !== "package") {
    return fixedVerificationTargetMeta[targetType].displayName;
  }
  const normalized = (matchedPackageName || packageName)?.trim() ?? "";
  return verificationComponentTypeForProduct(normalized) ? "" : normalized;
}

function packageNameForSubmission(values: VerificationFormValues) {
  if (values.target_type !== "package") {
    return fixedVerificationTargetMeta[values.target_type].submitName;
  }
  return values.package_name?.trim() ?? "";
}

function verificationComponentTypeForProduct(
  product?: string | null
): Exclude<VerificationTargetType, "package"> | "" {
  const key = (product ?? "").toLowerCase().replace(/[^a-z0-9]+/g, "");
  if (
    ["linuxkernel", "kernel", "linuximage", "linuximagegeneric", "linuxheaders"].includes(
      key
    )
  ) {
    return "kernel";
  }
  if (
    [
      "ubuntu",
      "ubuntulinux",
      "debian",
      "debianlinux",
      "redhatenterpriselinux",
      "rhel",
      "redhat",
      "redhatlinux",
      "centos",
      "centoslinux",
      "rockylinux",
      "rocky",
      "almalinux",
      "amazonlinux",
      "amzn",
      "amzn2"
    ].includes(key)
  ) {
    return "operating_system";
  }
  return "";
}

function traceRowKey(record: MatchRuleTrace, index?: number) {
  const scopeKey = JSON.stringify(record.risk_scope ?? {});
  return [
    index ?? "trace",
    record.rule_name,
    record.rule_version,
    record.status,
    scopeKey
  ].join(":");
}

function traceStatusColor(status: string) {
  if (status === "affected") {
    return "red";
  }
  if (status === "not_affected") {
    return "green";
  }
  if (status === "needs_review") {
    return "orange";
  }
  if (status === "not_applicable") {
    return "default";
  }
  return "blue";
}

const traceRuleLabels: Record<string, string> = {
  product_rule: t("产品匹配"),
  version_rule: t("版本匹配"),
  os_rule: t("操作系统匹配"),
  feature_rule: t("特性条件匹配"),
  exposure_rule: t("暴露面匹配")
};

const traceStatusLabels: Record<string, string> = {
  affected: t("受影响"),
  not_affected: t("不受影响"),
  needs_review: t("待复核"),
  not_applicable: t("不适用")
};

const traceContextLabels: Record<string, string> = {
  vendor: t("厂商"),
  product: t("产品"),
  aliases: t("产品别名"),
  affected_versions: t("受影响版本"),
  fixed_versions: t("修复版本"),
  affected_os: t("适用系统"),
  requires_module: t("依赖模块"),
  requires_feature_flag: t("功能条件"),
  requires_public_access: t("需要公网访问"),
  source_url: t("范围来源"),
  matched_components: t("命中组件"),
  matched_versions: t("命中版本"),
  platform: t("平台"),
  os_family: t("操作系统"),
  os_version: t("系统版本"),
  kernel_version: t("内核版本"),
  public_exposure_count: t("公网暴露项"),
  matching_public_exposure_count: t("产品相关暴露项")
};

const riskScopeFieldOrder = [
  "vendor",
  "product",
  "affected_versions",
  "fixed_versions",
  "affected_os",
  "aliases",
  "requires_module",
  "requires_feature_flag",
  "requires_public_access",
  "source_url"
];

const assetContextFieldOrder = [
  "matched_components",
  "matched_versions",
  "platform",
  "os_family",
  "os_version",
  "kernel_version",
  "public_exposure_count",
  "matching_public_exposure_count"
];

function hasTraceContextValue(value: unknown) {
  if (value === null || value === undefined || value === "") {
    return false;
  }
  if (Array.isArray(value)) {
    return value.length > 0;
  }
  if (typeof value === "object") {
    return Object.keys(value).length > 0;
  }
  return true;
}

function orderedTraceContextEntries(
  context: Record<string, unknown>,
  fieldOrder: string[]
) {
  return fieldOrder
    .filter((key) => hasTraceContextValue(context[key]))
    .map((key) => [key, context[key]] as const);
}

function TraceContextValue({ field, value }: { field: string; value: unknown }) {
  if (
    ["matched_components", "matched_versions"].includes(field) &&
    Array.isArray(value)
  ) {
    return (
      <div className="trace-version-list">
        {value.map((item, index) => {
          const versionItem =
            item && typeof item === "object" ? (item as Record<string, unknown>) : {};
          return (
            <div className="trace-version-item" key={`${String(versionItem.name)}-${index}`}>
              <Typography.Text strong>{String(versionItem.name || t("未知组件"))}</Typography.Text>
              <Typography.Text code>
                {String(versionItem.version || t("未提供版本"))}
              </Typography.Text>
              {versionItem.kind || versionItem.source ? (
                <Typography.Text type="secondary">
                  {String(versionItem.kind || versionItem.source)}
                </Typography.Text>
              ) : null}
            </div>
          );
        })}
      </div>
    );
  }

  if (Array.isArray(value)) {
    return (
      <Space size={[4, 4]} wrap>
        {value.map((item, index) => (
          <Tag key={`${String(item)}-${index}`}>{String(item)}</Tag>
        ))}
      </Space>
    );
  }

  if (typeof value === "boolean") {
    return <Typography.Text>{value ? t("是") : t("否")}</Typography.Text>;
  }

  if (field === "source_url" && typeof value === "string") {
    return (
      <Typography.Link href={value} target="_blank" rel="noreferrer">
        {t("查看来源")}</Typography.Link>
    );
  }

  if (typeof value === "object" && value !== null) {
    return <Typography.Text>{JSON.stringify(value)}</Typography.Text>;
  }

  const versionLike = field.includes("version");
  return (
    <Typography.Text className={versionLike ? "trace-context-version" : undefined}>
      {String(value)}
    </Typography.Text>
  );
}

function TraceContextCell({
  context,
  emptyText,
  fieldOrder
}: {
  context: Record<string, unknown>;
  emptyText: string;
  fieldOrder: string[];
}) {
  const entries = orderedTraceContextEntries(context, fieldOrder);
  if (!entries.length) {
    return <Typography.Text type="secondary">{emptyText}</Typography.Text>;
  }

  return (
    <div className="trace-context-grid">
      {entries.map(([field, value]) => (
        <div className="trace-context-item" key={field}>
          <Typography.Text className="trace-context-label">
            {traceContextLabels[field] || field}
          </Typography.Text>
          <div className="trace-context-value">
            <TraceContextValue field={field} value={value} />
          </div>
        </div>
      ))}
    </div>
  );
}

function TraceExpandedDetail({ record }: { record: MatchRuleTrace }) {
  return (
    <div className="trace-expanded-detail">
      <div className="trace-expanded-section">
        <Typography.Text className="trace-expanded-title">{t("风险范围")}</Typography.Text>
        <TraceContextCell
          context={record.risk_scope ?? {}}
          emptyText={t("无")}
          fieldOrder={riskScopeFieldOrder}
        />
      </div>
      <div className="trace-expanded-section">
        <Typography.Text className="trace-expanded-title">{t("资产情况")}</Typography.Text>
        <TraceContextCell
          context={record.asset_context ?? {}}
          emptyText={t("无")}
          fieldOrder={assetContextFieldOrder}
        />
      </div>
      <div className="trace-expanded-section trace-expanded-json">
        <Typography.Text className="trace-expanded-title">{t("输入摘要")}</Typography.Text>
        <pre className="json-block">
          {JSON.stringify(record.input_summary ?? {}, null, 2)}
        </pre>
      </div>
    </div>
  );
}

function SectionCardTitle({
  title,
  subtitle
}: {
  title: string;
  subtitle: string;
}) {
  return (
    <Space className="section-card-title" size={8} wrap>
      <Typography.Text strong>{title}</Typography.Text>
      <Typography.Text type="secondary">{subtitle}</Typography.Text>
    </Space>
  );
}

export default function MatchResultDetailPage() {
  const navigate = useNavigate();
  const { matchResultId } = useParams<{ matchResultId: string }>();
  const [searchParams] = useSearchParams();
  const [form] = Form.useForm<VerificationFormValues>();
  const [messageApi, contextHolder] = message.useMessage();
  const queryClient = useQueryClient();
  const [lastTask, setLastTask] = useState<VerificationTask | null>(null);
  const [handlingModalOpen, setHandlingModalOpen] = useState(false);
  const selectedVerificationTarget =
    Form.useWatch("target_type", form) ?? defaultVerificationValues.target_type;

  const detailQuery = useQuery({
    queryKey: ["match-results", "detail", matchResultId],
    queryFn: () => getMatchResult(matchResultId ?? ""),
    enabled: Boolean(matchResultId)
  });

  const detail = detailQuery.data;
  const matchedPackageName = useMemo(
    () => matchedPackageNameFromEvidence(detail?.evidence),
    [detail?.evidence]
  );
  const defaultVerificationTarget = useMemo(
    () =>
      buildPackageVerificationDefaults(
        detail?.vulnerability_product,
        matchedPackageName
      ),
    [detail?.vulnerability_product, matchedPackageName]
  );
  const verificationNameLabel =
    selectedVerificationTarget === "package" ? t("待验证包名称") : t("待验证对象名称");
  const verificationNamePlaceholder =
    selectedVerificationTarget === "kernel"
      ? fixedVerificationTargetMeta.kernel.displayName
      : selectedVerificationTarget === "operating_system"
        ? fixedVerificationTargetMeta.operating_system.displayName
        : t("例如 nginx、openssl、linux-image-generic");
  const isFixedVerificationTarget = selectedVerificationTarget !== "package";

  useEffect(() => {
    if (!detail) {
      return;
    }
    form.setFieldsValue({
      task_type: defaultVerificationValues.task_type,
      ...defaultVerificationTarget
    });
  }, [defaultVerificationTarget, detail, form]);

  const createTaskMutation = useMutation({
    mutationFn: (values: VerificationFormValues) => {
      if (!matchResultId) {
        throw new Error(t("缺少匹配结果 ID"));
      }

      const packageName = packageNameForSubmission(values);
      if (!packageName) {
        throw new Error(t("请输入待验证包名称"));
      }

      const parameters: Record<string, string> = {
        package_name: packageName
      };
      if (values.target_type !== "package") {
        parameters.component_type = values.target_type;
      }

      return createVerificationTask(matchResultId, {
        task_type: values.task_type || defaultVerificationValues.task_type,
        requested_by: values.requested_by?.trim() || null,
        parameters
      });
    },
    onSuccess: (task) => {
      setLastTask(task);
      messageApi.success(t("验证任务已创建"));
      form.setFieldsValue({
        task_type: defaultVerificationValues.task_type,
        ...defaultVerificationTarget,
        requested_by: form.getFieldValue("requested_by")
      });
      void queryClient.invalidateQueries({ queryKey: ["match-results"] });
      void queryClient.invalidateQueries({ queryKey: ["verification-tasks"] });
    },
    onError: (error) => {
      messageApi.error(error instanceof Error ? error.message : t("验证任务创建失败"));
    }
  });

  const reevaluateMutation = useMutation({
    mutationFn: () => {
      if (!matchResultId) {
        throw new Error(t("缺少匹配结果 ID"));
      }
      return reevaluateMatchResult(matchResultId);
    },
    onSuccess: () => {
      messageApi.success(t("匹配结果已重评估"));
      void queryClient.invalidateQueries({ queryKey: ["match-results"] });
    },
    onError: (error) => {
      messageApi.error(error instanceof Error ? error.message : t("重评估失败"));
    }
  });

  const handleVerificationTargetChange = (targetType: VerificationTargetType) => {
    form.setFieldValue(
      "package_name",
      packageFieldValueForTarget(
        targetType,
        detail?.vulnerability_product,
        matchedPackageName
      )
    );
  };

  const updateHandlingMutation = useMutation({
    mutationFn: (values: MatchResultHandlingUpdate) => {
      if (!matchResultId) {
        throw new Error(t("缺少匹配结果 ID"));
      }
      return updateMatchResultHandling(matchResultId, values);
    },
    onSuccess: () => {
      messageApi.success(t("处置状态已更新"));
      setHandlingModalOpen(false);
      void queryClient.invalidateQueries({ queryKey: ["match-results"] });
      void queryClient.invalidateQueries({ queryKey: ["task-center"] });
    },
    onError: (error) => {
      messageApi.error(error instanceof Error ? error.message : t("处置状态更新失败"));
    }
  });

  const reopenHandlingMutation = useMutation({
    mutationFn: (note?: string | null) => {
      if (!matchResultId) {
        throw new Error(t("缺少匹配结果 ID"));
      }
      return reopenMatchResultHandling(matchResultId, { note });
    },
    onSuccess: () => {
      messageApi.success(t("风险项已重新打开"));
      setHandlingModalOpen(false);
      void queryClient.invalidateQueries({ queryKey: ["match-results"] });
      void queryClient.invalidateQueries({ queryKey: ["task-center"] });
    },
    onError: (error) => {
      messageApi.error(error instanceof Error ? error.message : t("重新打开失败"));
    }
  });

  const emailAlertMutation = useMutation({
    mutationFn: () => {
      if (!matchResultId) {
        throw new Error(t("缺少匹配结果 ID"));
      }
      return sendMatchResultEmailAlert(matchResultId);
    },
    onSuccess: (result) => {
      if (result.status === "skipped") {
        messageApi.warning(result.message);
      } else {
        messageApi.success(result.message);
      }
      void queryClient.invalidateQueries({ queryKey: ["email-deliveries"] });
    },
    onError: (error) => {
      messageApi.error(error instanceof Error ? error.message : t("邮件告警发起失败"));
    }
  });

  const shouldFocusVerification = searchParams.get("verify") === "1";

  const verificationTasksQuery = useQuery({
    queryKey: ["verification-tasks", "match-result", detail?.id],
    queryFn: () =>
      getVerificationTasks({
        match_result_id: detail?.id ?? "",
        limit: 20
      }),
    enabled: Boolean(detail?.id)
  });

  const riskFactorColumns: ColumnsType<RiskFactor> = useMemo(
    () => [
      { title: t("因子"), dataIndex: "label", width: 140 },
      {
        title: t("取值"),
        dataIndex: "value",
        width: 120,
        render: (value: number) => formatScore(value)
      },
      {
        title: t("权重"),
        dataIndex: "weight",
        width: 120,
        render: (value: number) => formatPercent(value)
      },
      {
        title: t("加权分"),
        dataIndex: "weighted_score",
        width: 140,
        render: (value: number) => (
          <div className="factor-score">
            <Progress
              percent={Math.round(Math.max(0, Math.min(1, value)) * 100)}
              size="small"
              showInfo={false}
            />
            <span>{formatScore(value)}</span>
          </div>
        )
      },
      {
        title: t("证据"),
        dataIndex: "evidence",
        render: (value: string[]) =>
          value.length ? (
            <Typography.Text className="table-subtitle">{value.join(" / ")}</Typography.Text>
          ) : (
            "-"
          )
      }
    ],
    []
  );

  const traceColumns: ColumnsType<MatchRuleTrace> = useMemo(
    () => [
      {
        title: t("规则"),
        dataIndex: "rule_name",
        width: 190,
        render: (value: string, record) => (
          <Space orientation="vertical" size={0}>
            <Typography.Text strong>{traceRuleLabels[value] || value}</Typography.Text>
            <Typography.Text className="table-subtitle">
              {value} · {record.rule_version}
            </Typography.Text>
          </Space>
        )
      },
      {
        title: t("输出"),
        dataIndex: "status",
        width: 150,
        render: (value: string, record) => (
          <Space size={4} wrap>
            <Tag color={traceStatusColor(value)}>{traceStatusLabels[value] || value}</Tag>
            {!record.executed ? <Tag>{t("跳过")}</Tag> : null}
          </Space>
        )
      },
      {
        title: t("置信度"),
        dataIndex: "confidence",
        width: 130,
        render: (value: number) => <ConfidenceBar value={value} />
      },
      {
        title: t("证据数"),
        dataIndex: "evidence_count",
        width: 86
      },
      {
        title: t("原因"),
        dataIndex: "reason",
        render: (value: string, record) => (
          <Space className="trace-reason-cell" orientation="vertical" size={2}>
            <Typography.Text className="trace-reason">{value}</Typography.Text>
            {record.uncertain_reason ? (
              <Typography.Text className="table-subtitle">
                {record.uncertain_reason}
              </Typography.Text>
            ) : null}
          </Space>
        )
      }
    ],
    []
  );

  const verificationTaskColumns: ColumnsType<VerificationTaskSummary> = useMemo(
    () => [
      {
        title: t("任务"),
        dataIndex: "id",
        minWidth: 260,
        render: (_: string, record) => (
          <Space orientation="vertical" size={0}>
            <Typography.Link onClick={() => navigate(`/verification-tasks/${record.id}`)}>
              {record.id}
            </Typography.Link>
            <Typography.Text className="table-subtitle">
              {record.task_type}
            </Typography.Text>
          </Space>
        )
      },
      {
        title: t("状态"),
        dataIndex: "status",
        width: 120,
        render: (value: string) => <VerificationTaskStatusTag value={value} />
      },
      {
        title: t("证据"),
        dataIndex: "evidence_count",
        width: 80
      },
      {
        title: t("创建时间"),
        dataIndex: "created_at",
        width: 190,
        render: (value: string) => formatDateTime(value)
      },
      {
        title: t("完成时间"),
        dataIndex: "completed_at",
        width: 190,
        render: (value: string | null) => formatDateTime(value)
      },
      {
        title: t("操作"),
        key: "actions",
        width: 100,
        render: (_, record) => (
          <Button
            className="table-action-button"
            type="link"
            onClick={() => navigate(`/verification-tasks/${record.id}`)}
          >
            {t("查看")}</Button>
        )
      }
    ],
    [navigate]
  );

  const handlingRecordColumns: ColumnsType<MatchResultHandlingRecord> = useMemo(
    () => [
      {
        title: t("时间"),
        dataIndex: "created_at",
        width: 190,
        render: (value: string) => formatDateTime(value)
      },
      {
        title: t("动作"),
        dataIndex: "action",
        width: 120,
        render: (value: string) => (value === "reopened" ? t("重新打开") : t("状态变更"))
      },
      {
        title: t("状态变化"),
        key: "status",
        width: 240,
        render: (_, record) => (
          <Space size={4} wrap>
            {record.from_status ? (
              <HandlingStatusTag value={record.from_status} />
            ) : (
              <Tag>{t("起始")}</Tag>
            )}
            <Typography.Text type="secondary">{t("到")}</Typography.Text>
            <HandlingStatusTag value={record.to_status} />
          </Space>
        )
      },
      {
        title: t("说明"),
        dataIndex: "note",
        render: (value: string | null) => value || "-"
      },
      {
        title: t("操作者"),
        key: "actor",
        width: 180,
        render: (_, record) =>
          record.actor_display_name || record.actor_username || record.actor_id || "-"
      }
    ],
    []
  );

  const latestHandlingRecord = detail?.handling_records[0];

  return (
    <Space className="page-stack" orientation="vertical" size={16}>
      {contextHolder}
      <PageHeader
        title={t("匹配详情")}
        extra={
          <Space>
            <Button icon={<ArrowLeft size={16} />} onClick={() => navigate(-1)}>
              {t("返回")}</Button>
            <Button
              icon={<FileClock size={16} />}
              onClick={() =>
                navigate(
                  `/audit?resource_type=match_result&resource_id=${encodeURIComponent(
                    matchResultId ?? ""
                  )}`
                )
              }
              disabled={!matchResultId}
            >
              {t("相关审计")}</Button>
            <Button
              icon={<RefreshCw size={16} />}
              onClick={() => detailQuery.refetch()}
              loading={detailQuery.isFetching}
            >
              {t("刷新")}</Button>
            <Button
              icon={<RotateCcw size={16} />}
              onClick={() => reevaluateMutation.mutate()}
              loading={reevaluateMutation.isPending}
              disabled={!matchResultId}
            >
              {t("重评估")}</Button>
            <Popconfirm
              title={t("确认发送风险邮件告警？")}
              description={t("手动发送受风险阈值和邮件总开关限制，允许重复发送。")}
              okText={t("确认发送")}
              cancelText={t("取消")}
              onConfirm={() => emailAlertMutation.mutate()}
            >
              <Button icon={<Mail size={16} />} loading={emailAlertMutation.isPending} disabled={!matchResultId}>
                {t("邮件告警")}
              </Button>
            </Popconfirm>
            <Button
              type="primary"
              icon={<ClipboardCheck size={16} />}
              onClick={() => setHandlingModalOpen(true)}
              disabled={!detail}
            >
              {t("处置")}</Button>
          </Space>
        }
      />

      {detailQuery.isLoading ? <LoadingBlock /> : null}
      {detailQuery.isError ? <ErrorState error={detailQuery.error} /> : null}

      {detail ? (
        <>
          <Row gutter={[16, 16]}>
            <Col xs={24} lg={6}>
              <Card className="metric-card metric-card-red">
                <Statistic
                  title={t("风险分")}
                  value={formatScore(detail.risk_score)}
                  prefix={<RiskPriorityTag value={detail.risk_priority} />}
                />
              </Card>
            </Col>
            <Col xs={24} lg={6}>
              <Card className="metric-card">
                <Statistic
                  title={t("当前状态")}
                  valueRender={() => <StatusTag value={detail.status} />}
                />
              </Card>
            </Col>
            <Col xs={24} lg={6}>
              <Card className="metric-card">
                <Statistic
                  title={t("匹配置信度")}
                  valueRender={() => <ConfidenceBar value={detail.confidence} />}
                />
              </Card>
            </Col>
            <Col xs={24} lg={6}>
              <Card className="metric-card metric-card-green">
                <Statistic title={t("验证证据")} value={detail.verification_evidence.length} />
              </Card>
            </Col>
          </Row>

          <Card className="content-card" title={t("上下文")}>
            <Descriptions
              bordered
              size="small"
              column={{ xs: 1, md: 2 }}
              items={[
                {
                  key: "riskCode",
                  label: t("风险编号"),
                  children: detail.risk_code ? (
                    <Typography.Text
                      className="risk-business-code"
                      copyable={{ text: detail.risk_code }}
                    >
                      {detail.risk_code}
                    </Typography.Text>
                  ) : (
                    <Typography.Text type="secondary">
                      {t("未进入风险队列，不生成风险编号")}</Typography.Text>
                  )
                },
                {
                  key: "vulnerability",
                  label: t("漏洞"),
                  children: (
                    <Space orientation="vertical" size={0}>
                      <Typography.Link
                        onClick={() =>
                          navigate(
                            `/vulnerabilities/${encodeURIComponent(
                              detail.vulnerability_canonical_id ||
                                detail.vulnerability_id
                            )}`
                          )
                        }
                      >
                        {detail.vulnerability_canonical_id}
                      </Typography.Link>
                      <Typography.Text className="table-subtitle" ellipsis>
                        {detail.vulnerability_title}
                      </Typography.Text>
                    </Space>
                  )
                },
                {
                  key: "asset",
                  label: t("资产"),
                  children: (
                    <Space orientation="vertical" size={0}>
                      <Typography.Link
                        onClick={() =>
                          navigate(`/assets/${encodeURIComponent(detail.asset_id)}`)
                        }
                      >
                        {detail.asset_hostname}
                      </Typography.Link>
                      <Typography.Text className="table-subtitle" ellipsis>
                        {detail.asset_id}
                      </Typography.Text>
                    </Space>
                  )
                },
                {
                  key: "rule",
                  label: t("规则版本"),
                  children: detail.rule_version
                },
                {
                  key: "riskModel",
                  label: t("风险模型"),
                  children: detail.risk_model_version
                },
                {
                  key: "evaluated",
                  label: t("最近评估"),
                  children: formatDateTime(detail.last_evaluated_at)
                },
                {
                  key: "matchId",
                  label: t("内部匹配 ID"),
                  children: detail.id
                },
                {
                  key: "assetId",
                  label: t("资产 ID"),
                  children: detail.asset_id
                },
                {
                  key: "agent",
                  label: "Agent",
                  children: detail.asset_agent_id ? (
                    <Typography.Link
                      onClick={() =>
                        navigate(`/agents?agent_id=${encodeURIComponent(detail.asset_agent_id ?? "")}`)
                      }
                    >
                      {detail.asset_agent_id}
                    </Typography.Link>
                  ) : (
                    "-"
                  )
                },
                {
                  key: "snapshot",
                  label: t("资产新鲜度"),
                  children: detail.asset_is_stale ? t("快照过期") : t("快照新鲜")
                }
              ]}
            />
          </Card>

          <Card className="content-card" title={t("风险解释")}>
            <Space orientation="vertical" size={12}>
              <Typography.Paragraph className="explanation-text">
                {detail.risk_explanation ?? "-"}
              </Typography.Paragraph>
              <Typography.Paragraph className="explanation-text">
                {detail.match_reason ?? "-"}
              </Typography.Paragraph>
            </Space>
          </Card>

          <Card
            className="content-card"
            title={t("责任归属")}
            extra={
              <Space size={8}>
                <Tag color={ownershipStatusMeta[detail.ownership.status].color}>
                  {ownershipStatusMeta[detail.ownership.status].label}
                </Tag>
                <Button
                  type="link"
                  onClick={() =>
                    navigate(`/assets/${encodeURIComponent(detail.asset_id)}`)
                  }
                >
                  {t("查看资产")}</Button>
              </Space>
            }
          >
            {detail.ownership.status !== "complete" ? (
              <Alert
                className="ownership-status-alert"
                type={detail.ownership.status === "unassigned" ? "warning" : "info"}
                showIcon
                title={
                  detail.ownership.status === "unassigned"
                    ? t("该风险关联资产尚未绑定业务系统")
                    : t("该风险关联资产的责任关系不完整")
                }
                description={
                  detail.ownership.status === "unassigned"
                    ? t("请先在资产列表中绑定业务系统，系统会自动带出责任人员和责任团队。")
                    : t("业务系统、责任人员或责任团队存在缺失、停用状态，请到归属管理页面完善。")
                }
              />
            ) : null}
            <Descriptions
              bordered
              size="small"
              column={{ xs: 1, md: 3 }}
              items={[
                {
                  key: "businessSystem",
                  label: t("业务系统"),
                  children: detail.ownership.business_system ? (
                    <Space orientation="vertical" size={0}>
                      <Typography.Text strong>
                        {detail.ownership.business_system.name}
                      </Typography.Text>
                      <Typography.Text className="table-subtitle">
                        {detail.ownership.business_system.code}
                      </Typography.Text>
                    </Space>
                  ) : (
                    "-"
                  )
                },
                {
                  key: "responsiblePerson",
                  label: t("责任人员"),
                  children: detail.ownership.responsible_person ? (
                    <Space orientation="vertical" size={0}>
                      <Typography.Text strong>
                        {detail.ownership.responsible_person.name}
                      </Typography.Text>
                      {detail.ownership.responsible_person.email ? (
                        <Typography.Link
                          href={`mailto:${detail.ownership.responsible_person.email}`}
                        >
                          {detail.ownership.responsible_person.email}
                        </Typography.Link>
                      ) : null}
                    </Space>
                  ) : (
                    "-"
                  )
                },
                {
                  key: "responsibilityTeam",
                  label: t("责任团队"),
                  children: detail.ownership.responsibility_team ? (
                    <Space orientation="vertical" size={0}>
                      <Typography.Text strong>
                        {detail.ownership.responsibility_team.name}
                      </Typography.Text>
                      <Typography.Text className="table-subtitle">
                        {detail.ownership.responsibility_team.code}
                      </Typography.Text>
                    </Space>
                  ) : (
                    "-"
                  )
                },
                {
                  key: "ownershipStatus",
                  label: t("归属状态"),
                  children: (
                    <Tag color={ownershipStatusMeta[detail.ownership.status].color}>
                      {ownershipStatusMeta[detail.ownership.status].label}
                    </Tag>
                  )
                },
                {
                  key: "ownershipSource",
                  label: t("绑定来源"),
                  children: detail.ownership.source
                    ? ownershipSourceLabels[detail.ownership.source] ?? detail.ownership.source
                    : "-"
                },
                {
                  key: "ownershipUpdatedAt",
                  label: t("归属更新时间"),
                  children: formatDateTime(detail.ownership.updated_at)
                }
              ]}
            />
          </Card>

          <Card
            className="content-card"
            title={t("人工处置")}
            extra={
              <Button
                type="primary"
                icon={<ClipboardCheck size={16} />}
                onClick={() => setHandlingModalOpen(true)}
              >
                {t("处置")}</Button>
            }
          >
            <Descriptions
              bordered
              size="small"
              column={{ xs: 1, md: 2 }}
              items={[
                {
                  key: "handlingStatus",
                  label: t("当前处置状态"),
                  children: <HandlingStatusTag value={detail.handling_status} />
                },
                {
                  key: "handlingClosedAt",
                  label: t("闭环时间"),
                  children: formatDateTime(detail.handling_closed_at)
                },
                {
                  key: "handlingUpdatedAt",
                  label: t("最近处置时间"),
                  children: formatDateTime(detail.handling_updated_at)
                },
                {
                  key: "handlingActor",
                  label: t("最近操作者"),
                  children:
                    latestHandlingRecord?.actor_display_name ||
                    latestHandlingRecord?.actor_username ||
                    detail.handling_updated_by ||
                    "-"
                },
                {
                  key: "handlingNote",
                  label: t("最近说明"),
                  span: { xs: 1, md: 2 },
                  children: detail.handling_note || "-"
                }
              ]}
            />
            <ResizableTable<MatchResultHandlingRecord>
              storageKey="match-result-handling-history"
              className="handling-history-table"
              rowKey="id"
              columns={handlingRecordColumns}
              dataSource={detail.handling_records}
              pagination={false}
              locale={{ emptyText: t("暂无处置历史") }}
              scroll={{ x: 920 }}
              title={() => t("处置历史：{{v0}}", { v0: handlingStatusLabel(detail.handling_status) })}
            />
          </Card>

          <Card
            className="content-card"
            title={t("风险因子")}
            extra={
              <Button
                type="link"
                icon={<BookOpen size={15} />}
                onClick={() => navigate("/rules#risk-factors")}
              >
                {t("规则说明")}</Button>
            }
          >
            <ResizableTable<RiskFactor>
              storageKey="match-result-risk-factors"
              rowKey="name"
              columns={riskFactorColumns}
              dataSource={detail.risk_factors}
              pagination={false}
              scroll={{ x: 820 }}
            />
          </Card>

          <Card
            className="content-card"
            title={
              <Space className="section-card-title" size={8} wrap>
                <Typography.Text strong>{t("规则匹配过程")}</Typography.Text>
                <Typography.Text type="secondary">
                  {t("看规则引擎如何逐步执行、跳过和输出结论")}</Typography.Text>
                <Tooltip title={tracePaginationHelpText} placement="right">
                  <span
                    className="inline-help-trigger"
                    tabIndex={0}
                    aria-label={t("规则匹配过程分页说明")}
                  >
                    <Typography.Text className="inline-hint-text">
                      {t("按匹配组别分页")}</Typography.Text>
                  </span>
                </Tooltip>
              </Space>
            }
            extra={
              <Button
                type="link"
                icon={<BookOpen size={15} />}
                onClick={() => navigate("/rules#trace")}
              >
                {t("规则说明")}</Button>
            }
          >
            <ResizableTable<MatchRuleTrace>
              storageKey="match-result-rule-trace"
              rowKey={(record, index) => traceRowKey(record, index)}
              columns={traceColumns}
              dataSource={detail.matching_trace}
              pagination={{
                pageSize: 5,
                showSizeChanger: false,
                hideOnSinglePage: true,
                size: "small"
              }}
              scroll={{ x: 980 }}
              expandable={{
                expandedRowRender: (record) => <TraceExpandedDetail record={record} />
              }}
            />

            <Collapse
              className="detail-subsection-collapse"
              expandIconPosition="end"
              ghost
              items={[
                {
                  key: "matching-evidence",
                  label: (
                    <SectionCardTitle
                      title={t("匹配事实依据")}
                      subtitle={t("看规则用到了哪些资产、漏洞和暴露面事实")}
                    />
                  ),
                  children: (
                    <EvidenceList
                      items={detail.evidence}
                      emptyText={t("暂无匹配证据")}
                      mode="matching"
                    />
                  )
                }
              ]}
            />
          </Card>

          <Card
            className={`content-card verification-card ${
              shouldFocusVerification ? "verification-card-focused" : ""
            }`}
            title={
              <Space size={8}>
                <Typography.Text strong>{t("验证任务")}</Typography.Text>
                <Tooltip title={verificationTaskHelpText} placement="right">
                  <span
                    className="inline-help-trigger"
                    tabIndex={0}
                    aria-label={t("验证任务说明")}
                  >
                    <CircleHelp
                      size={15}
                      className="inline-help-icon"
                      aria-hidden="true"
                    />
                  </span>
                </Tooltip>
              </Space>
            }
          >
            <Form
              form={form}
              layout="vertical"
              initialValues={defaultVerificationValues}
              onFinish={(values) => createTaskMutation.mutate(values)}
            >
              <Form.Item name="task_type" hidden>
                <Input />
              </Form.Item>

              <Row gutter={[16, 0]}>
                <Col xs={24} md={8}>
                  <Form.Item
                    label={t("验证对象")}
                    name="target_type"
                    rules={[{ required: true, message: t("请选择验证对象") }]}
                  >
                    <Select
                      options={verificationTargetOptions}
                      onChange={handleVerificationTargetChange}
                    />
                  </Form.Item>
                </Col>
                <Col xs={24} md={10}>
                  <Form.Item
                    label={verificationNameLabel}
                    name="package_name"
                    rules={[
                      {
                        required: true,
                        whitespace: true,
                        message: t("请输入待验证包名称")
                      }
                    ]}
                  >
                    <Input
                      disabled={isFixedVerificationTarget}
                      placeholder={verificationNamePlaceholder}
                    />
                  </Form.Item>
                </Col>
                <Col xs={24} md={6}>
                  <Form.Item label={t("请求人")} name="requested_by">
                    <Input placeholder="operator@example.test" />
                  </Form.Item>
                </Col>
              </Row>

              <Space className="form-actions">
                <Button
                  onClick={() =>
                    form.setFieldsValue({
                      ...defaultVerificationValues,
                      ...defaultVerificationTarget
                    })
                  }
                  disabled={createTaskMutation.isPending}
                >
                  {t("重置")}</Button>
                <Button
                  type="primary"
                  htmlType="submit"
                  icon={<Send size={16} />}
                  loading={createTaskMutation.isPending}
                >
                  {t("创建验证任务")}</Button>
              </Space>
            </Form>

            {lastTask ? (
              <Alert
                className="task-alert"
                type="success"
                showIcon
                title={t("任务 {{v0}} 已进入 {{v1}}", { v0: lastTask.id, v1: lastTask.status })}
                description={t("创建时间：{{v0}}", { v0: formatDateTime(lastTask.created_at) })}
                action={
                  <Button
                    size="small"
                    type="primary"
                    onClick={() => navigate(`/verification-tasks/${lastTask.id}`)}
                  >
                    {t("查看任务")}</Button>
                }
              />
            ) : null}

            <Collapse
              className="detail-subsection-collapse"
              expandIconPosition="end"
              ghost
              items={[
                {
                  key: "verification-evidence",
                  label: (
                    <SectionCardTitle
                      title={t("验证发现")}
                      subtitle={t("看只读验证任务补充了哪些检查结果")}
                    />
                  ),
                  children: (
                    <EvidenceList
                      items={detail.verification_evidence}
                      emptyText={t("暂无验证证据")}
                      mode="verification"
                    />
                  )
                },
                {
                  key: "verification-records",
                  label: <Typography.Text strong>{t("任务记录")}</Typography.Text>,
                  children: (
                    <ResizableTable<VerificationTaskSummary>
                      storageKey="match-result-verification-tasks"
                      rowKey="id"
                      columns={verificationTaskColumns}
                      dataSource={verificationTasksQuery.data?.items ?? []}
                      loading={verificationTasksQuery.isFetching}
                      pagination={{
                        pageSize: 5,
                        showSizeChanger: false,
                        hideOnSinglePage: true,
                        size: "small"
                      }}
                      locale={{ emptyText: t("暂无任务记录") }}
                      scroll={{ x: 950 }}
                    />
                  )
                }
              ]}
            />
          </Card>
        </>
      ) : null}
      <MatchResultHandlingModal
        open={handlingModalOpen}
        result={detail ?? null}
        saving={updateHandlingMutation.isPending}
        reopening={reopenHandlingMutation.isPending}
        onCancel={() => setHandlingModalOpen(false)}
        onSave={(values) => updateHandlingMutation.mutate(values)}
        onReopen={(note) => reopenHandlingMutation.mutate(note)}
      />
    </Space>
  );
}
