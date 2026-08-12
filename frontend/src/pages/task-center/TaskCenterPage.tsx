import { t } from "@/app/i18n";
import {
  Button,
  Card,
  Col,
  Form,
  Input,
  InputNumber,
  Popconfirm,
  Row,
  Select,
  Space,
  Statistic,
  Tag,
  Typography,
  message
} from "antd";
import type { ColumnsType } from "antd/es/table";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  Ban,
  DownloadCloud,
  Eye,
  ListChecks,
  PlayCircle,
  RefreshCw,
  RotateCcw,
  SearchCheck,
  ShieldAlert
} from "lucide-react";
import { useMemo, useState } from "react";
import { useNavigate } from "react-router";

import type { IntelVisibleSourceName } from "@/api/intel";
import {
  collectIntelEnrichmentSource,
  collectIntelSource,
  isIntelEnrichmentSourceName
} from "@/api/intel";
import { createVerificationTask, reevaluateMatchResult } from "@/api/matchResults";
import { getTaskCenterItems, getTaskCenterSummary } from "@/api/taskCenter";
import type {
  RiskPriority,
  TaskCenterItem,
  TaskCenterItemsQuery,
  TaskCenterItemType,
  TaskCenterStatusGroup
} from "@/api/types";
import {
  cancelVerificationTask,
  retryVerificationTask
} from "@/api/verification";
import EmptyState from "@/components/EmptyState";
import ErrorState from "@/components/ErrorState";
import PageHeader from "@/components/PageHeader";
import ResizableTable from "@/components/ResizableTable";
import RiskPriorityTag from "@/components/RiskPriorityTag";
import { formatDateTime, formatScore } from "@/utils/format";

const defaultFilters: TaskCenterItemsQuery = {
  limit: 100
};

const itemTypeOptions: Array<{ label: string; value: TaskCenterItemType }> = [
  { label: t("验证任务"), value: "verification" },
  { label: t("情报采集"), value: "intel_collection" },
  { label: t("风险待处理项"), value: "risk_queue_item" },
  { label: t("AI 补全"), value: "ai_enrichment" }
];

const statusGroupOptions: Array<{ label: string; value: TaskCenterStatusGroup }> = [
  { label: t("待处理"), value: "pending" },
  { label: t("运行中"), value: "running" },
  { label: t("已完成"), value: "success" },
  { label: t("失败"), value: "failed" },
  { label: t("已取消"), value: "cancelled" },
  { label: t("需关注"), value: "attention" }
];

const sourceOptions = [
  { label: t("验证任务"), value: "verification" },
  { label: t("风险队列"), value: "risk-queue" },
  { label: t("AI 补全"), value: "ai-enrichment" },
  { label: "CISA KEV", value: "cisa-kev" },
  { label: "CVE List V5", value: "cve-list-v5" },
  { label: "NVD", value: "nvd" },
  { label: "Canonical Ubuntu Security", value: "canonical-ubuntu" },
  { label: "Debian Security Tracker", value: "debian-security-tracker" },
  { label: "Red Hat CSAF VEX", value: "redhat-csaf" }
];

const triggerOptions = [
  { label: t("手动"), value: "manual" },
  { label: t("定时"), value: "scheduled" },
  { label: "Webhook", value: "webhook" },
  { label: t("系统"), value: "system" }
];

const visibleIntelSources: IntelVisibleSourceName[] = [
  "cisa-kev",
  "cve-list-v5",
  "nvd",
  "canonical-ubuntu",
  "debian-security-tracker",
  "redhat-csaf"
];

function normalizeFilters(values: TaskCenterItemsQuery): TaskCenterItemsQuery {
  return {
    ...(values.item_type ? { item_type: values.item_type } : {}),
    ...(values.status_group ? { status_group: values.status_group } : {}),
    ...(values.status?.trim() ? { status: values.status.trim() } : {}),
    ...(values.source ? { source: values.source } : {}),
    ...(values.trigger_type ? { trigger_type: values.trigger_type } : {}),
    ...(values.keyword?.trim() ? { keyword: values.keyword.trim() } : {}),
    limit: values.limit ?? 100
  };
}

function itemTypeLabel(value: TaskCenterItemType) {
  const labels: Record<TaskCenterItemType, string> = {
    verification: t("验证任务"),
    intel_collection: t("情报采集"),
    risk_queue_item: t("风险项"),
    ai_enrichment: t("AI 补全")
  };
  return labels[value];
}

function statusGroupColor(value: TaskCenterStatusGroup) {
  const colors: Record<TaskCenterStatusGroup, string> = {
    pending: "cyan",
    running: "blue",
    success: "green",
    failed: "red",
    cancelled: "default",
    attention: "orange"
  };
  return colors[value];
}

function statusGroupLabel(value: TaskCenterStatusGroup) {
  const labels: Record<TaskCenterStatusGroup, string> = {
    pending: t("待处理"),
    running: t("运行中"),
    success: t("已完成"),
    failed: t("失败"),
    cancelled: t("已取消"),
    attention: t("需关注")
  };
  return labels[value];
}

function canCollectSource(source?: string | null): source is IntelVisibleSourceName {
  return visibleIntelSources.includes(source as IntelVisibleSourceName);
}

function riskPriorityValue(value?: string | null): RiskPriority {
  if (["critical", "high", "medium", "low", "none"].includes(value ?? "")) {
    return value as RiskPriority;
  }
  return "none";
}

function metricValue(item: TaskCenterItem, key: string) {
  return item.metrics[key] ?? 0;
}

function taskTitle(item: TaskCenterItem) {
  const title = item.title;

  if (item.item_type === "verification") {
    if (title === "验证任务") {
      return t("验证任务");
    }
    if (title.startsWith("验证 ")) {
      return `${t("验证")} ${title.slice("验证 ".length)}`;
    }
  }

  if (item.item_type === "intel_collection" && title.endsWith(" 情报采集")) {
    const sourceLabel = title.slice(0, -" 情报采集".length);
    return `${sourceLabel === "阿里云漏洞库" ? t("阿里云漏洞库") : sourceLabel} ${t("情报采集")}`;
  }

  if (item.item_type === "risk_queue_item" && title.startsWith("风险待处理 ")) {
    return `${t("风险待处理")} ${title.slice("风险待处理 ".length)}`;
  }

  if (item.item_type === "ai_enrichment") {
    if (title === "AI 漏洞补全") {
      return t("AI 漏洞补全");
    }
    if (title.startsWith("AI 漏洞补全 ") && title.endsWith(" 条")) {
      return `${t("AI 漏洞补全")} ${title.slice("AI 漏洞补全 ".length, -" 条".length)} ${t("条")}`;
    }
  }

  return title;
}

export default function TaskCenterPage() {
  const navigate = useNavigate();
  const [form] = Form.useForm<TaskCenterItemsQuery>();
  const [filters, setFilters] = useState<TaskCenterItemsQuery>(defaultFilters);
  const [messageApi, contextHolder] = message.useMessage();
  const queryClient = useQueryClient();

  const summaryQuery = useQuery({
    queryKey: ["task-center", "summary"],
    queryFn: getTaskCenterSummary
  });

  const itemsQuery = useQuery({
    queryKey: ["task-center", "items", filters],
    queryFn: () => getTaskCenterItems(filters)
  });

  function invalidateTaskData() {
    void queryClient.invalidateQueries({ queryKey: ["task-center"] });
    void queryClient.invalidateQueries({ queryKey: ["verification-tasks"] });
    void queryClient.invalidateQueries({ queryKey: ["match-results"] });
    void queryClient.invalidateQueries({ queryKey: ["intel"] });
  }

  const cancelMutation = useMutation({
    mutationFn: (taskId: string) => cancelVerificationTask(taskId),
    onSuccess: () => {
      messageApi.success(t("验证任务已更新"));
      invalidateTaskData();
    },
    onError: (error) => {
      messageApi.error(error instanceof Error ? error.message : t("取消任务失败"));
    }
  });

  const retryMutation = useMutation({
    mutationFn: (taskId: string) => retryVerificationTask(taskId),
    onSuccess: (task) => {
      messageApi.success(t("重试任务已创建"));
      invalidateTaskData();
      navigate(`/verification-tasks/${task.id}`);
    },
    onError: (error) => {
      messageApi.error(error instanceof Error ? error.message : t("重试任务失败"));
    }
  });

  const collectMutation = useMutation({
    mutationFn: (sourceName: IntelVisibleSourceName) =>
      isIntelEnrichmentSourceName(sourceName)
        ? collectIntelEnrichmentSource(sourceName, {
            async_mode: true,
            limit: 100,
            force_baseline: false
          })
        : collectIntelSource(sourceName, {
            async_mode: true,
            limit: 100,
            latest_only: true
          }),
    onSuccess: (result) => {
      messageApi.success(result.message ?? t("情报采集任务已提交"));
      invalidateTaskData();
    },
    onError: (error) => {
      messageApi.error(error instanceof Error ? error.message : t("情报采集失败"));
    }
  });

  const createVerificationMutation = useMutation({
    mutationFn: (matchResultId: string) =>
      createVerificationTask(matchResultId, {
        task_type: "package_version_check",
        parameters: {},
        requested_by: null
      }),
    onSuccess: (task) => {
      messageApi.success(t("验证任务已创建"));
      invalidateTaskData();
      navigate(`/verification-tasks/${task.id}`);
    },
    onError: (error) => {
      messageApi.error(error instanceof Error ? error.message : t("验证任务创建失败"));
    }
  });

  const reevaluateMutation = useMutation({
    mutationFn: (matchResultId: string) => reevaluateMatchResult(matchResultId),
    onSuccess: () => {
      messageApi.success(t("匹配结果已重评估"));
      invalidateTaskData();
    },
    onError: (error) => {
      messageApi.error(error instanceof Error ? error.message : t("重评估失败"));
    }
  });

  const summary = summaryQuery.data;
  const rows = itemsQuery.data ?? [];
  const localMetrics = useMemo(
    () => ({
      total: rows.length,
      pending: rows.filter((item) => item.status_group === "pending").length,
      running: rows.filter((item) => item.status_group === "running").length,
      failed: rows.filter((item) => item.status_group === "failed").length,
      attention: rows.filter((item) => item.status_group === "attention").length
    }),
    [rows]
  );

  const columns: ColumnsType<TaskCenterItem> = [
    {
      title: t("类型"),
      dataIndex: "item_type",
      width: 120,
      render: (value: TaskCenterItemType) => <Tag>{itemTypeLabel(value)}</Tag>
    },
    {
      title: t("任务"),
      dataIndex: "title",
      minWidth: 280,
      render: (_: string, record) => (
        <Space orientation="vertical" size={0}>
          <Typography.Link onClick={() => navigate(record.detail_path)}>
            {taskTitle(record)}
          </Typography.Link>
          <Typography.Text className="table-subtitle" copyable>
            {record.raw_id}
          </Typography.Text>
        </Space>
      )
    },
    {
      title: t("状态"),
      key: "status",
      width: 150,
      render: (_, record) => (
        <Space orientation="vertical" size={0}>
          <Tag color={statusGroupColor(record.status_group)}>
            {statusGroupLabel(record.status_group)}
          </Tag>
          <Typography.Text className="table-subtitle">{record.status}</Typography.Text>
        </Space>
      )
    },
    {
      title: t("来源/触发"),
      key: "source",
      width: 160,
      render: (_, record) => (
        <Space orientation="vertical" size={0}>
          <Typography.Text>{record.source ?? "-"}</Typography.Text>
          <Typography.Text className="table-subtitle">
            {record.trigger_type ?? "-"}
          </Typography.Text>
        </Space>
      )
    },
    {
      title: t("资产"),
      key: "asset",
      width: 210,
      render: (_, record) =>
        record.asset_id ? (
          <Space orientation="vertical" size={0}>
            <Typography.Link onClick={() => navigate(`/assets/${record.asset_id}`)}>
              {record.asset_name ?? record.asset_id}
            </Typography.Link>
            <Typography.Text className="table-subtitle">
              {record.agent_id ?? "-"}
            </Typography.Text>
          </Space>
        ) : (
          "-"
        )
    },
    {
      title: t("漏洞"),
      key: "vulnerability",
      minWidth: 240,
      render: (_, record) =>
        record.vulnerability_id ? (
          <Space orientation="vertical" size={0}>
            <Typography.Link
              onClick={() => navigate(`/vulnerabilities/${record.vulnerability_id}`)}
            >
              {record.vulnerability_id}
            </Typography.Link>
            <Typography.Text className="table-subtitle" ellipsis>
              {record.vulnerability_title ?? "-"}
            </Typography.Text>
          </Space>
        ) : (
          "-"
        )
    },
    {
      title: t("风险"),
      key: "risk",
      width: 140,
      render: (_, record) =>
        record.risk_priority ? (
          <Space orientation="vertical" size={0}>
            <RiskPriorityTag value={riskPriorityValue(record.risk_priority)} />
            <Typography.Text className="table-subtitle">
              {record.risk_score === null ? "-" : formatScore(record.risk_score)}
            </Typography.Text>
          </Space>
        ) : (
          "-"
        )
    },
    {
      title: t("计数"),
      key: "metrics",
      width: 170,
      render: (_, record) => {
        if (record.item_type === "verification") {
          return t("{{v0}} 证据 / {{v1}} 重试", { v0: metricValue(record, "evidence_count"), v1: metricValue(
            record,
            "retry_count"
          ) });
        }
        if (record.item_type === "intel_collection") {
          return t("{{v0}} 处理 / {{v1}} 失败", { v0: metricValue(record, "processed_count"), v1: metricValue(
            record,
            "failed_count"
          ) });
        }
        if (record.item_type === "ai_enrichment") {
          return t("{{v0}} 处理 / {{v1}} 待审 / {{v2}} 失败", { v0: metricValue(record, "processed_count"), v1: metricValue(
            record,
            "pending_review_count"
          ), v2: metricValue(record, "failed_count") });
        }
        return t("{{v0}} 验证 / {{v1}} 证据", { v0: metricValue(record, "verification_task_count"), v1: metricValue(
          record,
          "verification_evidence_count"
        ) });
      }
    },
    {
      title: t("更新时间"),
      dataIndex: "updated_at",
      width: 190,
      render: (value: string) => formatDateTime(value)
    },
    {
      title: t("错误"),
      dataIndex: "error_message",
      minWidth: 220,
      render: (value: string | null) => (
        <Typography.Text className="table-subtitle" ellipsis>
          {value ?? "-"}
        </Typography.Text>
      )
    },
    {
      title: t("操作"),
      key: "actions",
      fixed: "right",
      width: 300,
      render: (_, record) => (
        <Space className="table-actions" size={2} wrap>
          <Button
            type="link"
            icon={<Eye size={15} />}
            onClick={() => navigate(record.detail_path)}
          >
            {t("详情")}</Button>
          {record.item_type === "verification" ? (
            <>
              <Popconfirm
                title={t("取消验证任务")}
                onConfirm={() => cancelMutation.mutate(record.raw_id)}
                disabled={!record.available_actions.includes("cancel")}
              >
                <Button
                  type="link"
                  danger
                  icon={<Ban size={15} />}
                  disabled={!record.available_actions.includes("cancel")}
                  loading={cancelMutation.isPending}
                >
                  {t("取消")}</Button>
              </Popconfirm>
              <Button
                type="link"
                icon={<RotateCcw size={15} />}
                disabled={!record.available_actions.includes("retry")}
                loading={retryMutation.isPending}
                onClick={() => retryMutation.mutate(record.raw_id)}
              >
                {t("重试")}</Button>
            </>
          ) : null}
          {record.item_type === "risk_queue_item" ? (
            <>
              <Button
                type="link"
                icon={<PlayCircle size={15} />}
                loading={createVerificationMutation.isPending}
                onClick={() => createVerificationMutation.mutate(record.raw_id)}
              >
                {t("验证")}</Button>
              <Button
                type="link"
                icon={<SearchCheck size={15} />}
                loading={reevaluateMutation.isPending}
                onClick={() => reevaluateMutation.mutate(record.raw_id)}
              >
                {t("重评估")}</Button>
            </>
          ) : null}
          {record.item_type === "intel_collection" && canCollectSource(record.source) ? (
            <Button
              type="link"
              icon={<DownloadCloud size={15} />}
              loading={collectMutation.isPending}
              onClick={() => {
                if (canCollectSource(record.source)) {
                  collectMutation.mutate(record.source);
                }
              }}
            >
              {t("重采集")}</Button>
          ) : null}
        </Space>
      )
    }
  ];

  return (
    <Space className="page-stack" orientation="vertical" size={16}>
      {contextHolder}
      <PageHeader
        title={t("任务中心")}
        extra={
          <Space wrap>
            <Button
              icon={<RefreshCw size={16} />}
              onClick={() => {
                void summaryQuery.refetch();
                void itemsQuery.refetch();
              }}
              loading={summaryQuery.isFetching || itemsQuery.isFetching}
            >
              {t("刷新")}</Button>
          </Space>
        }
      />

      <Row gutter={[16, 16]}>
        <Col xs={24} lg={6}>
          <Card className="metric-card">
            <Statistic
              title={t("任务条目")}
              value={summary?.total ?? localMetrics.total}
              prefix={<ListChecks size={28} />}
            />
          </Card>
        </Col>
        <Col xs={24} lg={6}>
          <Card className="metric-card">
            <Statistic
              title={t("待处理")}
              value={summary?.pending ?? localMetrics.pending}
              prefix={<PlayCircle size={28} />}
            />
          </Card>
        </Col>
        <Col xs={24} lg={6}>
          <Card className="metric-card metric-card-green">
            <Statistic
              title={t("运行中")}
              value={summary?.running ?? localMetrics.running}
              prefix={<RefreshCw size={28} />}
            />
          </Card>
        </Col>
        <Col xs={24} lg={6}>
          <Card className="metric-card metric-card-red">
            <Statistic
              title={t("失败/需关注")}
              value={(summary?.failed ?? localMetrics.failed) + (summary?.attention ?? localMetrics.attention)}
              prefix={<ShieldAlert size={28} />}
            />
          </Card>
        </Col>
      </Row>

      <Card className="content-card filter-card">
        <Form
          form={form}
          layout="inline"
          initialValues={defaultFilters}
          onFinish={(values) => setFilters(normalizeFilters(values))}
        >
          <Form.Item label={t("类型")} name="item_type">
            <Select allowClear options={itemTypeOptions} placeholder={t("全部类型")} />
          </Form.Item>
          <Form.Item label={t("状态组")} name="status_group">
            <Select allowClear options={statusGroupOptions} placeholder={t("全部状态组")} />
          </Form.Item>
          <Form.Item label={t("原始状态")} name="status">
            <Input placeholder="queued / affected" />
          </Form.Item>
          <Form.Item label={t("来源")} name="source">
            <Select allowClear options={sourceOptions} placeholder={t("全部来源")} />
          </Form.Item>
          <Form.Item label={t("触发")} name="trigger_type">
            <Select allowClear options={triggerOptions} placeholder={t("全部触发")} />
          </Form.Item>
          <Form.Item label={t("关键字")} name="keyword">
            <Input placeholder={t("任务、资产、漏洞、Agent")} />
          </Form.Item>
          <Form.Item label={t("返回数量")} name="limit">
            <InputNumber min={1} max={500} />
          </Form.Item>
          <Form.Item>
            <Space>
              <Button
                onClick={() => {
                  form.resetFields();
                  setFilters(defaultFilters);
                }}
              >
                {t("重置")}</Button>
              <Button type="primary" htmlType="submit">
                {t("查询")}</Button>
            </Space>
          </Form.Item>
        </Form>
      </Card>

      <Card className="content-card" title={t("任务条目")}>
        {summaryQuery.isError ? <ErrorState title={t("任务统计加载失败")} error={summaryQuery.error} /> : null}
        {itemsQuery.isError ? <ErrorState error={itemsQuery.error} /> : null}
        <ResizableTable<TaskCenterItem>
          storageKey="task-center-items"
          rowKey="id"
          columns={columns}
          dataSource={rows}
          loading={
            itemsQuery.isFetching ||
            cancelMutation.isPending ||
            retryMutation.isPending ||
            createVerificationMutation.isPending ||
            reevaluateMutation.isPending
          }
          pagination={{ pageSize: 10, showSizeChanger: true }}
          locale={{
            emptyText: (
              <EmptyState title={t("暂无任务条目")}>
                <Button type="primary" onClick={() => navigate("/risk-queue")}>
                  {t("去风险队列")}</Button>
              </EmptyState>
            )
          }}
          scroll={{ x: 2180 }}
        />
      </Card>
    </Space>
  );
}
