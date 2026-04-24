import { Suspense, lazy, useEffect, useState } from 'react';
import type { AdminSnapshot } from '../shared/types';
import { apiRequest } from './api';

const AnalyticsSection = lazy(() => import('./AnalyticsSection'));

const STORAGE_KEYS = {
  adminSession: 'nct-api-sql-admin-session',
  ingest: 'nct-api-sql-ingest-token',
} as const;

type AdminAuthStatus = {
  configured: boolean;
};

type AdminAuthResponse = AdminAuthStatus & {
  expiresAt: string;
  sessionToken: string;
};

const sampleIngestPayload = JSON.stringify(
  {
    records: [
      {
        recordKey: 'patient-1001',
        source: 'hospital-a',
        encryptFields: ['name', 'phone', 'email'],
        payload: {
          id: 'patient-1001',
          name: 'Zhang San',
          phone: '13800000000',
          email: 'demo@example.com',
          city: 'Shanghai',
          score: 91,
          category: 'A',
        },
      },
    ],
  },
  null,
  2,
);

function truncate(
  value: string,
  limit = 72,
): string {
  if (value.length <= limit) {
    return value;
  }

  return `${value.slice(0, limit)}...`;
}

function toPrettyJson(value: unknown): string {
  return JSON.stringify(value, null, 2);
}

function MetricCard(props: {
  label: string;
  value: number | string;
  helper: string;
}) {
  return (
    <article className="metric-card glass-panel">
      <span className="metric-label">{props.label}</span>
      <strong className="metric-value">{props.value}</strong>
      <p className="metric-helper">{props.helper}</p>
    </article>
  );
}

function SectionTitle(props: {
  eyebrow: string;
  title: string;
  description: string;
}) {
  return (
    <div className="section-title">
      <span className="eyebrow">{props.eyebrow}</span>
      <h2>{props.title}</h2>
      <p>{props.description}</p>
    </div>
  );
}

function TableBlock(props: {
  title: string;
  columns: string[];
  rows: Array<string[]>;
}) {
  return (
    <section className="glass-panel table-panel">
      <div className="table-heading">
        <h3>{props.title}</h3>
        <span>{props.rows.length} rows</span>
      </div>
      <div className="table-scroll">
        <table>
          <thead>
            <tr>
              {props.columns.map((column) => (
                <th key={column}>{column}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {props.rows.length ? (
              props.rows.map((row, rowIndex) => (
                <tr key={`${props.title}-${rowIndex}`}>
                  {row.map((cell, cellIndex) => (
                    <td key={`${rowIndex}-${cellIndex}`}>
                      <span title={cell}>{cell}</span>
                    </td>
                  ))}
                </tr>
              ))
            ) : (
              <tr>
                <td colSpan={props.columns.length} className="empty-cell">
                  No rows yet.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </section>
  );
}

export default function App() {
  const [snapshot, setSnapshot] = useState<AdminSnapshot | null>(null);
  const [loading, setLoading] = useState(true);
  const [busyAction, setBusyAction] = useState<string | null>(null);
  const [message, setMessage] = useState<string>('Console ready.');
  const [error, setError] = useState<string | null>(null);
  const [adminConfigured, setAdminConfigured] = useState<boolean | null>(null);
  const [adminPassword, setAdminPassword] = useState('');
  const [adminSessionToken, setAdminSessionToken] = useState(
    () => localStorage.getItem(STORAGE_KEYS.adminSession) ?? '',
  );
  const [ingestToken, setIngestToken] = useState(
    () => localStorage.getItem(STORAGE_KEYS.ingest) ?? '',
  );
  const [ingestPayload, setIngestPayload] = useState(sampleIngestPayload);

  async function loadSnapshot(token = adminSessionToken) {
    if (!token) {
      setSnapshot(null);
      setLoading(false);
      if (adminConfigured) {
        setError('Log in to load the admin snapshot.');
      }
      return;
    }

    setLoading(true);
    setError(null);

    try {
      const nextSnapshot = await apiRequest<AdminSnapshot>(
        '/api/admin/snapshot',
        {
          token,
        },
      );
      setSnapshot(nextSnapshot);
    } catch (loadError) {
      const nextError =
        loadError instanceof Error ? loadError.message : 'Failed to load data.';
      setError(nextError);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    localStorage.setItem(STORAGE_KEYS.adminSession, adminSessionToken);
  }, [adminSessionToken]);

  useEffect(() => {
    localStorage.setItem(STORAGE_KEYS.ingest, ingestToken);
  }, [ingestToken]);

  useEffect(() => {
    async function initializeConsole() {
      setLoading(true);
      setError(null);

      try {
        const status = await apiRequest<AdminAuthStatus>('/api/admin/auth/status');
        setAdminConfigured(status.configured);

        if (!status.configured) {
          setSnapshot(null);
          setMessage('Set the first admin password to initialize Console access.');
          return;
        }

        if (adminSessionToken) {
          await loadSnapshot(adminSessionToken);
          return;
        }

        setSnapshot(null);
        setMessage('Log in to load the admin snapshot.');
      } catch (initializeError) {
        const nextError =
          initializeError instanceof Error
            ? initializeError.message
            : 'Failed to initialize Console.';
        setError(nextError);
      } finally {
        setLoading(false);
      }
    }

    void initializeConsole();
  }, []);

  async function handleAdminAuthSubmit(
    event: React.FormEvent<HTMLFormElement>,
  ) {
    event.preventDefault();
    await runAction(adminConfigured ? 'Login' : 'Setup admin password', async () => {
      const response = await apiRequest<AdminAuthResponse>(
        adminConfigured ? '/api/admin/auth/login' : '/api/admin/auth/setup',
        {
          method: 'POST',
          body: {
            password: adminPassword,
          },
        },
      );

      setAdminConfigured(true);
      setAdminPassword('');
      setAdminSessionToken(response.sessionToken);
      setMessage(`Admin session active until ${response.expiresAt}.`);
      await loadSnapshot(response.sessionToken);
    });
  }

  async function handleLogout() {
    const token = adminSessionToken;
    setAdminSessionToken('');
    setSnapshot(null);
    setMessage('Logged out.');
    if (!token) {
      return;
    }

    try {
      await apiRequest<null>('/api/admin/auth/logout', {
        method: 'POST',
        token,
      });
    } catch (_error) {
      // Local logout should still complete if the server session has already expired.
    }
  }

  async function runAction(
    actionName: string,
    task: () => Promise<void>,
  ) {
    setBusyAction(actionName);
    setError(null);

    try {
      await task();
    } catch (taskError) {
      const nextError =
        taskError instanceof Error ? taskError.message : 'Action failed.';
      setError(nextError);
      setMessage(`${actionName} failed.`);
    } finally {
      setBusyAction(null);
    }
  }

  async function handleIngestSubmit(
    event: React.FormEvent<HTMLFormElement>,
  ) {
    event.preventDefault();
    await runAction('Ingest', async () => {
      const parsedBody = JSON.parse(ingestPayload);
      const response = await apiRequest<{
        updatedCount: number;
      }>('/api/ingest', {
        method: 'POST',
        token: ingestToken || adminSessionToken || undefined,
        body: parsedBody,
      });
      setMessage(`Ingest completed. ${response.updatedCount} record(s) changed.`);
      await loadSnapshot();
    });
  }

  async function handleRebuild() {
    await runAction('Rebuild', async () => {
      const response = await apiRequest<{
        processed: number;
        updated: number;
      }>('/api/admin/rebuild-secure', {
        method: 'POST',
        token: adminSessionToken || undefined,
      });
      setMessage(
        `Rebuild completed. processed=${response.processed}, updated=${response.updated}.`,
      );
      await loadSnapshot();
    });
  }

  async function handleExport() {
    await runAction('Export', async () => {
      const response = await apiRequest<{
        objectKey: string;
        emailStatus: string;
      }>('/api/admin/export-now', {
        method: 'POST',
        token: adminSessionToken || undefined,
      });
      setMessage(
        `Export archived to ${response.objectKey}. Email=${response.emailStatus}.`,
      );
    });
  }

  async function handlePullNow() {
    await runAction('Recovery pull', async () => {
      const response = await apiRequest<{
        totalTargets: number;
        pulledTargets: number;
      }>('/api/admin/pull-now', {
        method: 'POST',
        token: adminSessionToken || undefined,
      });
      setMessage(
        `Recovery pull completed. targets=${response.totalTargets}, pulled=${response.pulledTargets}.`,
      );
      await loadSnapshot();
    });
  }

  const overview = snapshot?.overview;
  const rawRows =
    snapshot?.rawRecords.map((record) => [
      record.recordKey,
      record.source,
      truncate(record.receivedAt, 30),
      truncate(toPrettyJson(record.payload), 120),
      truncate(toPrettyJson(record.payloadColumns), 120),
    ]) ?? [];

  const secureRows =
    snapshot?.secureRecords.map((record) => [
      record.recordKey,
      String(record.version),
      record.encryptFields.join(', ') || 'none',
      truncate(toPrettyJson(record.publicData), 100),
      truncate(toPrettyJson(record.publicColumns), 100),
      truncate(toPrettyJson(record.encryptedColumns), 100),
    ]) ?? [];

  const downstreamRows =
    snapshot?.downstreamClients.map((client) => [
      client.entryKind,
      client.clientName ?? 'anonymous',
      client.callbackUrl,
      String(client.databackVersion ?? client.clientVersion),
      String(client.lastSyncVersion),
      client.lastPushAt ?? '-',
      client.reportedAt ?? client.lastSeenAt,
      client.lastStatus,
      client.reportCount === null ? '-' : String(client.reportCount),
    ]) ?? [];

  return (
    <div className="app-shell">
      <div className="bg-orb orb-a" />
      <div className="bg-orb orb-b" />
      <div className="bg-orb orb-c" />

      <header className="hero glass-panel">
        <div className="hero-copy">
          <span className="eyebrow">Cloudflare Workers + D1 + R2</span>
          <h1>NCT API SQL Console</h1>
          <p>
            单个 Worker 承载数据接收、加密处理、版本同步、R2 归档与
            React 管理台。页面内直接支持数据库查看、分析、同步调试和导出触发。
          </p>
        </div>
        <div className="hero-actions">
          <form className="token-grid" onSubmit={handleAdminAuthSubmit}>
            <label className="token-field">
              <span>{adminConfigured ? 'Admin password' : 'Set admin password'}</span>
              <input
                type="password"
                value={adminPassword}
                onChange={(event) => setAdminPassword(event.target.value)}
                placeholder={
                  adminConfigured
                    ? 'Log in to manage data'
                    : 'At least 12 characters'
                }
              />
            </label>
            <label className="token-field">
              <span>Ingest token</span>
              <input
                type="password"
                value={ingestToken}
                onChange={(event) => setIngestToken(event.target.value)}
                placeholder="Optional external ingest token"
              />
            </label>
            <label className="token-field">
              <span>Admin session</span>
              <input
                value={
                  adminSessionToken
                    ? 'Active'
                    : adminConfigured === false
                      ? 'Password not set'
                      : 'Login required'
                }
                readOnly
                placeholder="Login required"
              />
            </label>
            <div className="auth-actions">
              <button
                type="submit"
                className="primary-button"
                disabled={busyAction !== null || !adminPassword || adminConfigured === null}
              >
                {adminConfigured ? 'Log in' : 'Set password'}
              </button>
              <button
                type="button"
                className="secondary-button"
                onClick={() => void handleLogout()}
                disabled={!adminSessionToken || busyAction !== null}
              >
                Log out
              </button>
            </div>
          </form>
          <div className="action-row">
            <button
              type="button"
              className="primary-button"
              onClick={() => void loadSnapshot()}
              disabled={loading || busyAction !== null || !adminSessionToken}
            >
              {loading ? 'Refreshing...' : 'Refresh snapshot'}
            </button>
            <button
              type="button"
              className="secondary-button"
              onClick={() => void handleRebuild()}
              disabled={busyAction !== null || !adminSessionToken}
            >
              Rebuild secure table
            </button>
            <button
              type="button"
              className="secondary-button"
              onClick={() => void handleExport()}
              disabled={busyAction !== null || !adminSessionToken}
            >
              Export + email
            </button>
            <button
              type="button"
              className="secondary-button"
              onClick={() => void handlePullNow()}
              disabled={busyAction !== null || !adminSessionToken}
            >
              Recovery pull from subs
            </button>
          </div>
          <div className="status-strip">
            <span className={error ? 'status-badge danger' : 'status-badge'}>
              {busyAction ? `${busyAction} running` : 'Idle'}
            </span>
            <p>{error ?? message}</p>
          </div>
        </div>
      </header>

      <main className="content-grid">
        <section className="metric-grid">
          <MetricCard
            label="Raw records"
            value={overview?.totals.rawRecords ?? 0}
            helper="未加密原始表"
          />
          <MetricCard
            label="Secure records"
            value={overview?.totals.secureRecords ?? 0}
            helper="部分列加密后供子库主动拉取"
          />
          <MetricCard
            label="Third table rows"
            value={overview?.totals.downstreamClients ?? 0}
            helper="记录子库上报与最近恢复状态"
          />
          <MetricCard
            label="Current version"
            value={overview?.totals.currentVersion ?? 0}
            helper="以 secure table 的最大版本号为准"
          />
        </section>

        <Suspense
          fallback={
            <section className="glass-panel analytics-panel loading-panel">
              <SectionTitle
                eyebrow="Analysis"
                title="数据分析与可视化"
                description="图表模块正在加载。"
              />
            </section>
          }
        >
          <AnalyticsSection overview={overview} />
        </Suspense>

        <section className="glass-panel form-panel">
          <SectionTitle
            eyebrow="Debug"
            title="数据写入与灾备调试"
            description="直接验证 ingest、加密构建，以及从已登记子库执行一次手动恢复回拉。"
          />
          <div className="form-grid">
            <form className="action-form" onSubmit={handleIngestSubmit}>
              <h3>POST /api/ingest</h3>
              <textarea
                value={ingestPayload}
                onChange={(event) => setIngestPayload(event.target.value)}
                spellCheck={false}
              />
              <button
                type="submit"
                className="primary-button"
                disabled={busyAction !== null || (!ingestToken && !adminSessionToken)}
              >
                Send ingest
              </button>
            </form>

            <div className="action-form">
              <h3>POST /api/admin/pull-now</h3>
              <p>
                `nct-api-sql-sub` 会按自己的计划主动拉取主库公开数据并定时上报。
                这里保留的接口只用于灾备演练或母库恢复时，从已登记子库手动回拉最新
                `nct_databack`。
              </p>
              <button
                type="button"
                className="primary-button"
                onClick={() => void handlePullNow()}
                disabled={busyAction !== null || !adminSessionToken}
              >
                Trigger recovery pull
              </button>
            </div>
          </div>
        </section>

        <section className="table-grid">
          <TableBlock
            title="Raw table"
            columns={['recordKey', 'source', 'receivedAt', 'payload', 'payloadColumns']}
            rows={rawRows}
          />
          <TableBlock
            title="Secure table"
            columns={['recordKey', 'version', 'encryptFields', 'publicData', 'publicColumns', 'encryptedColumns']}
            rows={secureRows}
          />
          <TableBlock
            title="Third table"
            columns={['entryKind', 'name', 'url', 'reportedVersion', 'lastPushedVersion', 'lastPushAt', 'reportedAt', 'status', 'reportCount']}
            rows={downstreamRows}
          />
        </section>
      </main>
    </div>
  );
}
