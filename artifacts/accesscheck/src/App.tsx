import { useEffect, useMemo, useState, type FormEvent, type ReactNode } from 'react';
import { QueryClient, QueryClientProvider, useQueryClient } from '@tanstack/react-query';
import { Link, Route, Switch, useLocation, useParams, Router as WouterRouter } from 'wouter';
import { Bar, BarChart, CartesianGrid, Cell, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts';
import {
  Activity, ArrowDownToLine, ArrowLeftRight, ArrowRight, ArrowUpRight, Check, ChevronDown, CircleAlert,
  Clock3, Code2, ExternalLink, FileSearch, Filter, Gauge, Globe2, History, Layers3, LoaderCircle,
  Menu, Printer, RotateCw, Search, ShieldCheck, SlidersHorizontal, Sparkles,
} from 'lucide-react';
import {
  getExportScanCsvQueryKey, getGetDashboardQueryKey, getGetScanQueryKey, getHealthCheckQueryKey,
  getListScansQueryKey, useCreateScan, useExportScanCsv, useGetDashboard, useGetScan, useHealthCheck,
  useListScans,
} from '@workspace/api-client-react';
import type { Finding, FindingImpact, ScanSummary } from '@workspace/api-client-react';
import NotFound from '@/pages/not-found';
import { ErrorBoundary } from '@/components/error-boundary';
import { Toaster } from '@/components/ui/toaster';
import { TooltipProvider } from '@/components/ui/tooltip';

const queryClient = new QueryClient();
const severityOrder: FindingImpact[] = ['critical', 'serious', 'moderate', 'minor'];
const severityNames: Record<FindingImpact, string> = {
  critical: 'Critical', serious: 'Serious', moderate: 'Moderate', minor: 'Minor',
};
const severityColors: Record<FindingImpact, string> = {
  critical: 'severity-critical', serious: 'severity-serious', moderate: 'severity-moderate', minor: 'severity-minor',
};

function Shell({ children }: { children: ReactNode }) {
  const [location] = useLocation();
  const [menuOpen, setMenuOpen] = useState(false);
  const active = location === '/' ? 'dashboard' : location.startsWith('/history') ? 'history' : 'report';
  return <div className="app-frame">
    <aside className={`sidebar no-print ${menuOpen ? 'sidebar-open' : ''}`}>
      <div className="brand"><span className="brand-mark"><ShieldCheck size={20} strokeWidth={2.2} /></span><span>access<span className="brand-light">check</span></span></div>
      <div className="workspace-label">WORKSPACE</div>
      <nav aria-label="Main navigation" className="side-nav">
        <Link href="/" className={`nav-item ${active === 'dashboard' ? 'nav-active' : ''}`} data-testid="link-dashboard" onClick={() => setMenuOpen(false)}><Gauge size={17} /> Scan dashboard</Link>
        <Link href="/history" className={`nav-item ${active === 'history' ? 'nav-active' : ''}`} data-testid="link-history" onClick={() => setMenuOpen(false)}><History size={17} /> Scan history</Link>
      </nav>
      <div className="sidebar-bottom">
        <div className="side-note"><span className="note-icon"><Code2 size={16} /></span><div><strong>Evidence, not a score.</strong><p>Automated checks help you find issues. They cannot certify conformance.</p></div></div>
        <div className="sidebar-foot"><span className="status-dot"></span> Accessibility insights <span className="mono">v1.0</span></div>
      </div>
    </aside>
    <div className="app-main">
      <header className="topbar no-print">
        <button className="mobile-menu icon-button" aria-label="Open navigation" onClick={() => setMenuOpen(!menuOpen)} data-testid="button-menu"><Menu size={19}/></button>
        <div className="crumb"><span>AccessCheck</span><span className="crumb-sep">/</span><span>{active === 'dashboard' ? 'Dashboard' : active === 'history' ? 'History' : 'Scan report'}</span></div>
        <div className="topbar-right"><span className="live-indicator"><span className="status-dot"></span> Automated checks</span><span className="topbar-divider"></span><span className="quiet-label">axe-core engine</span></div>
      </header>
      <main className="main-content page-enter">
        {children}
      </main>
      <footer className="app-footer"><span>AccessCheck</span><span>Automated testing is one part of accessibility review. Manual testing is still needed.</span></footer>
    </div>
  </div>;
}

function LoadingLine() { return <div className="loading-panel" role="status" aria-label="Loading"><div className="skeleton wide"/><div className="skeleton"/><div className="skeleton short"/></div>; }
function ErrorPanel({ message, retry }: { message: string; retry: () => void }) {
  return <div className="error-panel" role="alert"><CircleAlert size={19}/><div><strong>We couldn't load this data</strong><p>{message}</p><button className="text-button" onClick={retry} data-testid="button-retry"><RotateCw size={14}/> Try again</button></div></div>;
}
function PageTitle({ eyebrow, title, description, children }: { eyebrow: string; title: string; description: string; children?: ReactNode }) {
  return <div className="page-heading"><div><div className="eyebrow">{eyebrow}</div><h1>{title}</h1><p>{description}</p></div>{children && <div className="heading-actions">{children}</div>}</div>;
}
function StatusTag({ status }: { status: string }) {
  return <span className={`status-tag ${status === 'completed' ? 'status-complete' : 'status-failed'}`}><span className="status-dot"/>{status === 'completed' ? 'Complete' : 'Failed'}</span>;
}
function CountBadge({ impact, count }: { impact: FindingImpact; count: number }) {
  return <span className={`count-badge ${severityColors[impact]}`}><i/> {count} {severityNames[impact].toLowerCase()}</span>;
}
function formatDate(value: string) {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : new Intl.DateTimeFormat(undefined, { month: 'short', day: 'numeric', year: 'numeric', hour: 'numeric', minute: '2-digit' }).format(date);
}
function shortenUrl(url: string) {
  try { const parsed = new URL(url); return `${parsed.hostname}${parsed.pathname === '/' ? '' : parsed.pathname}`; } catch { return url; }
}
function SummaryRow({ scan }: { scan: ScanSummary }) {
  return <Link href={`/scans/${scan.id}`} className="scan-row" data-testid={`link-scan-${scan.id}`}>
    <div className="scan-site-mark"><Globe2 size={16}/></div>
    <div className="scan-row-main"><strong>{scan.title || scan.domain}</strong><span className="scan-url">{shortenUrl(scan.url)}</span></div>
    <div className="scan-row-count"><strong>{scan.violationCount}</strong><span>findings</span></div>
    <div className="scan-row-severity">{severityOrder.map((impact) => scan[`${impact}Count` as 'criticalCount'] > 0 && <span key={impact} className={`mini-severity ${severityColors[impact]}`} title={`${scan[`${impact}Count` as 'criticalCount']} ${impact}`}>{scan[`${impact}Count` as 'criticalCount']}</span>)}</div>
    <StatusTag status={scan.status}/><time>{formatDate(scan.createdAt)}</time><ArrowUpRight className="row-arrow" size={16}/>
  </Link>;
}

function Dashboard() {
  const [url, setUrl] = useState('');
  const [formError, setFormError] = useState('');
  const [, setLocation] = useLocation();
  const queryClient = useQueryClient();
  const health = useHealthCheck({ query: { queryKey: getHealthCheckQueryKey(), refetchInterval: 60000 } });
  const dashboard = useGetDashboard({ query: { queryKey: getGetDashboardQueryKey() } });
  const scans = useListScans({ limit: 6 }, { query: { queryKey: getListScansQueryKey({ limit: 6 }) } });
  const createScan = useCreateScan();
  const isHealthy = health.data?.status === 'ok' || health.data?.status === 'healthy';
  const submit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setFormError('');
    let parsed: URL;
    try { parsed = new URL(url.trim()); } catch { setFormError('Enter a complete URL, including https://'); return; }
    if (!['http:', 'https:'].includes(parsed.protocol)) { setFormError('Use a website URL that begins with http:// or https://'); return; }
    createScan.mutate({ data: { url: parsed.toString() } }, {
      onSuccess: (scan) => {
        void queryClient.invalidateQueries({ queryKey: getGetDashboardQueryKey() });
        void queryClient.invalidateQueries({ queryKey: getListScansQueryKey({ limit: 6 }) });
        void queryClient.invalidateQueries({ queryKey: getListScansQueryKey() });
        setLocation(`/scans/${scan.id}`);
      },
      onError: (error) => setFormError(error instanceof Error ? error.message : 'The scan could not be started. Please try again.'),
    });
  };
  return <div className="page-stack">
    <PageTitle eyebrow="ACCESSIBILITY AUDIT" title="Scan dashboard" description="Run an automated review and inspect the evidence behind every finding."/>
    <section className="scan-hero">
      <div className="hero-copy"><div className="hero-kicker"><span className="hero-pulse"></span> NEW AUTOMATED SCAN</div><h2>Start with a URL.<br/><em>Find what gets in the way.</em></h2><p>AccessCheck examines a single page for common accessibility issues using axe-core.</p></div>
      <form className="scan-form" onSubmit={submit} noValidate>
        <label htmlFor="scan-url">Page URL</label>
        <div className={`url-input-wrap ${formError ? 'input-invalid' : ''}`}><Globe2 size={18}/><input id="scan-url" type="url" placeholder="https://yourwebsite.com" value={url} onChange={(e) => { setUrl(e.target.value); if (formError) setFormError(''); }} aria-describedby="url-help url-error" data-testid="input-scan-url" required/><button type="submit" className="primary-button" disabled={createScan.isPending} data-testid="button-start-scan">{createScan.isPending ? <><LoaderCircle className="spin" size={16}/> Scanning</> : <>Run scan <ArrowRight size={16}/></>}</button></div>
        <div className="form-foot"><span id="url-help">One page per scan · HTTPS recommended</span><span className="connection"><span className={`status-dot ${health.isError ? 'dot-error' : ''}`}></span>{health.isLoading ? 'Checking engine…' : health.isError ? 'Engine status unavailable' : isHealthy ? 'Scan engine ready' : 'Engine status: ' + (health.data?.status ?? 'unknown')}</span></div>
        {formError && <p id="url-error" className="form-error" role="alert">{formError}</p>}
        {createScan.isPending && <div className="pending-note" role="status"><span className="pending-orbit"/><span><strong>Scan in progress</strong><br/>Loading the page and evaluating automated rules. This may take a moment.</span></div>}
      </form>
      <div className="hero-index" aria-hidden="true">01 <span/> 03</div>
    </section>
    <section aria-label="Workspace scan totals">
      <div className="section-heading"><div><div className="eyebrow">YOUR WORKSPACE</div><h2>At a glance</h2></div><span className="data-caption"><Activity size={14}/> From saved scans</span></div>
      {dashboard.isLoading ? <div className="stats-grid"><div className="stat-skeleton"/><div className="stat-skeleton"/><div className="stat-skeleton"/></div> : dashboard.isError ? <ErrorPanel message="Dashboard totals are temporarily unavailable." retry={() => void dashboard.refetch()}/> : <div className="stats-grid" data-testid="dashboard-stats">
        <StatCard label="Saved scans" value={dashboard.data?.totalScans ?? 0} icon={<FileSearch size={17}/>} note="All pages checked"/>
        <StatCard label="Automated findings" value={dashboard.data?.totalViolations ?? 0} icon={<Layers3 size={17}/>} note="Across saved scans"/>
        <StatCard label="Critical findings" value={dashboard.data?.severityCounts.critical ?? 0} icon={<CircleAlert size={17}/>} note="Review these first" alert/>
      </div>}
    </section>
    {!dashboard.isLoading && !dashboard.isError && dashboard.data && <SeverityChart counts={dashboard.data.severityCounts}/>}
    <section className="recent-section">
      <div className="section-heading"><div><div className="eyebrow">RECENT ACTIVITY</div><h2>Latest scans</h2></div><Link href="/history" className="inline-link" data-testid="link-all-history">View scan history <ArrowRight size={15}/></Link></div>
      {scans.isLoading ? <LoadingLine/> : scans.isError ? <ErrorPanel message="Recent scans are temporarily unavailable." retry={() => void scans.refetch()}/> : scans.data?.length ? <div className="scan-list">{scans.data.map((scan) => <SummaryRow key={scan.id} scan={scan}/>)}</div> : <EmptyState title="No scans saved yet" body="Submit a page URL above to run your first automated scan. Findings and scan evidence will appear here."/>}
    </section>
    <div className="disclaimer"><ShieldCheck size={17}/><p><strong>What this scan can tell you.</strong> Automated checks identify detectable issues on the page at scan time. They do not determine whether a site conforms to WCAG or accessibility law. Manual testing with assistive technology and human review is still needed.</p></div>
  </div>;
}

function StatCard({ label, value, icon, note, alert = false }: { label: string; value: number; icon: ReactNode; note: string; alert?: boolean }) {
  return <article className={`stat-card ${alert ? 'stat-alert' : ''}`}><div className="stat-top"><span>{label}</span><span className="stat-icon">{icon}</span></div><div className="stat-value" data-testid={`value-${label.toLowerCase().replaceAll(' ', '-')}`}>{value.toLocaleString()}</div><div className="stat-note">{note}</div></article>;
}
function SeverityChart({ counts }: { counts: { critical: number; serious: number; moderate: number; minor: number } }) {
  const data = severityOrder.map((impact) => ({
    impact,
    name: severityNames[impact],
    count: counts[impact],
  }));
  const colors: Record<FindingImpact, string> = {
    critical: '#a94d45',
    serious: '#a86634',
    moderate: '#88722e',
    minor: '#557c82',
  };
  const hasFindings = data.some((item) => item.count > 0);
  return <section className="severity-chart-card" aria-label="Saved findings by severity" data-testid="chart-severity-breakdown">
    <div className="severity-chart-heading">
      <div><div className="eyebrow">SAVED SCANS</div><h3>Findings by severity</h3></div>
      <span className="data-caption">Completed scans only</span>
    </div>
    {hasFindings ? <div className="severity-chart-plot" role="img" aria-label={data.map((item) => `${item.name}: ${item.count}`).join(', ')}>
      <ResponsiveContainer width="100%" height="100%">
        <BarChart data={data} margin={{ top: 8, right: 8, left: -18, bottom: 0 }}>
          <CartesianGrid vertical={false} stroke="#e8e3d8" strokeDasharray="3 4" />
          <XAxis dataKey="name" tick={{ fill: '#738078', fontSize: 11 }} axisLine={false} tickLine={false} />
          <YAxis allowDecimals={false} width={34} tick={{ fill: '#899389', fontSize: 10 }} axisLine={false} tickLine={false} />
          <Tooltip cursor={{ fill: '#edf1e9' }} />
          <Bar dataKey="count" name="Findings" radius={[4, 4, 0, 0]} maxBarSize={42}>
            {data.map((item) => <Cell key={item.impact} fill={colors[item.impact]} />)}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div> : <div className="severity-chart-empty">
      <span className="data-caption">No automated violations recorded in completed scans yet.</span>
    </div>}
    <ul className="sr-only">{data.map((item) => <li key={item.impact}>{item.name}: {item.count}</li>)}</ul>
  </section>;
}
function EmptyState({ title, body }: { title: string; body: string }) {
  return <div className="empty-state"><div className="empty-icon"><FileSearch size={23}/></div><h3>{title}</h3><p>{body}</p></div>;
}

function HistoryPage() {
  const { data, isLoading, isError, refetch } = useListScans(undefined, { query: { queryKey: getListScansQueryKey() } });
  const [search, setSearch] = useState('');
  const [severity, setSeverity] = useState('all');
  const [selected, setSelected] = useState<string[]>([]);
  const filtered = useMemo(() => (data ?? []).filter((scan) => {
    const matchesText = `${scan.url} ${scan.title} ${scan.domain}`.toLowerCase().includes(search.toLowerCase());
    const matchesSeverity = severity === 'all' || scan[`${severity}Count` as 'criticalCount'] > 0;
    return matchesText && matchesSeverity;
  }), [data, search, severity]);
  const selectedScans = (data ?? []).filter((scan) => selected.includes(scan.id)).slice(0, 2);
  const toggle = (id: string) => setSelected((prev) => prev.includes(id) ? prev.filter((key) => key !== id) : prev.length >= 2 ? [prev[1], id] : [...prev, id]);
  return <div className="page-stack">
    <PageTitle eyebrow="YOUR WORKSPACE" title="Scan history" description="Revisit saved page scans and compare evidence over time.">
      <button className="secondary-button" onClick={() => void refetch()} data-testid="button-refresh-history"><RotateCw size={15}/> Refresh</button>
    </PageTitle>
    <div className="history-tools">
      <label className="search-field"><Search size={17}/><input type="search" value={search} onChange={(e) => setSearch(e.target.value)} placeholder="Search URL or page title" aria-label="Search scans" data-testid="input-history-search"/></label>
      <label className="filter-select"><SlidersHorizontal size={16}/><span className="sr-only">Filter by severity</span><select value={severity} onChange={(e) => setSeverity(e.target.value)} data-testid="select-severity-filter"><option value="all">All severities</option>{severityOrder.map((impact) => <option key={impact} value={impact}>{severityNames[impact]}</option>)}</select><ChevronDown size={14}/></label>
    </div>
    {isLoading ? <LoadingLine/> : isError ? <ErrorPanel message="Saved scan history could not be loaded." retry={() => void refetch()}/> : !data?.length ? <EmptyState title="Your history starts here" body="Completed and failed scans are saved here. Run a scan from the dashboard to begin building a useful record."/> : <>
      <div className="history-summary"><span><strong>{filtered.length}</strong> {filtered.length === 1 ? 'scan' : 'scans'} shown</span><span>Select up to two scans to compare their recorded findings.</span></div>
      {filtered.length ? <div className="history-table">
        <div className="history-table-head"><span>PAGE</span><span>FINDINGS</span><span>STATUS</span><span>SCANNED</span><span className="compare-label">COMPARE</span></div>
        {filtered.map((scan) => <div className="history-row" key={scan.id} data-testid={`row-history-${scan.id}`}>
          <Link href={`/scans/${scan.id}`} className="history-page-link"><span className="scan-site-mark"><Globe2 size={15}/></span><span><strong>{scan.title || scan.domain}</strong><small>{shortenUrl(scan.url)}</small></span><ArrowUpRight size={14}/></Link>
          <div className="history-count"><strong>{scan.violationCount}</strong><small>total</small><div>{severityOrder.filter((impact) => scan[`${impact}Count` as 'criticalCount'] > 0).map((impact) => <span key={impact} className={`mini-severity ${severityColors[impact]}`}>{scan[`${impact}Count` as 'criticalCount']}</span>)}</div></div>
          <StatusTag status={scan.status}/><time className="history-time">{formatDate(scan.createdAt)}</time>
          <label className="compare-check"><input type="checkbox" checked={selected.includes(scan.id)} onChange={() => toggle(scan.id)} aria-label={`Select ${scan.title || scan.domain} for comparison`} data-testid={`checkbox-compare-${scan.id}`}/><span>Select</span></label>
        </div>)}
      </div> : <EmptyState title="No scans match those filters" body="Try a different search or severity. Your saved scan records have not changed."/>}
      {selectedScans.length === 2 && <Comparison scans={selectedScans}/>}
    </>}
    <div className="disclaimer"><ShieldCheck size={17}/><p><strong>Compare carefully.</strong> Scan results describe automated checks on the page at the time of each scan. Differences can reflect changed content, page state, or scan conditions—not a conformance rating.</p></div>
  </div>;
}

function Comparison({ scans }: { scans: ScanSummary[] }) {
  return <section className="compare-panel" aria-label="Scan comparison" data-testid="comparison-panel">
    <div className="compare-title"><div><div className="eyebrow">SIDE-BY-SIDE</div><h2><ArrowLeftRight size={19}/> Scan comparison</h2></div><span>Recorded issue counts</span></div>
    <div className="compare-sites">{scans.map((scan) => <div className="compare-site" key={scan.id}><span className="mono">{formatDate(scan.createdAt)}</span><strong>{scan.title || scan.domain}</strong><small>{shortenUrl(scan.url)}</small></div>)}</div>
    <div className="compare-matrix"><div className="matrix-heading"><span>Severity</span>{scans.map((scan) => <span key={scan.id}>{scan.domain}</span>)}</div>
      {severityOrder.map((impact) => <div className="matrix-row" key={impact}><span><i className={`matrix-dot ${severityColors[impact]}`}/>{severityNames[impact]}</span>{scans.map((scan) => <strong key={scan.id}>{scan[`${impact}Count` as 'criticalCount']}</strong>)}</div>)}
      <div className="matrix-total"><strong>Total findings</strong>{scans.map((scan) => <strong key={scan.id}>{scan.violationCount}</strong>)}</div>
    </div>
    <p className="compare-footnote">These are counts from independent automated runs. They are not a pass rate or compliance score.</p>
  </section>;
}

function ScanDetail() {
  const params = useParams<{ scanId: string }>();
  const scanId = params.scanId ?? '';
  const scanQuery = useGetScan(scanId, { query: { queryKey: getGetScanQueryKey(scanId), enabled: Boolean(scanId) } });
  const [search, setSearch] = useState('');
  const [impact, setImpact] = useState('all');
  const [openFinding, setOpenFinding] = useState('');
  const [exportRequested, setExportRequested] = useState(false);
  const csv = useExportScanCsv(scanId, { query: { queryKey: getExportScanCsvQueryKey(scanId), enabled: exportRequested && Boolean(scanId) } });
  useEffect(() => {
    if (!csv.data || !exportRequested) return;
    const blob = new Blob([csv.data], { type: 'text/csv;charset=utf-8' });
    const href = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.href = href;
    anchor.download = `accesscheck-${scanId}.csv`;
    anchor.click();
    URL.revokeObjectURL(href);
    setExportRequested(false);
  }, [csv.data, exportRequested, scanId]);
  const scan = scanQuery.data;
  const findings = useMemo(() => (scan?.findings ?? []).filter((finding) => {
    const text = `${finding.description} ${finding.help} ${finding.ruleId} ${finding.wcag.join(' ')} ${finding.nodes.map((node) => `${node.target.join(' ')} ${node.html}`).join(' ')}`.toLowerCase();
    return (impact === 'all' || finding.impact === impact) && text.includes(search.toLowerCase());
  }), [scan?.findings, impact, search]);
  if (scanQuery.isLoading) return <div className="page-stack"><LoadingLine/><div className="stat-skeleton"/></div>;
  if (scanQuery.isError || !scan) return <div className="page-stack"><Link className="back-link" href="/history" data-testid="link-back-history"><ArrowRight size={15}/> Back to history</Link><ErrorPanel message="This scan report could not be loaded. It may no longer be available." retry={() => void scanQuery.refetch()}/></div>;
  return <div className="page-stack">
    <Link className="back-link no-print" href="/history" data-testid="link-back-history"><ArrowRight size={15}/> All scans</Link>
    <PageTitle eyebrow="AUTOMATED SCAN REPORT" title={scan.pageTitle || scan.title || scan.domain} description={scan.pageUrl || scan.url}>
      <button className="secondary-button" onClick={() => window.print()} data-testid="button-print-report"><Printer size={15}/> Print</button>
      <button className="secondary-button" onClick={() => { setExportRequested(true); void csv.refetch(); }} disabled={csv.isFetching} data-testid="button-export-csv">{csv.isFetching ? <LoaderCircle className="spin" size={15}/> : <ArrowDownToLine size={15}/>} CSV</button>
    </PageTitle>
    <div className="report-meta"><StatusTag status={scan.status}/><span><Clock3 size={14}/>{formatDate(scan.createdAt)}</span><span><Activity size={14}/>{scan.durationMs > 0 ? `${(scan.durationMs / 1000).toFixed(1)} sec` : 'Duration not recorded'}</span><a href={scan.pageUrl || scan.url} target="_blank" rel="noreferrer" data-testid="link-open-page">Open page <ExternalLink size={13}/></a></div>
    {scan.error && <div className="scan-error" role="alert"><CircleAlert size={17}/><span><strong>Scan could not complete.</strong> {scan.error}</span></div>}
    <div className="report-counts">
      <div className="report-total"><span>Automated findings</span><strong>{scan.violationCount}</strong><small>issues identified by rules</small></div>
      <div className="count-line">{severityOrder.map((value) => <div className="severity-stat" key={value}><span className={`severity-bar ${severityColors[value]}`}/><span>{severityNames[value]}</span><strong>{scan[`${value}Count` as 'criticalCount']}</strong></div>)}</div>
      <div className="report-support"><div><span>Rules passed</span><strong>{scan.passCount}</strong></div><div><span>Needs review</span><strong>{scan.incompleteCount}</strong></div><p>“Needs review” checks require human judgment and are not counted as violations.</p></div>
    </div>
    <section className="findings-section">
      <div className="section-heading"><div><div className="eyebrow">ISSUE EXPLORER</div><h2>Findings <span className="heading-count">{findings.length}</span></h2></div><span className="data-caption">Each item includes page-level evidence</span></div>
      <div className="finding-tools"><label className="search-field"><Search size={16}/><input type="search" placeholder="Search findings, WCAG, selectors…" aria-label="Search findings" value={search} onChange={(e) => setSearch(e.target.value)} data-testid="input-finding-search"/></label>
        <label className="filter-select"><Filter size={15}/><span className="sr-only">Filter by impact</span><select value={impact} onChange={(e) => setImpact(e.target.value)} data-testid="select-finding-impact"><option value="all">All impact levels</option>{severityOrder.map((value) => <option key={value} value={value}>{severityNames[value]}</option>)}</select><ChevronDown size={14}/></label></div>
      {findings.length ? <div className="finding-list">{findings.map((finding) => <FindingCard key={finding.id} finding={finding} isOpen={openFinding === finding.id} onToggle={() => setOpenFinding(openFinding === finding.id ? '' : finding.id)}/>)}</div> :
        scan.findings.length ? <EmptyState title="No findings match" body="Clear the search or change impact filter to see other automated findings."/> : <EmptyState title="No violations reported" body="No violations were returned by the automated rules in this run. This is not proof that the page is accessible or WCAG-conformant; manual testing is still needed."/>}
    </section>
    <div className="disclaimer"><ShieldCheck size={17}/><p><strong>Automated evidence, not a compliance certificate.</strong> Findings are generated by rules and reflect this page's state during this scan. They may need human verification, and automated tools cannot identify every accessibility barrier. Test with keyboards, assistive technologies, and people with disabilities.</p></div>
  </div>;
}

function FindingCard({ finding, isOpen, onToggle }: { finding: Finding; isOpen: boolean; onToggle: () => void }) {
  return <article className={`finding-card ${isOpen ? 'finding-open' : ''}`} data-testid={`finding-${finding.id}`}>
    <button className="finding-trigger" aria-expanded={isOpen} onClick={onToggle} data-testid={`button-toggle-finding-${finding.id}`}>
      <span className={`impact-marker ${severityColors[finding.impact]}`}><CircleAlert size={16}/></span>
      <span className="finding-headline"><span className="rule-id mono">{finding.ruleId}</span><strong>{finding.help || finding.description}</strong><small>{finding.description}</small></span>
      <span className={`impact-pill ${severityColors[finding.impact]}`}>{severityNames[finding.impact]}</span><span className="node-count">{finding.nodes.length} {finding.nodes.length === 1 ? 'element' : 'elements'}</span><ChevronDown className={`finding-chevron ${isOpen ? 'rotate' : ''}`} size={17}/>
    </button>
    {isOpen && <div className="finding-body">
      <div className="finding-explanation"><div className="detail-label">WHY THIS MATTERS</div><p>{finding.description}</p><a href={finding.helpUrl} target="_blank" rel="noreferrer" className="resource-link" data-testid={`link-help-${finding.id}`}>Axe rule guidance <ExternalLink size={13}/></a></div>
      <div className="wcag-box"><div className="detail-label">WCAG REFERENCES</div><div className="wcag-tags">{finding.wcag.length ? finding.wcag.map((ref) => <span key={ref} className="wcag-tag">{ref}</span>) : <span className="quiet-label">No WCAG references provided for this rule.</span>}</div></div>
      <div className="evidence-list"><div className="detail-label">PAGE EVIDENCE <span>{finding.nodes.length} {finding.nodes.length === 1 ? 'instance' : 'instances'}</span></div>
        {finding.nodes.map((node, index) => <div className="evidence-card" key={`${finding.id}-${index}`}>
          <div className="evidence-target"><span>SELECTOR</span>{node.target.map((target, targetIndex) => <code key={targetIndex}>{target}</code>)}</div>
          <pre className="code-evidence"><code>{node.html || 'No HTML snippet provided'}</code></pre>
          <p className="failure-summary">{node.failureSummary || 'No additional failure summary provided.'}</p>
        </div>)}
      </div>
      <div className="remediation-note"><Sparkles size={16}/><p><strong>Suggested next step</strong> Use the axe guidance above to understand the rule, inspect the affected element in context, and choose a fix that works for the page’s interaction and content. Verify the change manually.</p></div>
    </div>}
  </article>;
}

function RoutedBoundary({ children }: { children: ReactNode }) {
  const [location] = useLocation();
  return <ErrorBoundary resetKey={location}>{children}</ErrorBoundary>;
}
function Routes() {
  return <Shell><RoutedBoundary><Switch>
    <Route path="/" component={Dashboard}/>
    <Route path="/history" component={HistoryPage}/>
    <Route path="/scans/:scanId" component={ScanDetail}/>
    <Route component={NotFound}/>
  </Switch></RoutedBoundary></Shell>;
}
function App() {
  return <QueryClientProvider client={queryClient}><TooltipProvider><WouterRouter base={import.meta.env.BASE_URL.replace(/\/$/, '')}><Routes/></WouterRouter><Toaster/></TooltipProvider></QueryClientProvider>;
}

export default App;
