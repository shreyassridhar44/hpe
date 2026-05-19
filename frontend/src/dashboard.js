/**
 * dashboard.js — Real-time metrics, threat feed, and model performance display.
 */

// Live counters
const state = {
  totalProcessed: 0,
  totalThreats: 0,
  totalAllowed: 0,
  totalBlocked: 0,
  avgLatency: 0,
  latencySum: 0,
  replayedThreats: [],
  liveThreats: [],
  attackTypes: {},
  vaultRotationCount: 0,
};

/**
 * Render the dashboard layout
 */
export function renderDashboard(containerId) {
  const container = document.getElementById(containerId);
  if (!container) return;

  container.innerHTML = `
    <!-- Metrics Cards -->
    <div class="dashboard-grid">
      <div class="metric-card">
        <div class="metric-label">Total Processed</div>
        <div class="metric-value cyan" id="metric-total">0</div>
        <div class="metric-change">Events through pipeline</div>
      </div>
      <div class="metric-card">
        <div class="metric-label">Threats Detected</div>
        <div class="metric-value magenta" id="metric-threats">0</div>
        <div class="metric-change">Anomalies identified by AI</div>
      </div>
      <div class="metric-card">
        <div class="metric-label">Allowed</div>
        <div class="metric-value lime" id="metric-allowed">0</div>
        <div class="metric-change">Safe connections passed</div>
      </div>
      <div class="metric-card">
        <div class="metric-label">Blocked / Critical</div>
        <div class="metric-value magenta" id="metric-blocked">0</div>
        <div class="metric-change">Threats neutralized</div>
      </div>
      <div class="metric-card">
        <div class="metric-label">Avg Latency</div>
        <div class="metric-value amber" id="metric-latency">0ms</div>
        <div class="metric-change">Pipeline processing time</div>
      </div>
      <div class="metric-card">
        <div class="metric-label">Detection Rate</div>
        <div class="metric-value lime" id="metric-rate">100%</div>
        <div class="metric-change">Model accuracy (F1)</div>
      </div>
    </div>

    <div style="display: flex; gap: var(--space-2xl); margin-top: var(--space-2xl);">
        
        <!-- Left Column: Models & Vault -->
        <div style="flex: 1;">
            <!-- Model Performance -->
            <div>
              <div class="section-title">Model Performance</div>
              <div class="model-perf-grid">
                <div class="perf-card">
                  <div class="perf-card-title">XGBoost Prob</div>
                  <div class="perf-card-value" id="perf-xgb">--</div>
                </div>
                <div class="perf-card">
                  <div class="perf-card-title">LightGBM Prob</div>
                  <div class="perf-card-value" id="perf-lgb">--</div>
                </div>
                <div class="perf-card">
                  <div class="perf-card-title">Ensemble Score</div>
                  <div class="perf-card-value" id="perf-ens">--</div>
                </div>
                <div class="perf-card">
                  <div class="perf-card-title">Threshold</div>
                  <div class="perf-card-value" id="perf-thr" style="color: var(--amber);">--</div>
                </div>
              </div>
            </div>

            <!-- Vault Credentials -->
            <div style="margin-top: var(--space-2xl);">
              <div class="section-title">HashiCorp Vault Credentials</div>
              <div class="vault-card" id="vault-card" style="background: rgba(20, 20, 25, 0.8); border: 1px solid var(--border-color); border-radius: var(--radius-md); padding: var(--space-lg); transition: all 0.3s ease;">
                <div style="display: flex; justify-content: space-between; margin-bottom: var(--space-md);">
                    <div style="color: var(--text-muted); font-size: 12px; font-family: var(--font-mono);">DB_PASSWORD</div>
                    <div style="color: var(--cyan); font-family: var(--font-mono);" id="vault-db-pw">****</div>
                </div>
                <div style="display: flex; justify-content: space-between; margin-bottom: var(--space-md);">
                    <div style="color: var(--text-muted); font-size: 12px; font-family: var(--font-mono);">API_KEY</div>
                    <div style="color: var(--cyan); font-family: var(--font-mono);" id="vault-api-key">****</div>
                </div>
                <div style="display: flex; justify-content: space-between; margin-bottom: var(--space-md);">
                    <div style="color: var(--text-muted); font-size: 12px; font-family: var(--font-mono);">SERVICE_TOKEN</div>
                    <div style="color: var(--cyan); font-family: var(--font-mono);" id="vault-svc-token">****</div>
                </div>
                <div style="border-top: 1px solid var(--border-color); margin-top: var(--space-md); padding-top: var(--space-md); display: flex; justify-content: space-between;">
                    <div style="color: var(--text-muted); font-size: 12px;">Rotations: <span id="vault-rotations" style="color: var(--magenta); font-weight: 600;">0</span></div>
                    <div style="color: var(--text-muted); font-size: 12px;">Last Reason: <span id="vault-reason" style="color: var(--amber);">none</span></div>
                </div>
              </div>
            </div>
            
            <!-- Attack Type Breakdown -->
            <div style="margin-top: var(--space-2xl);">
              <div class="section-title">Attack Type Breakdown</div>
              <div id="attack-breakdown" style="display: grid; grid-template-columns: 1fr 1fr; gap: var(--space-sm); font-family: var(--font-mono); font-size: 12px;">
                <!-- Filled dynamically -->
              </div>
            </div>

            <!-- Pipeline Health -->
            <div style="margin-top: var(--space-2xl);">
              <div class="section-title">Infrastructure Health</div>
              <div class="pipeline-health-grid" id="health-grid">
                <div class="health-item">
                  <div class="status-dot" id="health-kafka"></div>
                  <span>Kafka</span>
                </div>
                <div class="health-item">
                  <div class="status-dot" id="health-es"></div>
                  <span>Elasticsearch</span>
                </div>
                <div class="health-item">
                  <div class="status-dot" id="health-vault"></div>
                  <span>Vault</span>
                </div>
                <div class="health-item">
                  <div class="status-dot" id="health-model"></div>
                  <span>AI Model</span>
                </div>
              </div>
            </div>
        </div>

        <!-- Right Column: Dual Threat Feed -->
        <div style="flex: 2; display: flex; flex-direction: column; gap: var(--space-md);">
            <div style="display: flex; justify-content: space-between; align-items: center;">
                <span style="font-size: 14px; font-weight: 600; color: var(--text-primary); letter-spacing: 0.5px;">Threat Feeds</span>
                <select id="threat-feed-filter" class="vault-filter-select" style="width: auto; padding: 4px 8px; background: rgba(20, 20, 25, 0.8);">
                    <option value="all">All Logs</option>
                    <option value="replayed">Replayed Dataset Only</option>
                    <option value="live" selected>Live Portal Logins Only</option>
                </select>
            </div>
            <div style="display: flex; gap: var(--space-xl); flex: 1;">
                <!-- Left Sub-column: Replayed Dataset -->
                <div class="threat-feed" id="threat-feed-replayed" style="flex: 1; height: 100%; display: none;">
                  <div class="threat-feed-header" style="border-bottom: 1px solid var(--border-color); padding-bottom: 8px; margin-bottom: 12px; display: flex; justify-content: space-between; align-items: center;">
                    <span class="threat-feed-title" style="font-size: 14px; font-weight: 600; letter-spacing: 0.5px;">📊 Replayed Dataset Threats</span>
                    <span class="live-badge" style="background: rgba(0, 169, 130, 0.1); color: var(--cyan); font-size: 8px; padding: 2px 6px; border-radius: 4px;">ACTIVE</span>
                  </div>
                  <div id="threat-feed-replayed-list" style="display: flex; flex-direction: column; gap: 8px;">
                    <div style="text-align: center; color: var(--text-muted); font-family: var(--font-mono); font-size: 11px; padding: var(--space-lg);">
                      No replayed threats yet
                    </div>
                  </div>
                </div>

                <!-- Right Sub-column: Live Portal Logins -->
                <div class="threat-feed" id="threat-feed-live" style="flex: 1; height: 100%; border-left: none; padding-left: 0;">
                  <div class="threat-feed-header" style="border-bottom: 1px solid var(--border-color); padding-bottom: 8px; margin-bottom: 12px; display: flex; justify-content: space-between; align-items: center;">
                    <span class="threat-feed-title" style="font-size: 14px; font-weight: 600; letter-spacing: 0.5px;">🌐 Live Portal Logins</span>
                    <span class="live-badge" style="background: rgba(233, 69, 96, 0.15); color: var(--magenta); font-size: 8px; padding: 2px 6px; border-radius: 4px; animation: pulse 2s infinite;">LIVE PORTAL</span>
                  </div>
                  <div id="threat-feed-live-list" style="display: flex; flex-direction: column; gap: 8px;">
                    <div style="text-align: center; color: var(--text-muted); font-family: var(--font-mono); font-size: 11px; padding: var(--space-lg);">
                      No live login events yet
                    </div>
                  </div>
                </div>
            </div>
        </div>
        
    </div>

    <!-- Kafka & Elasticsearch Stats Row -->
    <div style="display: flex; gap: var(--space-xl); margin-top: var(--space-2xl);">
        <!-- Kafka Stats -->
        <div style="flex: 1;">
          <div class="section-title">Apache Kafka — Live Stats</div>
          <div class="infra-stats-card" id="kafka-stats-card">
            <div class="infra-stats-grid">
              <div class="infra-stat">
                <span class="infra-stat-label">Brokers</span>
                <span class="infra-stat-value" id="kafka-brokers">—</span>
              </div>
              <div class="infra-stat">
                <span class="infra-stat-label">Topics</span>
                <span class="infra-stat-value" id="kafka-topics">—</span>
              </div>
              <div class="infra-stat">
                <span class="infra-stat-label">Total Messages</span>
                <span class="infra-stat-value cyan" id="kafka-total-msgs">—</span>
              </div>
              <div class="infra-stat">
                <span class="infra-stat-label">Consumer Lag</span>
                <span class="infra-stat-value" id="kafka-lag">—</span>
              </div>
            </div>
            <div id="kafka-partitions" style="margin-top: var(--space-md); font-family: var(--font-mono); font-size: 11px;"></div>
          </div>
        </div>

        <!-- Elasticsearch Stats -->
        <div style="flex: 1;">
          <div class="section-title">Elasticsearch — Index Stats</div>
          <div class="infra-stats-card" id="es-stats-card">
            <div class="infra-stats-grid">
              <div class="infra-stat">
                <span class="infra-stat-label">Audit Logs</span>
                <span class="infra-stat-value lime" id="es-audit-count">—</span>
              </div>
              <div class="infra-stat">
                <span class="infra-stat-label">Threats Indexed</span>
                <span class="infra-stat-value magenta" id="es-threats-count">—</span>
              </div>
            </div>
            <div id="es-threat-breakdown" style="margin-top: var(--space-md); font-family: var(--font-mono); font-size: 11px;"></div>
          </div>
        </div>
    </div>

    <!-- Vault Users Table -->
    <div style="margin-top: var(--space-2xl);">
      <div class="section-title" style="display: flex; justify-content: space-between; align-items: center;">
        <span>🔐 HashiCorp Vault — 200 User Credentials</span>
        <span id="vault-user-count" style="font-size: 12px; color: var(--text-muted); font-weight: 400;"></span>
      </div>
      <div class="vault-table-controls">
        <input type="text" id="vault-search" placeholder="Search user ID..." class="vault-search-input" />
        <select id="vault-role-filter" class="vault-filter-select">
          <option value="">All Roles</option>
          <option value="Admin">Admin</option>
          <option value="Developer">Developer</option>
          <option value="Finance">Finance</option>
          <option value="HR">HR</option>
          <option value="Sales">Sales</option>
        </select>
        <select id="vault-status-filter" class="vault-filter-select">
          <option value="">All Status</option>
          <option value="active">Active</option>
          <option value="rotated">Rotated</option>
        </select>
      </div>
      <div class="vault-table-wrapper">
        <table class="vault-table" id="vault-users-table">
          <thead>
            <tr>
              <th>User ID</th>
              <th>Role</th>
              <th>Region</th>
              <th>DB Password</th>
              <th>API Key</th>
              <th>Rotations</th>
              <th>Status</th>
              <th>Last Reason</th>
            </tr>
          </thead>
          <tbody id="vault-users-tbody">
            <tr><td colspan="8" style="text-align: center; color: var(--text-muted);">Loading 200 users...</td></tr>
          </tbody>
        </table>
      </div>
    </div>
  `;
  
  // Start polling vault credentials
  setInterval(updateVaultCredentials, 5000);
  updateVaultCredentials();

  // Start polling Kafka + ES stats
  setInterval(updateKafkaStats, 8000);
  setInterval(updateEsStats, 10000);
  updateKafkaStats();
  updateEsStats();

  // Load Vault users table
  loadVaultUsersTable();
  setInterval(loadVaultUsersTable, 15000);

  // Setup search/filter listeners
  setupVaultTableFilters();
  setupThreatFeedFilter();

  // Initialize dashboard counters from backend metrics (persist across reloads)
  initDashboardFromBackend();
}

/**
 * Initialize dashboard state from backend metrics so counters persist across reloads
 */
async function initDashboardFromBackend() {
  try {
    const res = await fetch('/api/metrics');
    if (!res.ok) return;
    const data = await res.json();

    state.totalProcessed = data.total_requests || 0;
    state.totalThreats = data.total_threats || 0;
    state.totalAllowed = data.total_allowed || 0;
    state.totalBlocked = (data.total_blocked || 0) + (data.total_critical || 0);
    state.avgLatency = data.avg_latency_ms || 0;
    state.latencySum = state.avgLatency * state.totalProcessed;
    state.attackTypes = data.attack_types || {};

    // Update all metric cards
    updateElement('metric-total', state.totalProcessed.toLocaleString());
    updateElement('metric-threats', state.totalThreats.toLocaleString());
    updateElement('metric-allowed', state.totalAllowed.toLocaleString());
    updateElement('metric-blocked', state.totalBlocked.toLocaleString());
    updateElement('metric-latency', `${state.avgLatency.toFixed(1)}ms`);

    const rate = state.totalProcessed > 0
      ? ((state.totalProcessed - state.totalThreats) / state.totalProcessed * 100)
      : 100;
    updateElement('metric-rate', `${rate.toFixed(1)}%`);

    // Rebuild attack breakdown chart
    if (Object.keys(state.attackTypes).length > 0) {
      updateAttackBreakdown();
    }
    
    // Hydrate threat feed
    try {
      const feedRes = await fetch('/api/elasticsearch/recent-threats?size=100');
      if (feedRes.ok) {
        const feedData = await feedRes.json();
        if (feedData.threats && feedData.threats.length > 0) {
          const mapped = feedData.threats.map(t => ({
            is_threat: true,
            threat_score: t.threat_score,
            event_summary: {
              user: t.user,
              source_ip: t.source_ip,
              anomaly_type: t.attack_type,
              event_source: t.event_source || 'replayed_dataset',
            },
            time: new Date(t.timestamp).toLocaleTimeString(),
          }));
          state.replayedThreats = mapped.filter(t => t.event_summary?.event_source !== 'live_portal');
          state.liveThreats = mapped.filter(t => t.event_summary?.event_source === 'live_portal');
          updateThreatFeed();
        }
      }
    } catch(e) {
       console.warn('[HPE] Could not fetch initial threat feed from ES');
    }

    console.log(`[HPE] Dashboard initialized: ${state.totalProcessed} events, ${state.totalThreats} threats`);
  } catch (e) {
    console.warn('[HPE] Could not fetch backend metrics for dashboard init');
  }
}

/**
 * Update dashboard with a new prediction result
 */
export function updateDashboard(prediction) {
  state.totalProcessed++;
  state.latencySum += prediction.total_latency_ms || 0;
  state.avgLatency = state.latencySum / state.totalProcessed;

  const isLivePortal = (prediction.event_summary?.event_source === 'live_portal');

  if (prediction.is_threat) {
    state.totalThreats++;
    state.totalBlocked++;

    // Track attack types
    const aType = prediction.event_summary?.anomaly_type || 'Unknown';
    if (!state.attackTypes[aType]) state.attackTypes[aType] = 0;
    state.attackTypes[aType]++;
    updateAttackBreakdown();
  } else {
    state.totalAllowed++;
  }

  // Always add to threat feed if it is a threat OR from live portal
  if (prediction.is_threat || isLivePortal) {
    const item = {
      ...prediction,
      time: new Date().toLocaleTimeString(),
    };
    if (isLivePortal) {
      state.liveThreats.unshift(item);
      if (state.liveThreats.length > 50) state.liveThreats.pop();
    } else {
      state.replayedThreats.unshift(item);
      if (state.replayedThreats.length > 50) state.replayedThreats.pop();
    }
  }

  // Update metric cards
  updateElement('metric-total', state.totalProcessed.toLocaleString());
  updateElement('metric-threats', state.totalThreats.toLocaleString());
  updateElement('metric-allowed', state.totalAllowed.toLocaleString());
  updateElement('metric-blocked', state.totalBlocked.toLocaleString());
  updateElement('metric-latency', `${state.avgLatency.toFixed(1)}ms`);

  const rate = state.totalProcessed > 0
    ? ((state.totalAllowed / state.totalProcessed) * 100).toFixed(1)
    : '100';
  updateElement('metric-rate', `${rate}%`);

  // Update threat feed display
  updateThreatFeed();
  
  // Update recent model scores from prediction
  if (prediction.xgb_score !== undefined) {
      updateElement('perf-xgb', (prediction.xgb_score || 0).toFixed(4));
      updateElement('perf-lgb', (prediction.lgb_score || 0).toFixed(4));
      updateElement('perf-ens', (prediction.ensemble_score || 0).toFixed(4));
      updateElement('perf-thr', (prediction.threshold || 0.5).toFixed(4));
  }
}

/**
 * Update health indicators from API
 */
export async function updateHealth() {
  try {
    const res = await fetch('/api/health');
    if (!res.ok) return;
    const data = await res.json();

    setHealthDot('health-kafka', data.kafka_connected);
    setHealthDot('health-es', data.elasticsearch_connected);
    setHealthDot('health-vault', data.vault_connected);
    setHealthDot('health-model', data.model_loaded);
  } catch (e) {
    // Backend not available
    setHealthDot('health-kafka', false);
    setHealthDot('health-es', false);
    setHealthDot('health-vault', false);
    setHealthDot('health-model', false);
  }
}

/**
 * Update Vault Credentials
 */
async function updateVaultCredentials() {
    try {
        const res = await fetch('/api/vault/credentials');
        if (!res.ok) return;
        const data = await res.json();
        
        if (data.error) return;
        
        updateElement('vault-db-pw', data.db_password);
        updateElement('vault-api-key', data.api_key);
        updateElement('vault-svc-token', data.service_token);
        updateElement('vault-reason', data.rotation_reason);
        
        const newCount = data.rotation_count || 0;
        if (newCount > state.vaultRotationCount) {
            const card = document.getElementById('vault-card');
            if (card) {
                card.style.borderColor = 'var(--magenta)';
                card.style.boxShadow = '0 0 15px rgba(233, 69, 96, 0.5)';
                setTimeout(() => {
                    card.style.borderColor = 'var(--border-color)';
                    card.style.boxShadow = 'none';
                }, 1500);
            }
            state.vaultRotationCount = newCount;
        }
        updateElement('vault-rotations', state.vaultRotationCount.toString());
        
    } catch(e) { /* Ignore */ }
}

/**
 * Update Kafka Stats Panel
 */
async function updateKafkaStats() {
    try {
        const res = await fetch('/api/kafka/stats');
        if (!res.ok) return;
        const data = await res.json();
        if (data.error) {
            updateElement('kafka-brokers', '—');
            return;
        }

        updateElement('kafka-brokers', data.broker_count || 0);
        const topicCount = Object.keys(data.topics || {}).length;
        updateElement('kafka-topics', topicCount);
        updateElement('kafka-total-msgs', (data.total_messages_in_topics || 0).toLocaleString());

        // Consumer lag
        const lagEntries = Object.values(data.consumer_lag || {});
        const totalLag = lagEntries.reduce((sum, l) => sum + (l.lag || 0), 0);
        const lagEl = document.getElementById('kafka-lag');
        if (lagEl) {
            lagEl.textContent = totalLag.toLocaleString();
            lagEl.className = `infra-stat-value ${totalLag > 50 ? 'magenta' : totalLag > 10 ? 'amber' : 'lime'}`;
        }

        // Partition details
        const partDiv = document.getElementById('kafka-partitions');
        if (partDiv && lagEntries.length > 0) {
            partDiv.innerHTML = lagEntries.map(l => `
                <div class="kafka-partition-row">
                    <span style="color: var(--text-muted);">${l.topic}[${l.partition}]</span>
                    <span style="color: var(--cyan);">offset: ${l.committed_offset}</span>
                    <span style="color: var(--amber);">latest: ${l.latest_offset}</span>
                    <span class="${l.lag > 10 ? 'lag-warning' : 'lag-ok'}">lag: ${l.lag}</span>
                </div>
            `).join('');
        } else if (partDiv) {
            partDiv.innerHTML = '<div style="color: var(--text-muted);">No active partitions</div>';
        }
    } catch(e) { /* Ignore */ }
}

/**
 * Update Elasticsearch Stats Panel
 */
async function updateEsStats() {
    try {
        const res = await fetch('/api/elasticsearch/stats');
        if (!res.ok) return;
        const data = await res.json();

        const docs = data.index_doc_counts || {};
        updateElement('es-audit-count', (docs['hpe-audit-logs'] || 0).toLocaleString());
        updateElement('es-threats-count', (docs['hpe-threats'] || 0).toLocaleString());

        // Threat breakdown from aggregations
        const breakdown = data.threat_breakdown || {};
        const breakDiv = document.getElementById('es-threat-breakdown');
        if (breakDiv && Object.keys(breakdown).length > 0) {
            const entries = Object.entries(breakdown).sort((a, b) => b[1] - a[1]);
            breakDiv.innerHTML = '<div style="color: var(--text-muted); margin-bottom: 4px;">Threat Actions:</div>' +
                entries.map(([action, count]) => `
                    <div style="display: flex; justify-content: space-between; padding: 2px 0;">
                        <span style="color: var(--text-secondary);">${action}</span>
                        <span style="color: var(--magenta);">${count}</span>
                    </div>
                `).join('');
        }
    } catch(e) { /* Ignore */ }
}

/**
 * Load Vault Users Table
 */
let _allVaultUsers = [];

async function loadVaultUsersTable() {
    try {
        const res = await fetch('/api/vault/users');
        if (!res.ok) return;
        const data = await res.json();
        _allVaultUsers = data.users || [];
        updateElement('vault-user-count', `${data.total_users} users · ${data.global_rotation_count} total rotations`);
        renderVaultTable(_allVaultUsers);
    } catch(e) {
        const tbody = document.getElementById('vault-users-tbody');
        if (tbody) tbody.innerHTML = '<tr><td colspan="8" style="text-align: center; color: var(--amber);">Vault not connected</td></tr>';
    }
}

function renderVaultTable(users) {
    const tbody = document.getElementById('vault-users-tbody');
    if (!tbody) return;

    if (users.length === 0) {
        tbody.innerHTML = '<tr><td colspan="8" style="text-align: center; color: var(--text-muted);">No users match filters</td></tr>';
        return;
    }

    tbody.innerHTML = users.map(u => {
        const statusClass = u.status === 'rotated' ? 'status-rotated' : 'status-active';
        const statusLabel = u.status === 'rotated' ? '🔄 ROTATED' : '✅ ACTIVE';
        const reason = u.last_rotation_reason || '—';
        const shortReason = reason.length > 25 ? reason.substring(0, 25) + '…' : reason;
        return `
            <tr class="vault-row ${u.status === 'rotated' ? 'row-rotated' : ''}">
                <td class="user-id-cell">${u.user_id}</td>
                <td><span class="role-badge role-${(u.role || '').toLowerCase()}">${u.role}</span></td>
                <td>${u.home_region || '—'}</td>
                <td class="mono-cell">${u.db_password || '****'}</td>
                <td class="mono-cell">${u.api_key || '****'}</td>
                <td style="text-align: center;">${u.rotation_count || 0}</td>
                <td><span class="${statusClass}">${statusLabel}</span></td>
                <td class="reason-cell" title="${reason}">${shortReason}</td>
            </tr>
        `;
    }).join('');
}

function setupVaultTableFilters() {
    const search = document.getElementById('vault-search');
    const roleFilter = document.getElementById('vault-role-filter');
    const statusFilter = document.getElementById('vault-status-filter');

    const applyFilters = () => {
        const q = (search?.value || '').toLowerCase();
        const role = roleFilter?.value || '';
        const status = statusFilter?.value || '';

        let filtered = _allVaultUsers;
        if (q) filtered = filtered.filter(u => (u.user_id || '').toLowerCase().includes(q));
        if (role) filtered = filtered.filter(u => u.role === role);
        if (status) filtered = filtered.filter(u => u.status === status);

        renderVaultTable(filtered);
    };

    search?.addEventListener('input', applyFilters);
    roleFilter?.addEventListener('change', applyFilters);
    statusFilter?.addEventListener('change', applyFilters);
}

function setupThreatFeedFilter() {
    const feedFilter = document.getElementById('threat-feed-filter');
    feedFilter?.addEventListener('change', (e) => {
        const val = e.target.value;
        const replayedCol = document.getElementById('threat-feed-replayed');
        const liveCol = document.getElementById('threat-feed-live');
        
        if (!replayedCol || !liveCol) return;

        if (val === 'all') {
            replayedCol.style.display = 'block';
            liveCol.style.display = 'block';
            liveCol.style.borderLeft = '1px solid var(--border-color)';
            liveCol.style.paddingLeft = '20px';
        } else if (val === 'replayed') {
            replayedCol.style.display = 'block';
            liveCol.style.display = 'none';
        } else if (val === 'live') {
            replayedCol.style.display = 'none';
            liveCol.style.display = 'block';
            liveCol.style.borderLeft = 'none';
            liveCol.style.paddingLeft = '0';
        }
    });
}

function updateAttackBreakdown() {
    const container = document.getElementById('attack-breakdown');
    if (!container) return;
    
    const types = Object.entries(state.attackTypes).sort((a, b) => b[1] - a[1]);
    
    container.innerHTML = types.map(([type, count]) => `
        <div style="display: flex; justify-content: space-between; background: rgba(0,0,0,0.2); padding: 4px 8px; border-radius: 4px;">
            <span style="color: var(--text-secondary);">${type}</span>
            <span style="color: var(--magenta);">${count}</span>
        </div>
    `).join('');
}


/**
 * Update model performance metrics from API (kept for backwards compatibility)
 * In v2, model scores are updated inline from each prediction result.
 */
export async function updateModelMetrics() {
  // No-op: model scores are now updated per-event in updateDashboard()
}


// ── Helpers ───────────────────────────────────────────────────────────────

function updateThreatFeed() {
  const replayedList = document.getElementById('threat-feed-replayed-list');
  const liveList = document.getElementById('threat-feed-live-list');
  if (!replayedList || !liveList) return;

  const replayedEvents = state.replayedThreats || [];
  const liveEvents = state.liveThreats || [];

  // Render Replayed
  if (replayedEvents.length > 0) {
    replayedList.innerHTML = replayedEvents.slice(0, 15).map(threat => {
      const severity = threat.threat_score > 0.9 ? 'critical' : 'high';
      const summary = threat.event_summary || {};
      const aType = summary.anomaly_type && summary.anomaly_type !== 'None' ? summary.anomaly_type : 'BLOCK';
      
      return `
        <div class="threat-item ${severity}" style="margin-bottom: 4px; font-size: 11px;">
          <span class="event-badge ${severity === 'critical' ? 'critical' : 'block'}" style="font-size: 9px; padding: 2px 4px;">
            ${aType}
          </span>
          <span style="color: var(--text-primary); font-weight: 500; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; max-width: 80px;">${summary.user || 'unknown'}</span>
          <span style="color: var(--cyan-dim); font-family: var(--font-mono);">${summary.source_ip || '--'}</span>
          <span style="color: var(--magenta); font-weight: 600;">${((threat.threat_score || 0) * 100).toFixed(1)}%</span>
          <span style="color: var(--text-muted); font-size: 10px; margin-left: auto;">${threat.time}</span>
        </div>
      `;
    }).join('');
  } else {
    replayedList.innerHTML = `
      <div style="text-align: center; color: var(--text-muted); font-family: var(--font-mono); font-size: 11px; padding: var(--space-lg);">
        No replayed threats yet
      </div>
    `;
  }

  // Render Live
  if (liveEvents.length > 0) {
    liveList.innerHTML = liveEvents.slice(0, 15).map(threat => {
      const isThreat = threat.is_threat || threat.threat_score >= 0.6;
      const isCritical = threat.threat_action === 'CRITICAL_ALERT';
      const severity = isCritical ? 'critical' : isThreat ? 'high' : 'safe';
      const summary = threat.event_summary || {};
      
      const badgeClass = severity === 'critical' ? 'critical' : severity === 'high' ? 'block' : 'allow';
      const badgeLabel = severity === 'critical' ? 'CRITICAL' : severity === 'high' ? 'BLOCKED' : 'ALLOWED';
      
      const scoreColor = isThreat ? 'var(--magenta)' : 'var(--lime)';
      const scorePercent = ((threat.threat_score || 0) * 100).toFixed(1);

      return `
        <div class="threat-item ${severity === 'safe' ? 'safe' : severity}" style="margin-bottom: 4px; font-size: 11px; background: ${isThreat ? 'rgba(233, 69, 96, 0.05)' : 'rgba(1, 169, 130, 0.05)'}; border-left: 3px solid ${isThreat ? 'var(--magenta)' : 'var(--cyan)'};">
          <span class="event-badge ${badgeClass}" style="font-size: 8px; padding: 2px 4px; font-family: var(--font-mono);">
            ${badgeLabel}
          </span>
          <span style="color: var(--text-primary); font-weight: 600; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; max-width: 80px;">${summary.user || 'unknown'}</span>
          <span style="color: var(--cyan-dim); font-family: var(--font-mono);">${summary.source_ip || '--'}</span>
          <span style="color: ${scoreColor}; font-weight: 700;">${scorePercent}%</span>
          <span style="color: var(--text-muted); font-size: 10px; margin-left: auto;">${threat.time}</span>
        </div>
      `;
    }).join('');
  } else {
    liveList.innerHTML = `
      <div style="text-align: center; color: var(--text-muted); font-family: var(--font-mono); font-size: 11px; padding: var(--space-lg);">
        No live login events yet
      </div>
    `;
  }
}

function updateElement(id, value) {
  const el = document.getElementById(id);
  if (el) el.textContent = value;
}

function setHealthDot(id, isHealthy) {
  const dot = document.getElementById(id);
  if (!dot) return;
  dot.className = `status-dot ${isHealthy ? '' : 'danger'}`;
}


// ── VPN Login Alert Banner ───────────────────────────────────────────────────

let _vpnAlertContainer = null;

function _ensureVpnAlertContainer() {
  if (_vpnAlertContainer && document.body.contains(_vpnAlertContainer)) return;
  _vpnAlertContainer = document.createElement('div');
  _vpnAlertContainer.className = 'vpn-alert-container';
  _vpnAlertContainer.id = 'vpn-alert-container';
  document.body.appendChild(_vpnAlertContainer);
}

/**
 * Show a VPN login alert banner at the top of the screen.
 * Called when a user logs in from a VPN-detected IP.
 * @param {object} data - { username, source_ip, vpn_provider, country, city, login_success, timestamp }
 */
export function showVpnAlert(data) {
  _ensureVpnAlertContainer();

  const alertId = `vpn-alert-${Date.now()}`;
  const statusClass = data.login_success ? 'vpn-status-success' : 'vpn-status-failure';
  const statusText = data.login_success ? '✓ LOGIN SUCCESS' : '✗ LOGIN FAILED';
  const timeStr = data.timestamp
    ? new Date(data.timestamp).toLocaleTimeString()
    : new Date().toLocaleTimeString();

  const banner = document.createElement('div');
  banner.className = 'vpn-alert-banner';
  banner.id = alertId;
  banner.innerHTML = `
    <div class="vpn-alert-header">
      <div class="vpn-alert-title">
        <span class="vpn-shield-icon">🛡️</span>
        VPN Login Detected
      </div>
      <button class="vpn-alert-close" onclick="event.stopPropagation(); document.getElementById('${alertId}').classList.add('dismissing'); setTimeout(() => document.getElementById('${alertId}')?.remove(), 400);">✕</button>
    </div>
    <div class="vpn-alert-body">
      <div class="vpn-alert-field">
        <span class="vpn-alert-field-label">Username</span>
        <span class="vpn-alert-field-value">${data.username || 'unknown'}</span>
      </div>
      <div class="vpn-alert-field">
        <span class="vpn-alert-field-label">Source IP</span>
        <span class="vpn-alert-field-value vpn-ip">${data.source_ip || '--'}</span>
      </div>
      <div class="vpn-alert-field">
        <span class="vpn-alert-field-label">VPN Provider / ISP</span>
        <span class="vpn-alert-field-value vpn-provider">${data.vpn_provider || 'Unknown'}</span>
      </div>
      <div class="vpn-alert-field">
        <span class="vpn-alert-field-label">Location</span>
        <span class="vpn-alert-field-value">${data.city || '?'}, ${data.country || '?'}</span>
      </div>
      <div class="vpn-alert-field">
        <span class="vpn-alert-field-label">Status</span>
        <span class="vpn-alert-field-value ${statusClass}">${statusText}</span>
      </div>
      <div class="vpn-alert-field">
        <span class="vpn-alert-field-label">Time</span>
        <span class="vpn-alert-field-value">${timeStr}</span>
      </div>
    </div>
    <div class="vpn-alert-footer">
      <span style="color: var(--amber); font-weight: 600; font-size: 10px; display: flex; align-items: center; gap: 4px;">👉 Click to review in Admin Console</span>
      <span class="vpn-alert-countdown" id="${alertId}-countdown">Auto-dismiss in 15s</span>
    </div>
  `;

  // Click handler to redirect to Admin Console (simulates nav dot click for bulletproof scroll transitions)
  banner.addEventListener('click', (e) => {
    // If the close button was clicked, don't redirect
    if (e.target.closest('.vpn-alert-close')) {
      return;
    }
    
    const dots = document.querySelectorAll('.section-nav-dot');
    if (dots && dots.length >= 4) {
      console.log('[HPE] Redirecting to Admin Console via native navigation dot simulation');
      dots[3].click();
    } else {
      const adminSection = document.getElementById('admin-section');
      if (adminSection) {
        console.log('[HPE] Redirecting to Admin Console via direct scroll fallback');
        adminSection.scrollIntoView({ behavior: 'smooth' });
      }
    }
  });

  _vpnAlertContainer.appendChild(banner);

  // Countdown + auto-dismiss
  let remaining = 15;
  const interval = setInterval(() => {
    remaining--;
    const countdownEl = document.getElementById(`${alertId}-countdown`);
    if (countdownEl) {
      countdownEl.textContent = `Auto-dismiss in ${remaining}s`;
    }
    if (remaining <= 0) {
      clearInterval(interval);
      const el = document.getElementById(alertId);
      if (el) {
        el.classList.add('dismissing');
        setTimeout(() => el.remove(), 400);
      }
    }
  }, 1000);

  // Limit to 3 visible alerts max
  const alerts = _vpnAlertContainer.querySelectorAll('.vpn-alert-banner');
  if (alerts.length > 3) {
    const oldest = alerts[0];
    oldest.classList.add('dismissing');
    setTimeout(() => oldest.remove(), 400);
  }

  console.log(`[HPE] 🛡️ VPN Alert: ${data.username} from ${data.source_ip} (${data.vpn_provider})`);
}
