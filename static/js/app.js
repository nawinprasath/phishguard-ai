/**
 * PhishGuard - Frontend Application Logic (Vanilla JavaScript)
 * Handles theme switching, asynchronous ML prediction calls, real-time metrics,
 * and in-memory scan history management.
 */

document.addEventListener('DOMContentLoaded', () => {
  // DOM Elements
  const themeToggleBtn = document.getElementById('themeToggleBtn');
  const scanForm = document.getElementById('scanForm');
  const urlInput = document.getElementById('urlInput');
  const clearBtn = document.getElementById('clearBtn');
  const analyzeBtn = document.getElementById('analyzeBtn');
  const errorAlert = document.getElementById('errorAlert');

  // Status Elements
  const modelStatusIndicator = document.getElementById('modelStatusIndicator');
  const modelStatusText = document.getElementById('modelStatusText');

  // Result Card Elements
  const resultSection = document.getElementById('resultSection');
  const resultCard = document.getElementById('resultCard');
  const verdictIconContainer = document.getElementById('verdictIconContainer');
  const verdictTitle = document.getElementById('verdictTitle');
  const riskBadge = document.getElementById('riskBadge');
  const scannedUrlText = document.getElementById('scannedUrlText');
  const confidenceValue = document.getElementById('confidenceValue');
  const riskScoreValue = document.getElementById('riskScoreValue');
  const riskVerdictText = document.getElementById('riskVerdictText');
  const meterBar = document.getElementById('meterBar');
  const featureGrid = document.getElementById('featureGrid');
  const featureCountText = document.getElementById('featureCountText');

  // History Elements
  const historyTableBody = document.getElementById('historyTableBody');
  const clearHistoryBtn = document.getElementById('clearHistoryBtn');

  // Metrics Elements
  const metricDatasetSize = document.getElementById('metricDatasetSize');
  const metricBestModel = document.getElementById('metricBestModel');
  const metricAccuracy = document.getElementById('metricAccuracy');
  const metricF1 = document.getElementById('metricF1');
  const comparisonContainer = document.getElementById('comparisonContainer');
  const comparisonTableBody = document.getElementById('comparisonTableBody');
  const metricsNotice = document.getElementById('metricsNotice');

  // Example Chips
  const exampleChips = document.querySelectorAll('.chip');

  // In-memory session history
  let scanHistory = [];

  // ============================================================================
  // 1. Theme Management (Dark / Light)
  // ============================================================================
  const savedTheme = localStorage.getItem('phishguard_theme') || 'dark';
  document.documentElement.setAttribute('data-theme', savedTheme);

  themeToggleBtn.addEventListener('click', () => {
    const currentTheme = document.documentElement.getAttribute('data-theme');
    const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
    document.documentElement.setAttribute('data-theme', newTheme);
    localStorage.setItem('phishguard_theme', newTheme);
  });

  // ============================================================================
  // 2. Input Handling & Clear Button
  // ============================================================================
  urlInput.addEventListener('input', () => {
    clearBtn.style.display = urlInput.value.trim() ? 'block' : 'none';
    hideError();
  });

  clearBtn.addEventListener('click', () => {
    urlInput.value = '';
    clearBtn.style.display = 'none';
    urlInput.focus();
    hideError();
  });

  // Example Chips click
  exampleChips.forEach(chip => {
    chip.addEventListener('click', () => {
      const targetUrl = chip.getAttribute('data-url');
      if (targetUrl) {
        urlInput.value = targetUrl;
        clearBtn.style.display = 'block';
        performScan(targetUrl);
      }
    });
  });

  function showError(msg) {
    errorAlert.textContent = msg;
    errorAlert.style.display = 'block';
  }

  function hideError() {
    errorAlert.textContent = '';
    errorAlert.style.display = 'none';
  }

  // ============================================================================
  // 3. Health & Model Readiness Check
  // ============================================================================
  async function checkHealth() {
    try {
      const res = await fetch('/api/health');
      const data = await res.json();
      if (data.model_loaded) {
        modelStatusIndicator.classList.add('ready');
        modelStatusIndicator.classList.remove('offline');
        modelStatusText.textContent = `Model Ready (${data.model_name || 'Active'})`;
      } else {
        modelStatusIndicator.classList.add('offline');
        modelStatusIndicator.classList.remove('ready');
        modelStatusText.textContent = 'Model Offline (Train First)';
      }
    } catch (err) {
      modelStatusIndicator.classList.add('offline');
      modelStatusText.textContent = 'Server Offline';
    }
  }

  // ============================================================================
  // 4. Fetch Model Metrics (/api/metrics)
  // ============================================================================
  async function loadMetrics() {
    try {
      const res = await fetch('/api/metrics');
      if (!res.ok) {
        metricsNotice.style.display = 'block';
        return;
      }
      const data = await res.json();

      metricsNotice.style.display = 'none';
      metricDatasetSize.textContent = data.total_dataset_size ? data.total_dataset_size.toLocaleString() : '--';
      metricBestModel.textContent = data.best_model || '--';
      metricAccuracy.textContent = data.accuracy ? `${(data.accuracy * 100).toFixed(2)}%` : '--';
      metricF1.textContent = data.f1_score ? `${(data.f1_score * 100).toFixed(2)}%` : '--';

      // Populate comparison table
      if (data.all_models && data.all_models.length > 0) {
        comparisonContainer.style.display = 'block';
        comparisonTableBody.innerHTML = '';

        data.all_models.forEach(m => {
          const isBest = m.model_name === data.best_model;
          const tr = document.createElement('tr');
          if (isBest) tr.classList.add('best-row');

          tr.innerHTML = `
            <td>
              <strong>${escapeHtml(m.model_name)}</strong>
              ${isBest ? ' <span style="color:var(--color-safe); font-size:0.75rem;">(Best)</span>' : ''}
            </td>
            <td>${(m.accuracy * 100).toFixed(2)}%</td>
            <td>${(m.precision * 100).toFixed(2)}%</td>
            <td>${(m.recall * 100).toFixed(2)}%</td>
            <td><strong>${(m.f1_score * 100).toFixed(2)}%</strong></td>
            <td>${m.training_time_sec ? m.training_time_sec + 's' : '--'}</td>
          `;
          comparisonTableBody.appendChild(tr);
        });
      }
    } catch (err) {
      console.warn('Metrics could not be fetched:', err);
      metricsNotice.style.display = 'block';
    }
  }

  // ============================================================================
  // 5. URL Analysis (Prediction Execution)
  // ============================================================================
  scanForm.addEventListener('submit', (e) => {
    e.preventDefault();
    const url = urlInput.value.trim();
    if (!url) {
      showError('Please enter a URL to analyze.');
      return;
    }
    performScan(url);
  });

  async function performScan(url) {
    hideError();
    setLoading(true);

    try {
      const response = await fetch('/api/predict', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: url })
      });

      const result = await response.json();

      if (!response.ok) {
        throw new Error(result.error || result.message || 'Failed to scan URL');
      }

      displayResult(result);
      addToHistory(result);

      // Smooth scroll to results
      resultSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
    } catch (err) {
      showError(err.message || 'An error occurred during scanning. Make sure the server and model are running.');
    } finally {
      setLoading(false);
    }
  }

  function setLoading(isLoading) {
    const btnText = analyzeBtn.querySelector('.btn-text');
    const spinner = analyzeBtn.querySelector('.btn-spinner');

    if (isLoading) {
      analyzeBtn.disabled = true;
      btnText.style.display = 'none';
      spinner.style.display = 'block';
    } else {
      analyzeBtn.disabled = false;
      btnText.style.display = 'block';
      spinner.style.display = 'none';
    }
  }

  // ============================================================================
  // 6. Render Prediction Results
  // ============================================================================
  function displayResult(data) {
    resultSection.style.display = 'block';

    const isPhish = data.is_phishing;
    const isSafe = !isPhish;

    // Card styling
    resultCard.classList.remove('safe-verdict', 'phish-verdict');
    resultCard.classList.add(isSafe ? 'safe-verdict' : 'phish-verdict');

    // Icon & Header
    verdictIconContainer.className = `verdict-icon-container ${isSafe ? 'safe' : 'phish'}`;
    verdictIconContainer.innerHTML = isSafe
      ? `<svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m9 12 2 2 4-4"/></svg>`
      : `<svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>`;

    verdictTitle.textContent = isSafe ? 'VERIFIED LEGITIMATE' : 'PHISHING THREAT DETECTED';
    scannedUrlText.textContent = data.url;

    // Risk badge
    const level = (data.risk_level || 'Safe').toLowerCase();
    riskBadge.className = `risk-badge ${level}`;
    riskBadge.textContent = `${data.risk_level} Risk`;

    // Confidence
    confidenceValue.textContent = `${data.confidence.toFixed(1)}%`;

    // Meter
    riskScoreValue.textContent = `${data.risk_score}/100`;
    riskVerdictText.textContent = isSafe ? 'Low Threat Probability' : 'High Threat Probability';
    meterBar.style.width = `${data.risk_score}%`;
    meterBar.style.backgroundColor = isSafe ? 'var(--color-safe)' : 'var(--color-phish)';

    // Render Features
    featureGrid.innerHTML = '';
    const feats = data.features || [];
    featureCountText.textContent = `Analyzed ${feats.length} structural & lexical indicators`;

    feats.forEach(f => {
      const item = document.createElement('div');
      item.className = 'feature-item';

      if (f.risk_level === 'danger') item.classList.add('flagged-danger');
      else if (f.risk_level === 'warning') item.classList.add('flagged-warning');

      const iconSvg = f.is_flagged
        ? `<svg class="feature-icon" style="color:var(--color-phish)" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>`
        : `<svg class="feature-icon" style="color:var(--color-safe)" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="m9 12 2 2 4-4"/></svg>`;

      item.innerHTML = `
        <div class="feature-top">
          <div class="feature-title-group">
            ${iconSvg}
            <span class="feature-name">${escapeHtml(f.name)}</span>
          </div>
          <span class="feature-value-badge">${escapeHtml(String(f.value))}</span>
        </div>
        <div class="feature-desc">${escapeHtml(f.reason)}</div>
      `;
      featureGrid.appendChild(item);
    });
  }

  // ============================================================================
  // 7. Session Scan History
  // ============================================================================
  function addToHistory(item) {
    // Add to in-memory array (max 20 items)
    scanHistory.unshift({
      url: item.url,
      prediction: item.prediction,
      is_phishing: item.is_phishing,
      confidence: item.confidence,
      risk_level: item.risk_level
    });

    if (scanHistory.length > 20) scanHistory.pop();
    renderHistoryTable();
  }

  function renderHistoryTable() {
    if (scanHistory.length === 0) {
      historyTableBody.innerHTML = `
        <tr class="empty-row">
          <td colspan="5">No scans performed yet in this session. Try analyzing a URL above!</td>
        </tr>
      `;
      clearHistoryBtn.style.display = 'none';
      return;
    }

    clearHistoryBtn.style.display = 'inline-block';
    historyTableBody.innerHTML = '';

    scanHistory.forEach((scan, index) => {
      const tr = document.createElement('tr');
      const isPhish = scan.is_phishing;
      const badgeClass = isPhish ? 'phish' : 'safe';

      tr.innerHTML = `
        <td><span class="history-url" title="${escapeHtml(scan.url)}">${escapeHtml(scan.url)}</span></td>
        <td>
          <span class="chip-dot ${badgeClass}"></span>
          <strong>${scan.prediction}</strong>
        </td>
        <td>${scan.confidence.toFixed(1)}%</td>
        <td><span class="risk-badge ${(scan.risk_level || 'Safe').toLowerCase()}">${scan.risk_level}</span></td>
        <td>
          <button class="retest-btn" data-url="${escapeHtml(scan.url)}">Re-scan</button>
        </td>
      `;
      historyTableBody.appendChild(tr);
    });

    // Attach retest handlers
    document.querySelectorAll('.retest-btn').forEach(btn => {
      btn.addEventListener('click', (e) => {
        const u = e.currentTarget.getAttribute('data-url');
        urlInput.value = u;
        clearBtn.style.display = 'block';
        performScan(u);
      });
    });
  }

  clearHistoryBtn.addEventListener('click', () => {
    scanHistory = [];
    renderHistoryTable();
  });

  // Utility to escape HTML to prevent XSS
  function escapeHtml(str) {
    if (!str) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }

  // Initial load
  checkHealth();
  loadMetrics();
});
