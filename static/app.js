/**
 * API Sentinel - Frontend Controller
 * Handles interactive scanning, animated progress tickers, dynamic results cards, and PDF report downloads.
 */

document.addEventListener('DOMContentLoaded', () => {
    const scanForm = document.getElementById('scanForm');
    const urlInput = document.getElementById('urlInput');
    const clearBtn = document.getElementById('clearBtn');
    const submitBtn = document.getElementById('submitBtn');
    const btnText = document.getElementById('btnText');
    const btnIcon = document.getElementById('btnIcon');
    
    const scanLoader = document.getElementById('scanLoader');
    const loaderStatusText = document.getElementById('loaderStatusText');
    const progressBar = document.getElementById('progressBar');
    
    const errorBanner = document.getElementById('errorBanner');
    const errorMessage = document.getElementById('errorMessage');
    const closeErrorBtn = document.getElementById('closeErrorBtn');
    
    const resultsContainer = document.getElementById('results');
    const resultsGrid = document.getElementById('resultsGrid');
    const downloadLink = document.getElementById('downloadLink');
    const scannedUrlDisplay = document.getElementById('scannedUrlDisplay');
    const scannedTimestamp = document.getElementById('scannedTimestamp');
    
    const statTotal = document.getElementById('statTotal');
    const statThreats = document.getElementById('statThreats');
    const statPassed = document.getElementById('statPassed');
    const statWarnings = document.getElementById('statWarnings');
    
    const presetButtons = document.querySelectorAll('.preset-btn');

    // Preset URL click handlers
    presetButtons.forEach(btn => {
        btn.addEventListener('click', () => {
            const url = btn.getAttribute('data-url');
            if (url) {
                urlInput.value = url;
                urlInput.focus();
            }
        });
    });

    // Clear input button
    if (clearBtn) {
        clearBtn.addEventListener('click', () => {
            urlInput.value = '';
            urlInput.focus();
        });
    }

    // Close error banner
    if (closeErrorBtn) {
        closeErrorBtn.addEventListener('click', () => {
            errorBanner.classList.add('hidden');
        });
    }

    // Vulnerability module icon & description mapping
    const moduleMeta = {
        'SQL Injection': {
            icon: 'fa-solid fa-database',
            iconColor: 'text-rose-400',
            iconBg: 'bg-rose-500/10 border-rose-500/20',
            desc: 'Tests database sanitation and query parameter escaping.'
        },
        'XSS': {
            icon: 'fa-solid fa-code',
            iconColor: 'text-amber-400',
            iconBg: 'bg-amber-500/10 border-amber-500/20',
            desc: 'Audits unescaped script tag injection in response body.'
        },
        'CSRF': {
            icon: 'fa-solid fa-fingerprint',
            iconColor: 'text-blue-400',
            iconBg: 'bg-blue-500/10 border-blue-500/20',
            desc: 'Evaluates anti-CSRF tokens in headers, body, and cookies.'
        },
        'Command Injection': {
            icon: 'fa-solid fa-terminal',
            iconColor: 'text-purple-400',
            iconBg: 'bg-purple-500/10 border-purple-500/20',
            desc: 'Checks for unauthorized OS shell command execution.'
        }
    };

    // Scan Form Submission
    scanForm.addEventListener('submit', async (e) => {
        e.preventDefault();

        const url = urlInput.value.trim();
        if (!url) return;

        // Reset UI states
        errorBanner.classList.add('hidden');
        resultsContainer.classList.add('hidden');
        resultsGrid.innerHTML = '';
        downloadLink.classList.add('hidden');

        // Set Loading state
        submitBtn.disabled = true;
        btnText.textContent = 'Scanning...';
        btnIcon.className = 'fa-solid fa-circle-notch fa-spin text-base';
        scanLoader.classList.remove('hidden');
        progressBar.style.width = '10%';

        // Simulated progressive scanner status ticker
        const progressSteps = [
            { text: 'Connecting to API endpoint...', width: '25%' },
            { text: 'Injecting SQL vulnerability probes...', width: '45%' },
            { text: 'Fuzzing input fields with XSS vectors...', width: '65%' },
            { text: 'Analyzing anti-CSRF token defenses...', width: '80%' },
            { text: 'Testing OS shell command payloads...', width: '92%' },
            { text: 'Generating executive PDF report...', width: '98%' }
        ];

        let stepIndex = 0;
        const progressInterval = setInterval(() => {
            if (stepIndex < progressSteps.length) {
                loaderStatusText.textContent = progressSteps[stepIndex].text;
                progressBar.style.width = progressSteps[stepIndex].width;
                stepIndex++;
            }
        }, 600);

        try {
            const response = await fetch('/scan', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ url })
            });

            clearInterval(progressInterval);
            progressBar.style.width = '100%';

            if (!response.ok) {
                const errData = await response.json().catch(() => ({}));
                throw new Error(errData.error || `HTTP ${response.status}: Scan failed.`);
            }

            const data = await response.json();
            renderResults(url, data);

        } catch (error) {
            clearInterval(progressInterval);
            errorMessage.textContent = error.message || 'Unable to scan endpoint. Check the target URL and network connection.';
            errorBanner.classList.remove('hidden');
        } finally {
            // Restore button state
            submitBtn.disabled = false;
            btnText.textContent = 'Launch Scan';
            btnIcon.className = 'fa-solid fa-radar text-base';
            scanLoader.classList.add('hidden');
            progressBar.style.width = '0%';
        }
    });

    // Render Results Cards
    function renderResults(scannedUrl, data) {
        let threatsCount = 0;
        let passedCount = 0;
        let warningsCount = 0;
        let totalCount = 0;

        scannedUrlDisplay.textContent = scannedUrl;
        scannedTimestamp.textContent = new Date().toLocaleString();

        const results = data.results || {};

        for (const [moduleName, status] of Object.entries(results)) {
            totalCount++;
            const statusLower = status.toLowerCase();

            let statusType = 'warning'; // 'danger', 'success', 'warning'
            let badgeBg = 'bg-amber-500/15 text-amber-300 border-amber-500/30';
            let badgeText = 'WARNING';
            let cardBorder = 'border-slate-800 hover:border-amber-500/40';

            if (statusLower.includes('detected')) {
                statusType = 'danger';
                threatsCount++;
                badgeBg = 'bg-red-500/15 text-red-300 border-red-500/30';
                badgeText = 'VULNERABLE';
                cardBorder = 'border-red-500/40 hover:border-red-500/70 shadow-lg shadow-red-950/30';
            } else if (statusLower.includes('no ') || statusLower.includes('clean') || statusLower.includes('passed')) {
                statusType = 'success';
                passedCount++;
                badgeBg = 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30';
                badgeText = 'SECURE';
                cardBorder = 'border-slate-800 hover:border-emerald-500/40';
            } else {
                warningsCount++;
            }

            const meta = moduleMeta[moduleName] || {
                icon: 'fa-solid fa-shield',
                iconColor: 'text-cyan-400',
                iconBg: 'bg-cyan-500/10 border-cyan-500/20',
                desc: 'Security assessment module.'
            };

            const card = document.createElement('div');
            card.className = `p-5 rounded-2xl bg-slate-900/80 backdrop-blur-xl border ${cardBorder} transition-all duration-200 flex flex-col justify-between`;

            card.innerHTML = `
                <div>
                    <div class="flex items-center justify-between gap-2 mb-3">
                        <div class="flex items-center gap-3">
                            <div class="w-9 h-9 rounded-xl ${meta.iconBg} border flex items-center justify-center">
                                <i class="${meta.icon} ${meta.iconColor} text-sm"></i>
                            </div>
                            <div>
                                <h3 class="font-bold text-sm text-white">${moduleName}</h3>
                                <p class="text-[11px] text-slate-400">${meta.desc}</p>
                            </div>
                        </div>
                        <span class="px-2.5 py-1 rounded-md text-[10px] font-mono font-bold tracking-wider uppercase border ${badgeBg}">
                            ${badgeText}
                        </span>
                    </div>
                    
                    <div class="mt-3 p-3 rounded-xl bg-slate-950/70 border border-slate-800/80 font-mono text-xs text-slate-300 leading-relaxed break-words">
                        ${escapeHtml(status)}
                    </div>
                </div>
            `;

            resultsGrid.appendChild(card);
        }

        // Update Summary Stats
        statTotal.textContent = totalCount;
        statThreats.textContent = threatsCount;
        statPassed.textContent = passedCount;
        statWarnings.textContent = warningsCount;

        // Update PDF Download Link
        if (data.pdf_report) {
            downloadLink.href = data.pdf_report;
            downloadLink.classList.remove('hidden');
        }

        // Display results container and smooth scroll into view
        resultsContainer.classList.remove('hidden');
        resultsContainer.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }

    // Helper: Escape HTML to avoid XSS in client-side rendering
    function escapeHtml(str) {
        const div = document.createElement('div');
        div.textContent = str;
        return div.innerHTML;
    }
});