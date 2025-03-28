/**
 * Anomalyze Documentation - Enhanced Interactive Features
 * Version 2.3 - August 2023
 * Features: Security visualization, interactive CLI, real-time content updates
 */

document.addEventListener('DOMContentLoaded', function() {
    'use strict';

    // ======================
    // Constants & Config
    // ======================
    const SECURITY_COLORS = {
        critical: '#ff5e5e',
        high: '#ff9a3e',
        medium: '#ffcc3e',
        low: '#5ec7ff'
    };

    const DEBOUNCE_DELAY = 200;
    const LOCALSTORAGE_KEY = 'anomalyze_docs_preferences';

    // ======================
    // Core Functions
    // ======================

    /**
     * Initialize all documentation enhancements
     */
    function initDocumentationFeatures() {
        addCopyButtons();
        setupInteractiveCLI();
        enhanceSecurityVisualizations();
        setupThemeWatcher();
        setupDynamicContent();
        setupDiagramRenderers();
        addKeyboardNavigation();
        setupVersionSelector();
    }

    // ======================
    // Security Visualization
    // ======================

    function enhanceSecurityVisualizations() {
        // Add severity indicators
        document.querySelectorAll('.security-severity').forEach(el => {
            const severity = el.textContent.trim().toLowerCase();
            if (SECURITY_COLORS[severity]) {
                el.style.backgroundColor = SECURITY_COLORS[severity];
                el.style.color = 'white';
                el.style.padding = '2px 8px';
                el.style.borderRadius = '4px';
                el.style.fontWeight = 'bold';
            }
        });

        // Interactive threat models
        document.querySelectorAll('.threat-model').forEach(model => {
            model.addEventListener('click', function() {
                this.classList.toggle('expanded');
            });
        });
    }

    // ======================
    // Code & CLI Enhancements
    // ======================

    function addCopyButtons() {
        const codeBlocks = document.querySelectorAll('pre > code, .cli-command');
        
        codeBlocks.forEach(codeBlock => {
            const container = codeBlock.closest('pre') || codeBlock.parentElement;
            if (container.querySelector('.copy-btn')) return;

            const btn = document.createElement('button');
            btn.className = 'copy-btn';
            btn.innerHTML = '<i class="far fa-copy"></i>';
            btn.title = 'Copy to clipboard';
            btn.ariaLabel = 'Copy code to clipboard';

            btn.addEventListener('click', async () => {
                try {
                    await navigator.clipboard.writeText(codeBlock.textContent);
                    btn.innerHTML = '<i class="fas fa-check"></i>';
                    setTimeout(() => {
                        btn.innerHTML = '<i class="far fa-copy"></i>';
                    }, 2000);
                } catch (err) {
                    console.error('Copy failed:', err);
                    btn.innerHTML = '<i class="fas fa-times"></i>';
                }
            });

            container.style.position = 'relative';
            container.appendChild(btn);
        });
    }

    function setupInteractiveCLI() {
        // Make CLI commands interactive
        document.querySelectorAll('.cli-command').forEach(cmd => {
            cmd.addEventListener('mouseenter', () => {
                cmd.style.boxShadow = '0 0 0 2px rgba(110, 64, 201, 0.3)';
            });
            cmd.addEventListener('mouseleave', () => {
                cmd.style.boxShadow = 'none';
            });
            
            // Add click-to-execute simulation
            if (cmd.dataset.command) {
                cmd.addEventListener('click', () => {
                    simulateCommandExecution(cmd.dataset.command);
                });
            }
        });
    }

    function simulateCommandExecution(command) {
        const terminal = document.querySelector('.terminal-output') || createTerminalOutput();
        terminal.innerHTML += `<div class="command-line">$ ${command}</div>`;
        terminal.scrollTop = terminal.scrollHeight;
    }

    // ======================
    // Diagram & Chart Support
    // ======================

    function setupDiagramRenderers() {
        // Mermaid.js initialization
        if (typeof mermaid !== 'undefined') {
            mermaid.initialize({
                startOnLoad: true,
                theme: 'dark',
                securityLevel: 'strict',
                flowchart: {
                    useMaxWidth: true,
                    htmlLabels: true
                }
            });
        }

        // Chart.js initialization
        document.querySelectorAll('.anomalyze-chart').forEach(chartEl => {
            try {
                const config = JSON.parse(chartEl.dataset.config);
                new Chart(chartEl.getContext('2d'), config);
            } catch (e) {
                console.error('Chart initialization failed:', e);
            }
        });
    }

    // ======================
    // UI Enhancements
    // ======================

    function setupThemeWatcher() {
        const observer = new MutationObserver(debounce(() => {
            if (document.documentElement.classList.contains('dark-mode')) {
                document.dispatchEvent(new CustomEvent('themeChanged', { detail: 'dark' }));
            } else {
                document.dispatchEvent(new CustomEvent('themeChanged', { detail: 'light' }));
            }
        }, DEBOUNCE_DELAY));

        observer.observe(document.documentElement, {
            attributes: true,
            attributeFilter: ['class']
        });
    }

    function setupDynamicContent() {
        // Lazy load images
        const lazyImages = document.querySelectorAll('img.lazy');
        const imgObserver = new IntersectionObserver((entries) => {
            entries.forEach(entry => {
                if (entry.isIntersecting) {
                    const img = entry.target;
                    img.src = img.dataset.src;
                    img.classList.remove('lazy');
                    imgObserver.unobserve(img);
                }
            });
        });

        lazyImages.forEach(img => imgObserver.observe(img));
    }

    function addKeyboardNavigation() {
        document.addEventListener('keydown', (e) => {
            // Ctrl+K for search
            if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
                e.preventDefault();
                document.querySelector('.md-search__input').focus();
            }
        });
    }

    function setupVersionSelector() {
        const versionSelect = document.querySelector('.version-selector');
        if (versionSelect) {
            versionSelect.addEventListener('change', (e) => {
                window.location.href = e.target.value;
            });
        }
    }

    // ======================
    // Utility Functions
    // ======================

    function debounce(func, wait) {
        let timeout;
        return function executedFunction(...args) {
            const later = () => {
                clearTimeout(timeout);
                func(...args);
            };
            clearTimeout(timeout);
            timeout = setTimeout(later, wait);
        };
    }

    function createTerminalOutput() {
        const terminal = document.createElement('div');
        terminal.className = 'terminal-output';
        terminal.style.backgroundColor = '#1e1e1e';
        terminal.style.color = '#d4d4d4';
        terminal.style.padding = '1em';
        terminal.style.borderRadius = '4px';
        terminal.style.fontFamily = 'Fira Code, monospace';
        terminal.style.overflowX = 'auto';
        document.body.appendChild(terminal);
        return terminal;
    }

    // ======================
    // Initialization
    // ======================

    // Load required libraries
    function loadDependencies() {
        const loadChartJS = new Promise((resolve) => {
            if (typeof Chart !== 'undefined') return resolve();
            const script = document.createElement('script');
            script.src = 'https://cdn.jsdelivr.net/npm/chart.js@3.7.1/dist/chart.min.js';
            script.onload = resolve;
            document.head.appendChild(script);
        });

        const loadMermaid = new Promise((resolve) => {
            if (typeof mermaid !== 'undefined') return resolve();
            const script = document.createElement('script');
            script.src = 'https://cdn.jsdelivr.net/npm/mermaid@10.2.4/dist/mermaid.min.js';
            script.onload = resolve;
            document.head.appendChild(script);
        });

        Promise.all([loadChartJS, loadMermaid])
            .then(initDocumentationFeatures)
            .catch(console.error);
    }

    // Start initialization
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', loadDependencies);
    } else {
        loadDependencies();
    }
});
