// This function will be called when the pywebview API is ready.
async function onPywebviewReady() {
    // DOM Elements
    const targetsInput = document.getElementById('targets');
    const workersInput = document.getElementById('workers');
    const onlineLookupCheckbox = document.getElementById('online-lookup');
    const nmapAggressiveCheckbox = document.getElementById('nmap-aggressive');
    const startScanBtn = document.getElementById('start-scan');
    const stopScanBtn = document.getElementById('stop-scan');
    const exportCsvBtn = document.getElementById('export-csv');
    const loadFileBtn = document.getElementById('load-file-btn');
    const resultsBody = document.getElementById('results-body');
    const resultsTable = document.getElementById('results-table');
    const statusText = document.getElementById('status-text');
    const progressBar = document.getElementById('progress-bar');
    const nmapModal = document.getElementById('nmap-modal');
    const nmapOutput = document.getElementById('nmap-output');
    const closeModalBtn = document.querySelector('.close-button');
    const filterInput = document.getElementById('filter');
    const clearFilterBtn = document.getElementById('clear-filter');

    let allResults = []; // Store all scan results for filtering/sorting
    let sortState = { column: 'ip', direction: 'asc' };

    // --- Populate initial data from Python ---
    try {
        targetsInput.value = await pywebview.api.get_default_target();
    } catch (e) {
        console.error("Could not get default target:", e);
    }
    
    // --- Event Listeners ---
    startScanBtn.addEventListener('click', startScan);
    stopScanBtn.addEventListener('click', stopScan);
    exportCsvBtn.addEventListener('click', exportCsv);
    loadFileBtn.addEventListener('click', () => pywebview.api.load_file());
    clearFilterBtn.addEventListener('click', () => {
        filterInput.value = '';
        renderTable();
    });
    filterInput.addEventListener('input', () => renderTable());
    closeModalBtn.addEventListener('click', () => nmapModal.style.display = 'none');

    // Hide context menu if clicking anywhere else
    window.addEventListener('click', () => document.querySelector('.context-menu')?.remove());
    
    // Add sorting listeners to table headers
    resultsTable.querySelector('thead').addEventListener('click', (e) => {
        const header = e.target.closest('th.sortable');
        if (!header) return;

        const column = header.dataset.column;
        if (sortState.column === column) {
            sortState.direction = sortState.direction === 'asc' ? 'desc' : 'asc';
        } else {
            sortState.column = column;
            sortState.direction = 'asc';
        }
        renderTable();
    });

    // Add context menu listener to table body
    resultsBody.addEventListener('contextmenu', (e) => {
        const row = e.target.closest('tr');
        if (!row) return;

        e.preventDefault();
        document.querySelector('.context-menu')?.remove();

        const ip = row.cells[0].textContent;
        const menu = document.createElement('div');
        menu.className = 'context-menu';
        menu.style.left = `${e.clientX}px`;
        menu.style.top = `${e.clientY}px`;
        menu.innerHTML = `
            <div class="menu-item" data-action="copy-ip">Copy IP</div>
            <div class="menu-item" data-action="open-browser">Open http://${ip}</div>
            <hr class="menu-separator">
            <div class="menu-item" data-action="nmap-scan">Nmap Scan this host</div>
        `;
        document.body.appendChild(menu);

        menu.addEventListener('click', (event) => {
            const action = event.target.dataset.action;
            const isNmapAggressive = nmapAggressiveCheckbox.checked;

            if (action === 'copy-ip') pywebview.api.copy_to_clipboard(ip);
            else if (action === 'open-browser') pywebview.api.open_external_browser(ip);
            else if (action === 'nmap-scan') pywebview.api.nmap_scan(ip, isNmapAggressive);
        });
    });

    // --- Core Functions ---
    function startScan() {
        allResults = [];
        renderTable();
        updateStatus('Starting scan...');
        startScanBtn.disabled = true;
        stopScanBtn.disabled = false;
        
        const params = {
            targets: targetsInput.value,
            workers: workersInput.value,
            onlineLookup: onlineLookupCheckbox.checked
        };
        pywebview.api.start_scan(params);
    }

    function stopScan() {
        pywebview.api.stop_scan();
    }
    
    function getVisibleTableData() {
        return Array.from(resultsBody.querySelectorAll('tr')).map(row => 
            Array.from(row.cells).map(cell => cell.textContent)
        );
    }

    function exportCsv() {
        const data = getVisibleTableData();
        if (data.length > 0) {
            pywebview.api.export_csv(data);
        } else {
            updateStatus('No data to export.');
        }
    }
    
    function renderTable() {
        const filterText = filterInput.value.toLowerCase();
        
        // 1. Filter
        const filteredResults = allResults.filter(r => {
            if (!filterText) return true;
            return Object.values(r).some(val => String(val).toLowerCase().includes(filterText));
        });

        // 2. Sort
        filteredResults.sort((a, b) => {
            const valA = a[sortState.column] || '';
            const valB = b[sortState.column] || '';

            let comparison = 0;
            if (sortState.column === 'ip') {
                const partsA = valA.split('.').map(Number);
                const partsB = valB.split('.').map(Number);
                for (let i = 0; i < 4; i++) {
                    if (partsA[i] !== partsB[i]) {
                        comparison = partsA[i] - partsB[i];
                        break;
                    }
                }
            } else {
                comparison = valA.localeCompare(valB, undefined, { numeric: true, sensitivity: 'base' });
            }
            return sortState.direction === 'asc' ? comparison : -comparison;
        });
        
        // 3. Update header styles for sorting indicators
        document.querySelectorAll('#results-table th.sortable').forEach(th => {
            th.classList.remove('sort-asc', 'sort-desc');
            if (th.dataset.column === sortState.column) {
                th.classList.add(`sort-${sortState.direction}`);
            }
        });

        // 4. Build and inject HTML
        resultsBody.innerHTML = filteredResults.map(r => `
            <tr id="ip-${r.ip.replace(/\./g, '-')}">
                <td>${r.ip || ''}</td>
                <td>${r.hostname || ''}</td>
                <td>${r.mac || ''}</td>
                <td>${r.vendor || ''}</td>
            </tr>`
        ).join('');
    }

    // --- Global Functions Callable from Python ---
    window.addScanResult = (result) => {
        // Find if the host is already in our list
        const index = allResults.findIndex(item => item.ip === result.ip);
        if (index > -1) {
            allResults[index] = result; // Update it
        } else {
            allResults.push(result); // Add new
        }
        renderTable(); // Re-render the table with new data
    };

    window.updateProgress = (done, total) => {
        const percent = total > 0 ? (done / total) * 100 : 0;
        progressBar.style.width = `${percent}%`;
        statusText.textContent = `Pinging... ${done} / ${total}`;
    };

    window.updateStatus = (message) => {
        statusText.textContent = message;
    };
    
    window.scanComplete = (hostCount) => {
        updateStatus(`Scan complete: ${hostCount} host(s) found.`);
        startScanBtn.disabled = false;
        stopScanBtn.disabled = true;
    };
    
    window.scanStopped = () => {
        updateStatus('Scan stopped by user.');
        startScanBtn.disabled = false;
        stopScanBtn.disabled = true;
    };
    
    window.showNmapResult = (resultText) => {
        nmapOutput.textContent = resultText;
        nmapModal.style.display = 'flex';
    };

    window.updateTargetsInput = (content) => {
        targetsInput.value = content;
    };

    // Initialize UI
    (async () => {
        targetsInput.value = await pywebview.api.get_default_target();
    })();
}

// Attach the main function to the pywebviewready event
window.addEventListener('pywebviewready', onPywebviewReady);