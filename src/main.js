import { getServiceIcon } from './icons.js';

// Safe Tauri Invoke helper
const invoke = window.__TAURI__ ? window.__TAURI__.core.invoke : async (cmd, args) => {
  console.warn(`Tauri bridge not available. Mocking ${cmd}`, args);
  return null;
};

// Application State
let appState = {
  isInitialized: false,
  isUnlocked: false,
  accounts: [],
  searchQuery: '',
  timerInterval: null,
  stagedMigrationAccounts: [],
  theme: 'dark'
};

// DOM References
const lockScreen = document.getElementById('lock-screen');
const lockTitle = document.getElementById('lock-title');
const lockSubtitle = document.getElementById('lock-subtitle');
const lockForm = document.getElementById('lock-form');
const masterPasswordInput = document.getElementById('master-password-input');
const confirmPasswordInput = document.getElementById('confirm-password-input');
const setupConfirmGroup = document.getElementById('setup-confirm-group');
const lockBtn = document.getElementById('lock-btn');

const accountList = document.getElementById('account-list');
const emptyState = document.getElementById('empty-state');
const searchInput = document.getElementById('search-input');
const themeToggle = document.getElementById('theme-toggle');
const lockVaultBtn = document.getElementById('lock-vault-btn');
const backupBtn = document.getElementById('backup-btn');

const fabAdd = document.getElementById('fab-add');
const modalActions = document.getElementById('modal-actions');
const modalManual = document.getElementById('modal-manual');
const modalBatch = document.getElementById('modal-batch-import');
const modalBackup = document.getElementById('modal-backup');

const dropOverlay = document.getElementById('drop-overlay');
const qrFileInput = document.getElementById('qr-file-input');
const backupFileInput = document.getElementById('backup-file-input');

// --- Initialization ---
window.addEventListener('DOMContentLoaded', async () => {
  setupTheme();
  setupEventListeners();
  await checkVaultStatus();
});

// --- Theme Management ---
function setupTheme() {
  const saved = localStorage.getItem('google-auth-theme') || 'dark';
  setTheme(saved);
}

function setTheme(theme) {
  appState.theme = theme;
  document.documentElement.setAttribute('data-theme', theme);
  localStorage.setItem('google-auth-theme', theme);
}

themeToggle.addEventListener('click', () => {
  const next = appState.theme === 'dark' ? 'light' : 'dark';
  setTheme(next);
});

// --- Vault State & Lock Screen ---
async function checkVaultStatus() {
  try {
    const status = await invoke('check_vault_status');
    appState.isInitialized = status?.is_initialized ?? false;
    appState.isUnlocked = status?.is_unlocked ?? false;

    if (!appState.isInitialized) {
      showMasterPasswordSetup();
    } else if (!appState.isUnlocked) {
      showLockScreen();
    } else {
      hideLockScreen();
      startTOTPLoop();
    }
  } catch (err) {
    showToast(`Status check error: ${err}`, 'error');
  }
}

function showMasterPasswordSetup() {
  lockTitle.textContent = 'Setup Master Password';
  lockSubtitle.textContent = 'Create a secure master password to encrypt your 2FA tokens with AES-256-GCM.';
  setupConfirmGroup.style.display = 'flex';
  lockBtn.textContent = 'Create Vault';
  lockScreen.classList.remove('hidden');
  masterPasswordInput.value = '';
  confirmPasswordInput.value = '';
  masterPasswordInput.focus();
}

function showLockScreen() {
  lockTitle.textContent = 'Unlock Vault';
  lockSubtitle.textContent = 'Enter your master password to decrypt your 2FA security tokens.';
  setupConfirmGroup.style.display = 'none';
  lockBtn.textContent = 'Unlock';
  lockScreen.classList.remove('hidden');
  masterPasswordInput.value = '';
  masterPasswordInput.focus();
}

function hideLockScreen() {
  lockScreen.classList.add('hidden');
}

lockForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  const password = masterPasswordInput.value.trim();

  if (!appState.isInitialized) {
    const confirm = confirmPasswordInput.value.trim();
    if (password.length < 4) {
      showToast('Password must be at least 4 characters', 'error');
      return;
    }
    if (password !== confirm) {
      showToast('Passwords do not match', 'error');
      confirmPasswordInput.classList.add('shake');
      setTimeout(() => confirmPasswordInput.classList.remove('shake'), 400);
      return;
    }

    try {
      await invoke('setup_master_password', { password });
      appState.isInitialized = true;
      appState.isUnlocked = true;
      hideLockScreen();
      showToast('Vault created and secured!');
      startTOTPLoop();
    } catch (err) {
      showToast(`Setup error: ${err}`, 'error');
    }
  } else {
    try {
      await invoke('unlock_vault', { password });
      appState.isUnlocked = true;
      hideLockScreen();
      showToast('Vault unlocked');
      startTOTPLoop();
    } catch (err) {
      showToast(err.toString(), 'error');
      lockForm.classList.add('shake');
      setTimeout(() => lockForm.classList.remove('shake'), 400);
      masterPasswordInput.select();
    }
  }
});

lockVaultBtn.addEventListener('click', async () => {
  try {
    await invoke('lock_vault');
    appState.isUnlocked = false;
    stopTOTPLoop();
    accountList.innerHTML = '';
    showLockScreen();
    showToast('Vault locked');
  } catch (err) {
    showToast(`Error: ${err}`, 'error');
  }
});

// --- TOTP Loop & Account Rendering ---
function startTOTPLoop() {
  stopTOTPLoop();
  fetchAndRenderAccounts();
  appState.timerInterval = setInterval(fetchAndRenderAccounts, 1000);
}

function stopTOTPLoop() {
  if (appState.timerInterval) {
    clearInterval(appState.timerInterval);
    appState.timerInterval = null;
  }
}

async function fetchAndRenderAccounts() {
  if (!appState.isUnlocked) return;
  try {
    const accounts = await invoke('get_accounts_with_codes');
    appState.accounts = accounts || [];
    renderAccountList();
  } catch (err) {
    console.error('Failed to fetch accounts:', err);
  }
}

function renderAccountList() {
  const query = appState.searchQuery.toLowerCase();
  const filtered = appState.accounts.filter(a =>
    a.issuer.toLowerCase().includes(query) || a.name.toLowerCase().includes(query)
  );

  if (appState.accounts.length === 0) {
    emptyState.style.display = 'flex';
    accountList.style.display = 'none';
    return;
  }

  emptyState.style.display = 'none';
  accountList.style.display = 'flex';

  accountList.innerHTML = '';

  const circumference = 2 * Math.PI * 15; // r = 15

  filtered.forEach(acc => {
    const card = document.createElement('div');
    card.className = 'account-card';
    card.setAttribute('data-id', acc.id);

    const isWarning = acc.remaining_seconds <= 5;
    const strokeDashoffset = circumference * (1 - acc.progress);

    card.innerHTML = `
      <div class="card-left">
        <div class="service-avatar">
          ${getServiceIcon(acc.issuer, acc.name)}
        </div>
        <div class="account-info">
          <span class="issuer-name">${escapeHtml(acc.issuer)}</span>
          <span class="account-code ${isWarning ? 'warning' : ''}">${acc.code}</span>
          <span class="account-label">${escapeHtml(acc.name)}</span>
        </div>
      </div>

      <div class="card-right">
        <div class="timer-circle-container" title="${acc.remaining_seconds}s remaining">
          <svg class="timer-svg" viewBox="0 0 38 38">
            <circle class="timer-bg" cx="19" cy="19" r="15"></circle>
            <circle class="timer-progress ${isWarning ? 'warning' : ''}" cx="19" cy="19" r="15"
              stroke-dasharray="${circumference}"
              stroke-dashoffset="${strokeDashoffset}"></circle>
          </svg>
          <span class="timer-text">${acc.remaining_seconds}</span>
        </div>

        <button class="card-delete-btn" title="Delete Account" data-delete-id="${acc.id}">
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <polyline points="3 6 5 6 21 6"></polyline>
            <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path>
          </svg>
        </button>
      </div>
    `;

    // Click card to copy
    card.addEventListener('click', (e) => {
      if (e.target.closest('.card-delete-btn')) return;
      copyCodeToClipboard(acc.code.replace(/\s+/g, ''), acc.issuer);
    });

    // Delete button
    const delBtn = card.querySelector('.card-delete-btn');
    delBtn.addEventListener('click', async (e) => {
      e.stopPropagation();
      if (confirm(`Remove 2FA code for ${acc.issuer} (${acc.name})?`)) {
        await invoke('delete_account', { id: acc.id });
        showToast(`Deleted ${acc.issuer}`);
        fetchAndRenderAccounts();
      }
    });

    accountList.appendChild(card);
  });
}

function copyCodeToClipboard(rawCode, issuer) {
  navigator.clipboard.writeText(rawCode).then(() => {
    showToast(`Copied ${rawCode} for ${issuer}!`);
  }).catch(() => {
    showToast('Failed to copy code', 'error');
  });
}

// --- Search Filter ---
searchInput.addEventListener('input', (e) => {
  appState.searchQuery = e.target.value.trim();
  renderAccountList();
});

// --- Modals Management ---
function openModal(modal) {
  closeAllModals();
  modal.classList.add('active');
}

function closeAllModals() {
  document.querySelectorAll('.modal-overlay').forEach(m => m.classList.remove('active'));
}

document.querySelectorAll('.modal-close').forEach(btn => {
  btn.addEventListener('click', closeAllModals);
});

// Close modal on background click
document.querySelectorAll('.modal-overlay').forEach(modal => {
  modal.addEventListener('click', (e) => {
    if (e.target === modal) closeAllModals();
  });
});

// --- Floating Action Button & Menu ---
fabAdd.addEventListener('click', () => openModal(modalActions));

document.getElementById('opt-upload').addEventListener('click', () => {
  closeAllModals();
  qrFileInput.click();
});

document.getElementById('opt-manual').addEventListener('click', () => {
  closeAllModals();
  openModal(modalManual);
  document.getElementById('input-issuer').focus();
});

// Empty state shortcuts
document.getElementById('empty-upload-btn').addEventListener('click', () => qrFileInput.click());
document.getElementById('empty-manual-btn').addEventListener('click', () => {
  openModal(modalManual);
  document.getElementById('input-issuer').focus();
});

// --- Manual Account Entry Form ---
document.getElementById('manual-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const issuer = document.getElementById('input-issuer').value.trim();
  const name = document.getElementById('input-name').value.trim();
  const secret = document.getElementById('input-secret').value.trim();
  const algorithm = document.getElementById('input-algo').value;

  try {
    await invoke('add_manual_account', {
      issuer,
      name,
      secret,
      algorithm,
      digits: 6,
      period: 30
    });
    closeAllModals();
    document.getElementById('manual-form').reset();
    showToast(`Added ${issuer} successfully!`);
    fetchAndRenderAccounts();
  } catch (err) {
    showToast(`Error: ${err}`, 'error');
  }
});

// --- Image File Upload ---
qrFileInput.addEventListener('change', async (e) => {
  const file = e.target.files[0];
  if (!file) return;
  await handleQRImageFile(file);
  qrFileInput.value = '';
});

async function handleQRImageFile(file) {
  const reader = new FileReader();
  reader.onload = async () => {
    const base64Data = reader.result;
    await processQRBase64(base64Data);
  };
  reader.readAsDataURL(file);
}

// --- Drag and Drop Handling (Website QR / Image File) ---
function setupEventListeners() {
  window.addEventListener('dragenter', (e) => {
    e.preventDefault();
    dropOverlay.classList.add('active');
  });

  window.addEventListener('dragover', (e) => {
    e.preventDefault();
  });

  dropOverlay.addEventListener('dragleave', (e) => {
    if (e.relatedTarget === null) {
      dropOverlay.classList.remove('active');
    }
  });

  window.addEventListener('drop', async (e) => {
    e.preventDefault();
    dropOverlay.classList.remove('active');

    // 1. Files drop (saved images)
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      const file = e.dataTransfer.files[0];
      if (file.type.startsWith('image/')) {
        await handleQRImageFile(file);
        return;
      }
    }

    // 2. Dragged image from web browser
    const html = e.dataTransfer.getData('text/html');
    if (html) {
      const doc = new DOMParser().parseFromString(html, 'text/html');
      const img = doc.querySelector('img');
      if (img && img.src) {
        await processImageUrl(img.src);
        return;
      }
    }

    const uri = e.dataTransfer.getData('text/uri-list');
    if (uri && (uri.startsWith('http') || uri.startsWith('data:image'))) {
      await processImageUrl(uri);
      return;
    }
  });

  // 3. Paste directly from Clipboard (Ctrl + V)
  window.addEventListener('paste', async (e) => {
    const items = e.clipboardData?.items;
    if (!items) return;

    for (let i = 0; i < items.length; i++) {
      if (items[i].type.startsWith('image/')) {
        const blob = items[i].getAsFile();
        if (blob) {
          showToast('Scanning QR from clipboard...');
          await handleQRImageFile(blob);
          return;
        }
      }
    }
  });
}

async function processImageUrl(url) {
  try {
    showToast('Reading dropped image...');
    const response = await fetch(url);
    const blob = await response.blob();
    await handleQRImageFile(blob);
  } catch (err) {
    showToast(`Could not load dropped image: ${err}`, 'error');
  }
}

// --- Process Base64 QR Image through Rust Backend ---
async function processQRBase64(base64Str) {
  try {
    const result = await invoke('decode_qr_image', { imageBase64: base64Str });
    if (!result) {
      showToast('No QR code detected', 'error');
      return;
    }

    playChime();
    if (result.mode === 'single') {
      await invoke('import_parsed_accounts', { accounts: result.accounts });
      showToast(`Added ${result.accounts[0].issuer} (${result.accounts[0].name})`);
      fetchAndRenderAccounts();
    } else if (result.mode === 'batch') {
      // Show Google Authenticator export preview
      promptBatchImport(result.accounts);
    }
  } catch (err) {
    showToast(`QR error: ${err}`, 'error');
  }
}

function promptBatchImport(accounts) {
  appState.stagedMigrationAccounts = accounts;
  const list = document.getElementById('batch-preview-list');
  list.innerHTML = '';

  document.getElementById('batch-desc').innerHTML = `Found <strong>${accounts.length}</strong> accounts ready to import:`;

  accounts.forEach(acc => {
    const item = document.createElement('div');
    item.style.display = 'flex';
    item.style.alignItems = 'center';
    item.style.gap = '10px';
    item.style.fontSize = '0.9rem';
    item.innerHTML = `
      <div style="width: 24px; height: 24px; flex-shrink: 0;">${getServiceIcon(acc.issuer, acc.name)}</div>
      <div style="overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">
        <strong>${escapeHtml(acc.issuer)}</strong>: <span style="color: var(--md-sys-color-on-surface-variant);">${escapeHtml(acc.name)}</span>
      </div>
    `;
    list.appendChild(item);
  });

  openModal(modalBatch);
}

document.getElementById('confirm-batch-import-btn').addEventListener('click', async () => {
  try {
    const imported = await invoke('import_parsed_accounts', { accounts: appState.stagedMigrationAccounts });
    closeAllModals();
    showToast(`Successfully imported ${imported} accounts!`);
    fetchAndRenderAccounts();
  } catch (err) {
    showToast(`Import error: ${err}`, 'error');
  }
});



// Audio chime using Web Audio API (zero audio file dependencies)
function playChime() {
  try {
    const audioCtx = new (window.AudioContext || window.webkitAudioContext)();
    const osc = audioCtx.createOscillator();
    const gain = audioCtx.createGain();
    osc.connect(gain);
    gain.connect(audioCtx.destination);
    osc.frequency.setValueAtTime(587.33, audioCtx.currentTime); // D5
    osc.frequency.setValueAtTime(880, audioCtx.currentTime + 0.08); // A5
    gain.gain.setValueAtTime(0.2, audioCtx.currentTime);
    gain.gain.exponentialRampToValueAtTime(0.01, audioCtx.currentTime + 0.25);
    osc.start();
    osc.stop(audioCtx.currentTime + 0.25);
  } catch (_) {}
}

// --- Backup & Restore ---
backupBtn.addEventListener('click', () => openModal(modalBackup));

document.getElementById('export-json-btn').addEventListener('click', async () => {
  try {
    const jsonStr = await invoke('export_vault_backup');
    const blob = new Blob([jsonStr], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `google-authenticator-backup-${new Date().toISOString().slice(0, 10)}.json`;
    a.click();
    URL.revokeObjectURL(url);
    showToast('Backup downloaded successfully');
    closeAllModals();
  } catch (err) {
    showToast(`Export error: ${err}`, 'error');
  }
});

document.getElementById('import-json-btn').addEventListener('click', () => {
  backupFileInput.click();
});

backupFileInput.addEventListener('change', async (e) => {
  const file = e.target.files[0];
  if (!file) return;

  const reader = new FileReader();
  reader.onload = async () => {
    try {
      const count = await invoke('import_vault_backup', { jsonStr: reader.result });
      showToast(`Imported ${count} accounts from backup!`);
      closeAllModals();
      fetchAndRenderAccounts();
    } catch (err) {
      showToast(`Import error: ${err}`, 'error');
    }
  };
  reader.readAsText(file);
  backupFileInput.value = '';
});

// --- Toast Utility ---
function showToast(msg, type = 'info') {
  const container = document.getElementById('toast-container');
  const toast = document.createElement('div');
  toast.className = 'toast';
  if (type === 'error') {
    toast.style.backgroundColor = 'var(--md-sys-color-error-container)';
    toast.style.color = 'var(--md-sys-color-on-error-container)';
  }
  toast.textContent = msg;
  container.appendChild(toast);

  setTimeout(() => {
    toast.style.opacity = '0';
    toast.style.transition = 'opacity 0.3s';
    setTimeout(() => toast.remove(), 300);
  }, 3000);
}

function escapeHtml(str) {
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}
