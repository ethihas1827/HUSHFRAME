/**
 * @file app.js
 * @brief Frontend logic for Hushframe — Keep what matters out of sight.
 */

// Global Application State
const state = {
  hide: {
    coverFile: null,
    coverWidth: 0,
    coverHeight: 0,
    cap1Bit: 0,
    cap2Bit: 0,
    cap3Bit: 0,
    secretType: 'text',
    secretFile: null,
    confirmedUnprotected: false,
    downloadBlobUrl: null,
    downloadFilename: 'protected_image.png'
  },
  splitHide: {
    covers: [],
    secretType: 'file',
    secretFile: null,
    resultParts: [],
    manifestJson: ''
  },
  splitReveal: {
    parts: [],
    recoveredBlobUrl: null,
    recoveredFilename: 'recovered_secret.bin'
  },
  reveal: {
    stegoFile: null,
    recoveredPayloadBase64: null,
    downloadBlobUrl: null,
    downloadFilename: 'recovered_secret.bin'
  },
  verify: {
    imageFile: null
  },
  capacity: {
    imageFile: null
  },
  privacy: {
    imageFile: null,
    scanResult: null,
    cleanBlobUrl: null,
    cleanFilename: 'clean_image.png'
  }
};

// Tracked Blob URLs for clean revocation
const activeBlobUrls = [];

function trackBlobUrl(url) {
  if (url) activeBlobUrls.push(url);
  return url;
}

function revokeAllBlobUrls() {
  while (activeBlobUrls.length > 0) {
    const url = activeBlobUrls.pop();
    try {
      URL.revokeObjectURL(url);
    } catch (e) {}
  }
}

/**
 * Universal Dual-Mode API Dispatcher
 * Seamlessly routes requests to native C server (if running) or in-browser StegoEngine (offline).
 */
async function apiCall(endpoint, formData) {
  // If running via file:/// or StegoEngine standalone mode, route directly to in-browser engine
  if (typeof window !== 'undefined' && (window.location.protocol === 'file:' || (window.StegoEngine && window.StegoEngine.isStandalone()))) {
    if (window.StegoEngine) {
      return await window.StegoEngine.handleRequest(endpoint, formData);
    }
  }

  try {
    const res = await fetch(endpoint, {
      method: 'POST',
      body: formData
    });
    return await res.json();
  } catch (err) {
    // If native backend is unreachable, gracefully fallback to in-browser engine!
    if (window.StegoEngine) {
      window.StegoEngine.setMode('standalone');
      return await window.StegoEngine.handleRequest(endpoint, formData);
    }
    throw err;
  }
}

// DOM Ready initialization
document.addEventListener('DOMContentLoaded', () => {
  initTheme();
  initTabs();
  initDragAndDrop();
  initFormInputs();
  initSandbox();
  if (typeof HistoryManager !== 'undefined') {
    HistoryManager.render();
  }
});

/* ==========================================================================
   Navigation & Screen Transitions
   ========================================================================== */

function initTabs() {
  const tabs = document.querySelectorAll('.nav-tab');
  tabs.forEach(tab => {
    tab.addEventListener('click', () => {
      const targetId = tab.getAttribute('data-tab');
      switchTab(targetId);
    });
  });
}

function switchTab(targetId) {
  // If navigating away from a completed success screen, reset form state
  const hideResultCard = document.getElementById('hideResultCard');
  if (hideResultCard && !hideResultCard.classList.contains('hidden') && targetId !== 'hide') {
    resetHideForm(false);
  }

  const revealResultCard = document.getElementById('revealResultCard');
  if (revealResultCard && !revealResultCard.classList.contains('hidden') && targetId !== 'reveal') {
    resetRevealForm(false);
  }

  clearAlerts();

  if (targetId === 'activity' && typeof HistoryManager !== 'undefined') {
    HistoryManager.render();
  }

  const tabs = document.querySelectorAll('.nav-tab');
  tabs.forEach(tab => {
    const isTarget = (tab.getAttribute('data-tab') === targetId);
    tab.classList.toggle('active', isTarget);
    tab.setAttribute('aria-selected', isTarget ? 'true' : 'false');
  });

  document.querySelectorAll('.tab-pane').forEach(pane => {
    pane.classList.remove('active');
  });

  const activePane = document.getElementById(`pane-${targetId}`);
  if (activePane) activePane.classList.add('active');

  window.scrollTo({ top: 0, behavior: 'smooth' });
}

function goHome() {
  // Reset any completed success cards before returning Home
  const hideResultCard = document.getElementById('hideResultCard');
  if (hideResultCard && !hideResultCard.classList.contains('hidden')) {
    resetHideForm(false);
  }
  const revealResultCard = document.getElementById('revealResultCard');
  if (revealResultCard && !revealResultCard.classList.contains('hidden')) {
    resetRevealForm(false);
  }
  switchTab('home');
}

function openHideScreen() {
  resetHideForm(false);
  switchTab('hide');
}

function openRevealScreen() {
  resetRevealForm(false);
  switchTab('reveal');
}

/* ==========================================================================
   Alerts & Notifications
   ========================================================================== */

function showAlert(type, message) {
  const container = document.getElementById('alertContainer');
  if (!container) return;

  const alert = document.createElement('div');
  alert.className = `alert alert-${type}`;
  alert.innerHTML = `
    <span>${escapeHtml(message)}</span>
    <button type="button" class="alert-close" onclick="this.parentElement.remove()">✕</button>
  `;

  container.appendChild(alert);

  setTimeout(() => {
    if (alert.parentElement) {
      alert.style.opacity = '0';
      alert.style.transform = 'translateY(-10px)';
      alert.style.transition = 'all 0.3s ease';
      setTimeout(() => alert.remove(), 300);
    }
  }, 6000);
}

function clearAlerts() {
  const container = document.getElementById('alertContainer');
  if (container) container.innerHTML = '';
}

function escapeHtml(str) {
  if (!str) return '';
  return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

/* ==========================================================================
   Drag & Drop Setup
   ========================================================================== */

function initDragAndDrop() {
  setupDropzone('hideDropzone', 'hideImageInput', handleHideImageSelect);
  setupDropzone('revealDropzone', 'revealImageInput', handleRevealImageSelect);
  setupDropzone('verifyDropzone', 'verifyImageInput', handleVerifyImageSelect);
  setupDropzone('capDropzone', 'capImageInput', handleCapImageSelect);
  setupDropzone('privDropzone', 'privImageInput', handlePrivImageSelect);
}

function setupDropzone(dropzoneId, inputId, onFileSelect) {
  const dropzone = document.getElementById(dropzoneId);
  const input = document.getElementById(inputId);
  if (!dropzone || !input) return;

  ['dragenter', 'dragover'].forEach(eventName => {
    dropzone.addEventListener(eventName, (e) => {
      e.preventDefault();
      e.stopPropagation();
      dropzone.classList.add('dragover');
    }, false);
  });

  ['dragleave', 'drop'].forEach(eventName => {
    dropzone.addEventListener(eventName, (e) => {
      e.preventDefault();
      e.stopPropagation();
      dropzone.classList.remove('dragover');
    }, false);
  });

  dropzone.addEventListener('drop', (e) => {
    const dt = e.dataTransfer;
    const files = dt.files;
    if (files && files.length > 0) {
      onFileSelect(files[0]);
    }
  });

  input.addEventListener('change', () => {
    if (input.files && input.files.length > 0) {
      onFileSelect(input.files[0]);
    }
  });
}

/* ==========================================================================
   Form Input Listeners
   ========================================================================== */

function initFormInputs() {
  const textMsg = document.getElementById('secretTextMessage');
  if (textMsg) {
    textMsg.addEventListener('input', () => {
      const len = textMsg.value.length;
      const bytes = new TextEncoder().encode(textMsg.value).length;
      document.getElementById('secretCharCount').textContent = `${len} character${len === 1 ? '' : 's'}`;
      document.getElementById('secretSizeEstimate').textContent = `${bytes} byte${bytes === 1 ? '' : 's'}`;
      validateHideForm();
      evaluateHideCapacity();
    });
  }

  const secretFileInput = document.getElementById('secretFileInput');
  if (secretFileInput) {
    secretFileInput.addEventListener('change', () => {
      if (secretFileInput.files && secretFileInput.files.length > 0) {
        state.hide.secretFile = secretFileInput.files[0];
        document.getElementById('secretFileInfo').textContent = 
          `${state.hide.secretFile.name} (${formatBytes(state.hide.secretFile.size)})`;
      } else {
        state.hide.secretFile = null;
        document.getElementById('secretFileInfo').textContent = 'No file chosen';
      }
      validateHideForm();
      evaluateHideCapacity();
    });
  }

  const hidePass = document.getElementById('hidePassword');
  const hidePassConf = document.getElementById('hidePasswordConfirm');
  if (hidePass && hidePassConf) {
    [hidePass, hidePassConf].forEach(el => {
      el.addEventListener('input', () => {
        checkPasswordMatch();
        evaluateHideCapacity();
        updateEntropyUI(
          hidePass,
          document.getElementById('hideEntropyFill'),
          document.getElementById('hideEntropyRating'),
          document.getElementById('hideEntropyBits')
        );
      });
    });
  }

  const revPass = document.getElementById('revealPassword');
  if (revPass) {
    revPass.addEventListener('input', () => {
      const btn = document.getElementById('btnRevealSecret');
      if (btn && state.reveal.stegoFile) {
        btn.disabled = false;
      }
    });
  }
}

function togglePasswordVisibility(fieldId) {
  const field = document.getElementById(fieldId);
  if (field) {
    field.type = (field.type === 'password') ? 'text' : 'password';
  }
}

function checkPasswordMatch() {
  const p1 = document.getElementById('hidePassword').value;
  const p2 = document.getElementById('hidePasswordConfirm').value;
  const msg = document.getElementById('passwordMatchMsg');

  if (!msg) return;

  if (p1.length > 0 && p2.length > 0) {
    if (p1 === p2) {
      msg.textContent = '✓ Passwords match';
      msg.className = 'password-match-msg match';
    } else {
      msg.textContent = '✗ Passwords do not match';
      msg.className = 'password-match-msg mismatch';
    }
  } else {
    msg.textContent = '';
    msg.className = 'password-match-msg';
  }

  validateHideForm();
}

function toggleSecretType() {
  const type = document.querySelector('input[name="secretType"]:checked').value;
  state.hide.secretType = type;

  const textBox = document.getElementById('secretTextBox');
  const fileBox = document.getElementById('secretFileBox');

  if (type === 'file') {
    textBox.classList.add('hidden');
    fileBox.classList.remove('hidden');
  } else {
    fileBox.classList.add('hidden');
    textBox.classList.remove('hidden');
  }

  validateHideForm();
}

function formatBytes(bytes) {
  if (!bytes || bytes === 0) return '0 Bytes';
  const k = 1024;
  const sizes = ['Bytes', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

/* ==========================================================================
   Image Format & Magic Byte Verification
   ========================================================================== */

function detectImageMagicBytes(bytes) {
  if (!bytes || bytes.length < 2) return null;
  // PNG: 89 50 4E 47 0D 0A 1A 0A
  if (bytes.length >= 8 &&
      bytes[0] === 0x89 && bytes[1] === 0x50 && bytes[2] === 0x4E && bytes[3] === 0x47 &&
      bytes[4] === 0x0D && bytes[5] === 0x0A && bytes[6] === 0x1A && bytes[7] === 0x0A) {
    return { format: 'PNG', mime: 'image/png', ext: 'png' };
  }
  // JPEG: FF D8 FF
  if (bytes.length >= 3 &&
      bytes[0] === 0xFF && bytes[1] === 0xD8 && bytes[2] === 0xFF) {
    return { format: 'JPEG', mime: 'image/jpeg', ext: 'jpg' };
  }
  // BMP: 42 4D ("BM")
  if (bytes.length >= 2 && bytes[0] === 0x42 && bytes[1] === 0x4D) {
    return { format: 'BMP', mime: 'image/bmp', ext: 'bmp' };
  }
  // WebP: RIFF .... WEBP
  if (bytes.length >= 12 &&
      bytes[0] === 0x52 && bytes[1] === 0x49 && bytes[2] === 0x46 && bytes[3] === 0x46 &&
      bytes[8] === 0x57 && bytes[9] === 0x45 && bytes[10] === 0x42 && bytes[11] === 0x50) {
    return { format: 'WEBP', mime: 'image/webp', ext: 'webp' };
  }
  // GIF: GIF87a or GIF89a
  if (bytes.length >= 6 &&
      bytes[0] === 0x47 && bytes[1] === 0x49 && bytes[2] === 0x46 && bytes[3] === 0x38 &&
      (bytes[4] === 0x37 || bytes[4] === 0x39) && bytes[5] === 0x61) {
    return { format: 'GIF', mime: 'image/gif', ext: 'gif' };
  }
  return null;
}

/* ==========================================================================
   Tab 1: Protect File Flow & State Reset
   ========================================================================== */

async function handleHideImageSelect(file) {
  if (!file) return;

  if (file.size === 0) {
    showAlert('danger', 'The selected file is empty (0 bytes). Please select a valid image.');
    resetHideImage();
    return;
  }

  // Detect image type from magic bytes
  let detected = null;
  try {
    const slice = file.slice(0, 16);
    const buffer = await slice.arrayBuffer();
    const bytes = new Uint8Array(buffer);
    detected = detectImageMagicBytes(bytes);
  } catch (err) {
    showAlert('danger', 'Failed to inspect file header: ' + err.message);
    resetHideImage();
    return;
  }

  if (!detected) {
    showAlert('danger', 'The selected file is not a supported image format. Select a valid PNG, JPEG, BMP, or WEBP image.');
    resetHideImage();
    return;
  }

  state.hide.coverFile = file;

  // Display initial file info immediately
  const nameEl = document.getElementById('hideMetaName');
  if (nameEl) nameEl.textContent = file.name;

  const sizeEl = document.getElementById('hideMetaSize');
  if (sizeEl) sizeEl.textContent = formatBytes(file.size);

  const fmtEl = document.getElementById('hideMetaFormat');
  if (fmtEl) fmtEl.textContent = detected.mime;

  const dimEl = document.getElementById('hideMetaDim');
  if (dimEl) dimEl.textContent = 'Calculating...';

  const capEl = document.getElementById('hideMetaCap');
  if (capEl) capEl.textContent = 'Calculating capacity...';

  const noticeEl = document.getElementById('hideMetaNotice');
  if (noticeEl) {
    noticeEl.textContent = '';
    noticeEl.classList.add('hidden');
  }

  // Load preview thumbnail
  const thumb = document.getElementById('hideThumb');
  if (thumb) {
    const reader = new FileReader();
    reader.onload = (e) => {
      thumb.src = e.target.result;
    };
    reader.readAsDataURL(file);
  }

  document.getElementById('hideDropzone')?.classList.add('hidden');
  document.getElementById('hideImageMeta')?.classList.remove('hidden');

  // Query server for carrier capacity and format details
  queryImageCapacity(
    file,
    (info) => {
      state.hide.coverWidth = info.width || 0;
      state.hide.coverHeight = info.height || 0;
      state.hide.cap1Bit = info.encrypted_capacity || 0;
      state.hide.cap2Bit = info.capacity_2bit || (state.hide.cap1Bit * 2);
      state.hide.cap3Bit = info.capacity_3bit || (state.hide.cap1Bit * 3);

      if (dimEl) dimEl.textContent = `${info.width} \u00d7 ${info.height} px`;
      if (fmtEl) fmtEl.textContent = info.mime_type || detected.mime;
      if (sizeEl && info.file_size) sizeEl.textContent = formatBytes(info.file_size);
      if (capEl) capEl.textContent = `Capacity: ${formatBytes(info.encrypted_capacity || 0)}`;

      if (noticeEl) {
        if (info.notice && info.notice.length > 0) {
          noticeEl.textContent = info.notice;
          noticeEl.classList.remove('hidden');
        } else {
          noticeEl.classList.add('hidden');
        }
      }

      validateHideForm();
      evaluateHideCapacity();
    },
    (errMsg) => {
      showAlert('danger', errMsg || 'Failed to inspect carrier image.');
      resetHideImage();
    }
  );

  validateHideForm();
  evaluateHideCapacity();
}

function resetHideImage() {
  state.hide.coverFile = null;
  const sizeEl = document.getElementById('hideMetaSize');
  if (sizeEl) sizeEl.textContent = '0 KB';
  const dimEl = document.getElementById('hideMetaDim');
  if (dimEl) dimEl.textContent = '0 \u00d7 0 px';
  const fmtEl = document.getElementById('hideMetaFormat');
  if (fmtEl) fmtEl.textContent = 'image/png';
  const capEl = document.getElementById('hideMetaCap');
  if (capEl) capEl.textContent = 'Capacity: 0 KB';
  const noticeEl = document.getElementById('hideMetaNotice');
  if (noticeEl) {
    noticeEl.textContent = '';
    noticeEl.classList.add('hidden');
  }
  state.hide.coverWidth = 0;
  state.hide.coverHeight = 0;
  state.hide.cap1Bit = 0;
  state.hide.cap2Bit = 0;
  state.hide.cap3Bit = 0;
  const input = document.getElementById('hideImageInput');
  if (input) input.value = '';
  const thumb = document.getElementById('hideThumb');
  if (thumb) thumb.src = '';
  document.getElementById('hideDropzone')?.classList.remove('hidden');
  document.getElementById('hideImageMeta')?.classList.add('hidden');
  document.getElementById('hideCapacityMeterBox')?.classList.add('hidden');
  document.getElementById('capacityShortfallCard')?.classList.add('hidden');
  validateHideForm();
}

function validateHideForm() {
  const btn = document.getElementById('btnHideSecret');
  if (!btn) return;

  if (!state.hide.coverFile) {
    btn.disabled = true;
    return;
  }

  let hasSecret = false;
  if (state.hide.secretType === 'text') {
    const text = document.getElementById('secretTextMessage').value.trim();
    hasSecret = (text.length > 0);
  } else {
    hasSecret = (state.hide.secretFile !== null);
  }

  if (!hasSecret) {
    btn.disabled = true;
    return;
  }

  const p1 = document.getElementById('hidePassword').value;
  const p2 = document.getElementById('hidePasswordConfirm').value;
  if (p1.length > 0 && p1 !== p2) {
    btn.disabled = true;
    return;
  }

  btn.disabled = false;
}

function submitHideSecret() {
  executeHideRequest();
}

function closeUnprotectedModal(focusPassword) {
  const modal = document.getElementById('unprotectedModal');
  if (modal) modal.classList.add('hidden');
  if (focusPassword) {
    const pInput = document.getElementById('hidePassword');
    if (pInput) pInput.focus();
  }
}

function confirmUnprotectedProceed() {
  state.hide.confirmedUnprotected = true;
  const modal = document.getElementById('unprotectedModal');
  if (modal) modal.classList.add('hidden');
  executeHideRequest();
}

async function executeHideRequest() {
  const btn = document.getElementById('btnHideSecret');
  const progress = document.getElementById('hideProgress');
  const resultCard = document.getElementById('hideResultCard');

  btn.disabled = true;
  progress.classList.remove('hidden');
  resultCard.classList.add('hidden');

  const formData = new FormData();
  formData.append('cover', state.hide.coverFile);
  formData.append('cover_image', state.hide.coverFile);

  if (state.hide.secretType === 'text') {
    const textVal = document.getElementById('secretTextMessage').value;
    formData.append('secret_type', 'text');
    formData.append('message', textVal);
    formData.append('secret_text', textVal);
  } else {
    formData.append('secret_type', 'file');
    formData.append('secret_file', state.hide.secretFile);
  }

  const pass = document.getElementById('hidePassword').value;
  if (pass.length > 0) {
    formData.append('password', pass);
  } else {
    formData.append('confirm_unprotected', 'true');
  }

  if (document.getElementById('hideAdaptive')?.checked) {
    formData.append('adaptive', 'true');
  }

  if (document.getElementById('hideCompress')?.checked) {
    formData.append('compress', 'true');
  }

  const bitsSelect = document.getElementById('hideBits');
  if (bitsSelect) {
    formData.append('bits', bitsSelect.value);
  }

  try {
    const json = await apiCall('/api/hide', formData);
    progress.classList.add('hidden');

    if (!json.success) {
      btn.disabled = false;
      if (json.capacity_exceeded) {
        showCapacityShortfallCard(json);
        showAlert('danger', json.error || Terminology.ERR_FILE_TOO_LARGE);
        return;
      }

      // Keep image for retry, clear password fields, show calm error
      document.getElementById('hidePassword').value = '';
      document.getElementById('hidePasswordConfirm').value = '';
      const pMatch = document.getElementById('passwordMatchMsg');
      if (pMatch) {
        pMatch.textContent = '';
        pMatch.className = 'password-match-msg';
      }
      state.hide.confirmedUnprotected = false;
      validateHideForm();
      showAlert('danger', json.error || Terminology.ERR_OUTPUT_ERROR);
      return;
    }

    // Success Screen Configuration
    document.getElementById('hideResultProtection').textContent = json.protection_label || (pass ? Terminology.LABEL_PASSWORD_PROTECTED : Terminology.LABEL_STANDARD_PROTECTION);
    document.getElementById('hideResultSize').textContent = formatBytes(json.file_size || 0);

    const noticeEl = document.getElementById('hideResultNotice');
    if (json.notice && json.notice.length > 0) {
      noticeEl.textContent = json.notice;
      noticeEl.classList.remove('hidden');
    } else {
      noticeEl.classList.add('hidden');
    }

    // Convert Base64 PNG to Blob and track it
    const blob = base64ToBlob(json.image_base64, 'image/png');
    const blobUrl = trackBlobUrl(URL.createObjectURL(blob));

    document.getElementById('hideResultPreview').src = blobUrl;
    state.hide.downloadBlobUrl = blobUrl;
    state.hide.downloadFilename = json.filename || 'protected_image.png';
    state.hide.isProtected = !!json.is_protected;
    state.hide.coverName = state.hide.coverFile ? state.hide.coverFile.name : 'cover.png';

    resultCard.classList.remove('hidden');
    showAlert('success', Terminology.MSG_PROTECTED_READY);

  } catch (err) {
    progress.classList.add('hidden');
    btn.disabled = false;
    showAlert('danger', Terminology.ERR_SERVER_CONNECTION);
  }
}

/**
 * Download protected image and trigger automatic post-download state cleanup
 */
function downloadProtectedImage() {
  if (!state.hide.downloadBlobUrl) return;

  const url = state.hide.downloadBlobUrl;
  const filename = state.hide.downloadFilename || 'protected_image.png';

  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);

  if (typeof HistoryManager !== 'undefined') {
    HistoryManager.record(Terminology.BTN_PROTECT_FILE, state.hide.coverName || 'cover.png', filename, state.hide.isProtected);
  }

  showAlert('success', 'Download started. Session state cleared.');

  // Automatic reset & return to Home screen
  setTimeout(() => {
    resetHideForm(false);
    goHome();
  }, 400);
}

/**
 * Universal reset function for the Protect file flow
 */
function resetHideForm(preserveCover = false) {
  revokeAllBlobUrls();

  if (!preserveCover) {
    state.hide.coverFile = null;
    const hideInput = document.getElementById('hideImageInput');
    if (hideInput) hideInput.value = '';
    const hideThumb = document.getElementById('hideThumb');
    if (hideThumb) hideThumb.src = '';
    const hideMetaName = document.getElementById('hideMetaName');
    if (hideMetaName) hideMetaName.textContent = '';
    const sizeEl = document.getElementById('hideMetaSize');
    if (sizeEl) sizeEl.textContent = '0 KB';
    const dimEl = document.getElementById('hideMetaDim');
    if (dimEl) dimEl.textContent = '0 \u00d7 0 px';
    const fmtEl = document.getElementById('hideMetaFormat');
    if (fmtEl) fmtEl.textContent = 'image/png';
    const capEl = document.getElementById('hideMetaCap');
    if (capEl) capEl.textContent = 'Capacity: 0 KB';
    state.hide.coverWidth = 0;
    state.hide.coverHeight = 0;
    state.hide.cap1Bit = 0;
    state.hide.cap2Bit = 0;
    state.hide.cap3Bit = 0;
    const hideDropzone = document.getElementById('hideDropzone');
    if (hideDropzone) hideDropzone.classList.remove('hidden');
    const hideImageMeta = document.getElementById('hideImageMeta');
    if (hideImageMeta) hideImageMeta.classList.add('hidden');
    const hideNotice = document.getElementById('hideMetaNotice');
    if (hideNotice) {
      hideNotice.textContent = '';
      hideNotice.classList.add('hidden');
    }
  }

  // Clear text message
  const textMsg = document.getElementById('secretTextMessage');
  if (textMsg) textMsg.value = '';
  const charCount = document.getElementById('secretCharCount');
  if (charCount) charCount.textContent = '0 characters';
  const sizeEst = document.getElementById('secretSizeEstimate');
  if (sizeEst) sizeEst.textContent = '0 bytes';

  // Clear secret file input
  const fileInput = document.getElementById('secretFileInput');
  if (fileInput) fileInput.value = '';
  const fileInfo = document.getElementById('secretFileInfo');
  if (fileInfo) fileInfo.textContent = 'No file chosen';
  state.hide.secretFile = null;

  // Clear password inputs and feedback
  const p1 = document.getElementById('hidePassword');
  if (p1) p1.value = '';
  const p2 = document.getElementById('hidePasswordConfirm');
  if (p2) p2.value = '';
  const pMatch = document.getElementById('passwordMatchMsg');
  if (pMatch) {
    pMatch.textContent = '';
    pMatch.className = 'password-match-msg';
  }

  // Clear adaptive checkbox and flags
  const adapt = document.getElementById('hideAdaptive');
  if (adapt) adapt.checked = false;
  state.hide.confirmedUnprotected = false;
  state.hide.downloadBlobUrl = null;
  state.hide.downloadFilename = 'protected_image.png';

  // Close modals
  const modal = document.getElementById('unprotectedModal');
  if (modal) modal.classList.add('hidden');

  // Reset progress and results
  const progress = document.getElementById('hideProgress');
  if (progress) progress.classList.add('hidden');
  const resultCard = document.getElementById('hideResultCard');
  if (resultCard) resultCard.classList.add('hidden');
  const preview = document.getElementById('hideResultPreview');
  if (preview) preview.src = '';

  validateHideForm();
}

/* ==========================================================================
   Tab 2: Recover File Flow & State Reset
   ========================================================================== */

function handleRevealImageSelect(file) {
  state.reveal.stegoFile = file;

  const reader = new FileReader();
  reader.onload = (e) => {
    document.getElementById('revealThumb').src = e.target.result;
    document.getElementById('revealMetaName').textContent = file.name;
    document.getElementById('revealMetaSize').textContent = formatBytes(file.size);
    document.getElementById('revealDropzone').classList.add('hidden');
    document.getElementById('revealImageMeta').classList.remove('hidden');
    document.getElementById('btnRevealSecret').disabled = false;
  };
  reader.readAsDataURL(file);
}

function resetRevealImage() {
  state.reveal.stegoFile = null;
  const input = document.getElementById('revealImageInput');
  if (input) input.value = '';
  document.getElementById('revealDropzone').classList.remove('hidden');
  document.getElementById('revealImageMeta').classList.add('hidden');
  document.getElementById('btnRevealSecret').disabled = true;
  document.getElementById('revealResultCard').classList.add('hidden');
}

async function submitRevealSecret() {
  if (!state.reveal.stegoFile) return;

  const btn = document.getElementById('btnRevealSecret');
  const progress = document.getElementById('revealProgress');
  const resultCard = document.getElementById('revealResultCard');

  btn.disabled = true;
  progress.classList.remove('hidden');
  resultCard.classList.add('hidden');

  const formData = new FormData();
  formData.append('stego_image', state.reveal.stegoFile);
  formData.append('image', state.reveal.stegoFile);

  const pass = document.getElementById('revealPassword').value;
  if (pass.length > 0) {
    formData.append('password', pass);
  }

  try {
    const json = await apiCall('/api/reveal', formData);
    progress.classList.add('hidden');

    if (!json.success) {
      btn.disabled = false;
      const revPassInput = document.getElementById('revealPassword');
      if (revPassInput) revPassInput.value = '';
      let errMsg = json.error || Terminology.ERR_WRONG_PASSWORD;
      if (json.error && (/password|auth|tamper|corrupt/i).test(json.error)) {
        errMsg = Terminology.ERR_WRONG_PASSWORD;
      }
      showAlert('danger', errMsg);
      return;
    }

    // Success Display
    document.getElementById('revealResultSub').textContent = 
      `${json.protection_label || Terminology.TECH_INTEGRITY} • ${json.payload_length} bytes recovered`;

    const textBox = document.getElementById('revealTextBox');
    const fileBox = document.getElementById('revealFileBox');
    const btnDown = document.getElementById('btnDownloadRecoveredFile') || document.getElementById('btnDownloadRecovered');

    if (json.is_file) {
      if (textBox) textBox.classList.add('hidden');
      if (fileBox) fileBox.classList.remove('hidden');
      if (btnDown) btnDown.classList.remove('hidden');

      const nameEl = document.getElementById('revealFileName');
      if (nameEl) nameEl.textContent = json.filename || 'recovered_file.bin';
      const sizeEl = document.getElementById('revealFileSize');
      if (sizeEl) sizeEl.textContent = formatBytes(json.payload_length || 0);

      const blob = base64ToBlob(json.file_base64, 'application/octet-stream');
      const blobUrl = trackBlobUrl(URL.createObjectURL(blob));

      state.reveal.downloadBlobUrl = blobUrl;
      state.reveal.downloadFilename = json.filename || 'recovered_file.bin';
      state.reveal.isProtected = !!json.is_protected;
      state.reveal.stegoName = state.reveal.stegoFile ? state.reveal.stegoFile.name : 'protected_image.png';

    } else {
      if (fileBox) fileBox.classList.add('hidden');
      if (btnDown) btnDown.classList.add('hidden');
      if (textBox) textBox.classList.remove('hidden');

      const tagEl = document.getElementById('revealPayloadTag');
      if (tagEl) tagEl.textContent = `${json.payload_length} bytes recovered`;
      const textEl = document.getElementById('revealResultText');
      if (textEl) textEl.value = json.text || '';

      if (typeof HistoryManager !== 'undefined') {
        HistoryManager.record(
          Terminology.BTN_RECOVER_FILE,
          state.reveal.stegoFile ? state.reveal.stegoFile.name : 'protected_image.png',
          Terminology.CONTENT_TEXT,
          json.is_protected
        );
      }
    }

    if (resultCard) resultCard.classList.remove('hidden');
    showAlert('success', Terminology.MSG_RECOVERED_SUCCESS);

  } catch (err) {
    console.error('Recover file error:', err);
    progress.classList.add('hidden');
    btn.disabled = false;
    showAlert('danger', Terminology.ERR_SERVER_CONNECTION);
  }
}

/**
 * Download recovered file and trigger automatic post-download state cleanup
 */
function downloadRecoveredFile() {
  if (!state.reveal.downloadBlobUrl) return;

  const url = state.reveal.downloadBlobUrl;
  const filename = state.reveal.downloadFilename || 'recovered_file.bin';

  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);

  if (typeof HistoryManager !== 'undefined') {
    HistoryManager.record(
      Terminology.BTN_RECOVER_FILE,
      state.reveal.stegoName || 'protected_image.png',
      filename,
      state.reveal.isProtected
    );
  }

  showAlert('success', 'Download started. Session state cleared.');

  // Automatic reset & return to Home screen
  setTimeout(() => {
    resetRevealForm(false);
    goHome();
  }, 400);
}

function copyRecoveredText() {
  const textEl = document.getElementById('revealResultText');
  if (textEl && textEl.value) {
    navigator.clipboard.writeText(textEl.value).then(() => {
      showAlert('success', 'Text copied to clipboard.');
    }).catch(() => {
      textEl.select();
      document.execCommand('copy');
      showAlert('success', 'Text copied to clipboard.');
    });
  }
}

/**
 * Universal reset function for the Recover file flow
 */
function resetRevealForm(preserveStego = false) {
  revokeAllBlobUrls();

  if (!preserveStego) {
    state.reveal.stegoFile = null;
    const input = document.getElementById('revealImageInput');
    if (input) input.value = '';
    const thumb = document.getElementById('revealThumb');
    if (thumb) thumb.src = '';
    const name = document.getElementById('revealMetaName');
    if (name) name.textContent = '';
    const dropzone = document.getElementById('revealDropzone');
    if (dropzone) dropzone.classList.remove('hidden');
    const meta = document.getElementById('revealImageMeta');
    if (meta) meta.classList.add('hidden');
  }

  // Clear password input
  const revPass = document.getElementById('revealPassword');
  if (revPass) revPass.value = '';

  // Clear progress bar
  const progress = document.getElementById('revealProgress');
  if (progress) progress.classList.add('hidden');

  // Clear results & payload data
  const resultCard = document.getElementById('revealResultCard');
  if (resultCard) resultCard.classList.add('hidden');
  const textResult = document.getElementById('revealResultText');
  if (textResult) textResult.value = '';
  const textBox = document.getElementById('revealTextBox');
  if (textBox) textBox.classList.add('hidden');
  const fileBox = document.getElementById('revealFileBox');
  if (fileBox) fileBox.classList.add('hidden');
  const btnDown = document.getElementById('btnDownloadRecoveredFile') || document.getElementById('btnDownloadRecovered');
  if (btnDown) btnDown.classList.add('hidden');

  state.reveal.downloadBlobUrl = null;
  state.reveal.downloadFilename = 'recovered_file.bin';
  state.reveal.recoveredPayloadBase64 = null;

  // Re-enable reveal button
  const btnReveal = document.getElementById('btnRevealSecret');
  if (btnReveal) {
    btnReveal.textContent = Terminology.BTN_RECOVER_FILE;
    btnReveal.disabled = (!preserveStego || !state.reveal.stegoFile);
  }
}

/* ==========================================================================
   Tab 3: Verify Flow
   ========================================================================== */

function handleVerifyImageSelect(file) {
  state.verify.imageFile = file;

  const reader = new FileReader();
  reader.onload = (e) => {
    document.getElementById('verifyThumb').src = e.target.result;
    document.getElementById('verifyMetaName').textContent = file.name;
    document.getElementById('verifyDropzone').classList.add('hidden');
    document.getElementById('verifyImageMeta').classList.remove('hidden');
    document.getElementById('btnVerifyImage').disabled = false;
  };
  reader.readAsDataURL(file);
}

function resetVerifyImage() {
  state.verify.imageFile = null;
  const input = document.getElementById('verifyImageInput');
  if (input) input.value = '';
  document.getElementById('verifyDropzone').classList.remove('hidden');
  document.getElementById('verifyImageMeta').classList.add('hidden');
  document.getElementById('btnVerifyImage').disabled = true;
  document.getElementById('verifyResultCard').classList.add('hidden');
}

async function submitVerifyImage() {
  if (!state.verify.imageFile) return;

  const btn = document.getElementById('btnVerifyImage');
  btn.disabled = true;

  const formData = new FormData();
  formData.append('image', state.verify.imageFile);

  try {
    const json = await apiCall('/api/verify', formData);
    btn.disabled = false;

    if (!json.success) {
      showAlert('danger', json.error || Terminology.ERR_INVALID_IMAGE);
      return;
    }

    const card = document.getElementById('verifyResultCard');
    const title = document.getElementById('verifyResultTitle');

    if (json.has_payload) {
      if (title) title.textContent = 'Protected content detected';
      document.getElementById('verifyHasPayload').textContent = 'Yes';
      document.getElementById('verifyProtection').textContent = json.protection_label || Terminology.LABEL_PASSWORD_PROTECTED;
      document.getElementById('verifyPayloadSize').textContent = `${json.payload_length} bytes`;
      document.getElementById('verifyResultMsg').textContent = 
        json.is_protected ? 'This image contains a password-protected file.' : 'This image contains an unencrypted file.';
    } else {
      if (title) title.textContent = 'No protected content detected';
      document.getElementById('verifyHasPayload').textContent = 'No';
      document.getElementById('verifyProtection').textContent = 'None';
      document.getElementById('verifyPayloadSize').textContent = '0 bytes';
      document.getElementById('verifyResultMsg').textContent = 'No protected content was detected in this image.';
    }

    card.classList.remove('hidden');

  } catch (err) {
    btn.disabled = false;
    showAlert('danger', Terminology.ERR_SERVER_CONNECTION);
  }
}

/* ==========================================================================
   Tab 4: Capacity Flow
   ========================================================================== */

function handleCapImageSelect(file) {
  state.capacity.imageFile = file;

  const reader = new FileReader();
  reader.onload = (e) => {
    document.getElementById('capThumb').src = e.target.result;
    document.getElementById('capMetaName').textContent = file.name;
    const sizeEl = document.getElementById('capMetaSize');
    if (sizeEl) sizeEl.textContent = formatBytes(file.size);
    document.getElementById('capDropzone').classList.add('hidden');
    document.getElementById('capImageMeta').classList.remove('hidden');
    document.getElementById('btnCheckCapacity').disabled = false;
  };
  reader.readAsDataURL(file);
}

function resetCapImage() {
  state.capacity.imageFile = null;
  const input = document.getElementById('capImageInput');
  if (input) input.value = '';
  document.getElementById('capDropzone').classList.remove('hidden');
  document.getElementById('capImageMeta').classList.add('hidden');
  document.getElementById('btnCheckCapacity').disabled = true;
  document.getElementById('capResultCard').classList.add('hidden');
}

async function submitCheckCapacity() {
  if (!state.capacity.imageFile) return;

  const btn = document.getElementById('btnCheckCapacity');
  btn.disabled = true;

  const formData = new FormData();
  formData.append('image', state.capacity.imageFile);

  try {
    const json = await apiCall('/api/capacity', formData);
    btn.disabled = false;

    if (!json.success) {
      showAlert('danger', json.error || 'Failed to inspect image.');
      return;
    }

    document.getElementById('capValEnc').textContent = formatBytes(json.encrypted_capacity || 0);
    document.getElementById('capValUnenc').textContent = formatBytes(json.unencrypted_capacity || 0);
    document.getElementById('capValDim').textContent = `${json.width} x ${json.height} px`;
    document.getElementById('capValFormat').textContent = json.normalized_mode || json.format || 'PNG';

    const noticeEl = document.getElementById('capResultNotice');
    if (json.notice && json.notice.length > 0) {
      noticeEl.textContent = json.notice;
      noticeEl.classList.remove('hidden');
    } else {
      noticeEl.classList.add('hidden');
    }

    document.getElementById('capResultCard').classList.remove('hidden');

  } catch (err) {
    btn.disabled = false;
    showAlert('danger', 'Capacity calculation failed.');
  }
}

async function queryImageCapacity(file, onSuccess, onError) {
  const formData = new FormData();
  formData.append('image', file, file.name || 'carrier.png');
  formData.append('cover', file, file.name || 'carrier.png');

  try {
    const json = await apiCall('/api/capacity', formData);
    if (json.success) {
      if (onSuccess) onSuccess(json);
    } else {
      if (onError) onError(json.error || 'Failed to calculate image capacity.');
    }
  } catch (e) {
    if (onError) onError('Could not calculate image capacity.');
  }
}

/* ==========================================================================
   Base64 to Blob Helper
   ========================================================================== */

function base64ToBlob(base64, mimeType) {
  const byteChars = atob(base64);
  const byteArrays = [];
  const sliceSize = 512;

  for (let offset = 0; offset < byteChars.length; offset += sliceSize) {
    const slice = byteChars.slice(offset, offset + sliceSize);
    const byteNumbers = new Array(slice.length);
    for (let i = 0; i < slice.length; i++) {
      byteNumbers[i] = slice.charCodeAt(i);
    }
    const byteArray = new Uint8Array(byteNumbers);
    byteArrays.push(byteArray);
  }

  return new Blob(byteArrays, { type: mimeType });
}

/* ==========================================================================
   Live Capacity Assessment & Shortfall Advice Handling
   ========================================================================== */

function evaluateHideCapacity() {
  if (!state.hide.coverFile) {
    document.getElementById('hideCapacityMeterBox')?.classList.add('hidden');
    document.getElementById('capacityShortfallCard')?.classList.add('hidden');
    return;
  }

  const bits = parseInt(document.getElementById('hideBits')?.value || '1', 10);
  let availableCap = state.hide.cap1Bit || 0;
  if (bits === 2) availableCap = state.hide.cap2Bit || (availableCap * 2);
  else if (bits === 3) availableCap = state.hide.cap3Bit || (availableCap * 3);

  let secretSize = 0;
  let secretName = 'secret.bin';
  if (state.hide.secretType === 'text') {
    const text = document.getElementById('secretTextMessage')?.value || '';
    secretSize = new TextEncoder().encode(text).length;
    secretName = 'message.txt';
  } else if (state.hide.secretFile) {
    secretSize = state.hide.secretFile.size;
    secretName = state.hide.secretFile.name;
  }

  if (secretSize === 0) {
    document.getElementById('hideCapacityMeterBox')?.classList.add('hidden');
    document.getElementById('capacityShortfallCard')?.classList.add('hidden');
    return;
  }

  const isEncrypted = (document.getElementById('hidePassword')?.value?.length > 0);
  const overhead = isEncrypted ? 52 : 8;
  const totalRequired = secretSize + overhead;

  const meterBox = document.getElementById('hideCapacityMeterBox');
  const meterFill = document.getElementById('hideCapacityFill');
  const meterStatus = document.getElementById('hideCapacityStatus');
  const sfCard = document.getElementById('capacityShortfallCard');

  if (meterBox) meterBox.classList.remove('hidden');

  if (totalRequired <= availableCap) {
    const pct = availableCap > 0 ? Math.min(100, Math.round((totalRequired / availableCap) * 100)) : 0;
    if (meterFill) {
      meterFill.style.width = `${pct}%`;
      meterFill.className = 'capacity-meter-fill' + (pct > 80 ? ' warning' : '');
    }
    if (meterStatus) {
      meterStatus.textContent = `${formatBytes(totalRequired)} of ${formatBytes(availableCap)} (${pct}%)`;
    }
    if (sfCard) sfCard.classList.add('hidden');
  } else {
    const shortfall = totalRequired - availableCap;
    if (meterFill) {
      meterFill.style.width = '100%';
      meterFill.className = 'capacity-meter-fill danger';
    }
    if (meterStatus) {
      meterStatus.textContent = `Exceeded: ${formatBytes(totalRequired)} / ${formatBytes(availableCap)} (+${formatBytes(shortfall)} needed)`;
    }

    const neededPixels = Math.ceil(totalRequired / (0.375 * bits));
    const recW = Math.ceil(Math.sqrt((neededPixels * 4.0) / 3.0));
    const recH = Math.ceil((recW * 3.0) / 4.0);
    const recSq = Math.ceil(Math.sqrt(neededPixels));

    showCapacityShortfallCard({
      secret_name: secretName,
      secret_size: secretSize,
      available_capacity: availableCap,
      additional_required: shortfall,
      rec_min_width: recW,
      rec_min_height: recH,
      rec_square_dim: recSq
    });
  }
}

function showCapacityShortfallCard(data) {
  const card = document.getElementById('capacityShortfallCard');
  if (!card) return;

  document.getElementById('sfSecretName').textContent = data.secret_name || 'secret.bin';
  document.getElementById('sfSecretSize').textContent = formatBytes(data.secret_size || 0);
  document.getElementById('sfAvailableCap').textContent = formatBytes(data.available_capacity || 0);
  document.getElementById('sfAdditionalReq').textContent = `${formatBytes(data.additional_required || 0)} more needed`;
  document.getElementById('sfRecDimensions').textContent = 
    `${data.rec_min_width || 0} × ${data.rec_min_height || 0} px (or ${data.rec_square_dim || 0} × ${data.rec_square_dim || 0} px square)`;

  card.classList.remove('hidden');
}

function dismissCapacityCard() {
  const card = document.getElementById('capacityShortfallCard');
  if (card) card.classList.add('hidden');
}

function applyCompressionChoice() {
  const compCheckbox = document.getElementById('hideCompress');
  if (compCheckbox) compCheckbox.checked = true;
  showAlert('info', 'Compression enabled (RFC 1951 DEFLATE). Files that are already compressed (ZIP, JPEG, MP3, MP4, WEBP) will not shrink significantly.');
  onCompressToggle();
  evaluateHideCapacity();
}

function applyHighCapChoice() {
  const bitsSelect = document.getElementById('hideBits');
  if (bitsSelect) {
    bitsSelect.value = (bitsSelect.value === '1') ? '2' : '3';
    onBitsChange();
  }
  showAlert('info', `Switched to ${bitsSelect?.value || '2'}-bit LSB mode. Available capacity increased.`);
  evaluateHideCapacity();
}

function onCompressToggle() {
  const badge = document.getElementById('compressionStatusBadge');
  const comp = document.getElementById('hideCompress')?.checked;
  if (!badge) return;

  if (comp) {
    badge.classList.remove('hidden');
    let size = 0;
    if (state.hide.secretType === 'text') {
      size = new TextEncoder().encode(document.getElementById('secretTextMessage')?.value || '').length;
    } else if (state.hide.secretFile) {
      size = state.hide.secretFile.size;
    }
    const est = Math.max(16, Math.round(size * 0.45));
    badge.textContent = `Estimated compressed payload: ~${formatBytes(est)}`;
  } else {
    badge.classList.add('hidden');
  }
  evaluateHideCapacity();
}

function onBitsChange() {
  const bits = parseInt(document.getElementById('hideBits')?.value || '1', 10);
  const hint = document.getElementById('hideBitsHint');
  if (hint) {
    if (bits === 1) {
      hint.textContent = '1-bit replaces the least significant bit per color channel.';
    } else if (bits === 2) {
      hint.textContent = '2-bit mode: Doubles storage capacity. Introduces minor noise.';
    } else {
      hint.textContent = '3-bit mode: Triples storage capacity. May be visible in uniform color regions.';
    }
  }
  evaluateHideCapacity();
}

/* ==========================================================================
   Workflow Mode Switching (Single vs Multi-Image Split)
   ========================================================================== */

function setHideMode(mode) {
  const isSingle = (mode === 'single');
  document.getElementById('btnModeHideSingle')?.classList.toggle('active', isSingle);
  document.getElementById('btnModeHideSplit')?.classList.toggle('active', !isSingle);
  document.getElementById('hideSingleSection')?.classList.toggle('hidden', !isSingle);
  document.getElementById('hideSplitSection')?.classList.toggle('hidden', isSingle);
}

function setRevealMode(mode) {
  const isSingle = (mode === 'single');
  document.getElementById('btnModeRevSingle')?.classList.toggle('active', isSingle);
  document.getElementById('btnModeRevSplit')?.classList.toggle('active', !isSingle);
  document.getElementById('revealSingleSection')?.classList.toggle('hidden', !isSingle);
  document.getElementById('revealSplitSection')?.classList.toggle('hidden', isSingle);
}

function switchToSplitMode() {
  setHideMode('split');
  if (state.hide.secretType === 'file' && state.hide.secretFile) {
    const rad = document.querySelector('input[name="splitSecretType"][value="file"]');
    if (rad) rad.checked = true;
    toggleSplitSecretType();
    handleSplitSecretFile(state.hide.secretFile);
  } else {
    const rad = document.querySelector('input[name="splitSecretType"][value="text"]');
    if (rad) rad.checked = true;
    toggleSplitSecretType();
    const text = document.getElementById('secretTextMessage')?.value || '';
    const splitTextEl = document.getElementById('splitSecretTextMsg');
    if (splitTextEl) {
      splitTextEl.value = text;
      handleSplitSecretText();
    }
  }
  showAlert('info', 'Switched to multi-image mode. Select two or more cover images to divide the content across.');
}

function switchToSplitReveal() {
  switchTab('reveal');
  setRevealMode('split');
}

/* ==========================================================================
   Multi-Image Splitting Implementation (Hide Tab)
   ========================================================================== */

function handleSplitCoversSelected(files) {
  if (!files || files.length === 0) return;
  for (let i = 0; i < files.length; i++) {
    state.splitHide.covers.push(files[i]);
  }
  renderSplitCoversList();
  validateSplitHideForm();
}

function clearSplitCovers() {
  state.splitHide.covers = [];
  renderSplitCoversList();
  validateSplitHideForm();
}

function removeSplitCover(idx) {
  if (idx >= 0 && idx < state.splitHide.covers.length) {
    state.splitHide.covers.splice(idx, 1);
    renderSplitCoversList();
    validateSplitHideForm();
  }
}

function renderSplitCoversList() {
  const container = document.getElementById('splitCoversContainer');
  const grid = document.getElementById('splitCoversGrid');
  const countEl = document.getElementById('splitCoversCount');
  const capEl = document.getElementById('splitCombinedCap');

  if (!container || !grid) return;

  const covers = state.splitHide.covers;
  if (covers.length === 0) {
    container.classList.add('hidden');
    return;
  }

  container.classList.remove('hidden');
  countEl.textContent = `${covers.length} cover image${covers.length === 1 ? '' : 's'} selected`;
  grid.innerHTML = '';

  let totalEstCap = 0;
  covers.forEach((f, idx) => {
    const estCap = Math.max(1024, Math.round(f.size * 0.15));
    totalEstCap += estCap;

    const chip = document.createElement('div');
    chip.className = 'multi-cover-chip';
    chip.innerHTML = `
      <img class="multi-cover-thumb" src="${URL.createObjectURL(f)}" alt="${escapeHtml(f.name)}">
      <span class="multi-cover-name" title="${escapeHtml(f.name)}">${escapeHtml(f.name)}</span>
      <span class="multi-cover-cap">Cover #${idx + 1}</span>
      <button type="button" class="multi-cover-remove" title="Remove" onclick="removeSplitCover(${idx})">✕</button>
    `;
    grid.appendChild(chip);
  });

  if (capEl) capEl.textContent = `Combined Capacity: ~${formatBytes(totalEstCap)}`;
}

function toggleSplitSecretType() {
  const type = document.querySelector('input[name="splitSecretType"]:checked')?.value || 'file';
  state.splitHide.secretType = type;

  const fileBox = document.getElementById('splitSecretFileBox');
  const textBox = document.getElementById('splitSecretTextBox');

  if (type === 'file') {
    fileBox?.classList.remove('hidden');
    textBox?.classList.add('hidden');
  } else {
    textBox?.classList.remove('hidden');
    fileBox?.classList.add('hidden');
  }
  validateSplitHideForm();
}

function handleSplitSecretFile(file) {
  if (file) {
    state.splitHide.secretFile = file;
    const info = document.getElementById('splitSecretFileInfo');
    if (info) info.textContent = `${file.name} (${formatBytes(file.size)})`;
  } else {
    state.splitHide.secretFile = null;
    const info = document.getElementById('splitSecretFileInfo');
    if (info) info.textContent = 'No file chosen';
  }
  validateSplitHideForm();
}

function handleSplitSecretText() {
  const text = document.getElementById('splitSecretTextMsg')?.value || '';
  const len = text.length;
  const bytes = new TextEncoder().encode(text).length;
  document.getElementById('splitSecretCharCount').textContent = `${len} character${len === 1 ? '' : 's'}`;
  document.getElementById('splitSecretSize').textContent = `${bytes} byte${bytes === 1 ? '' : 's'}`;
  validateSplitHideForm();
}

function validateSplitHideForm() {
  const btn = document.getElementById('btnSplitSecret');
  if (!btn) return;

  if (state.splitHide.covers.length < 2) {
    btn.disabled = true;
    return;
  }

  let hasSecret = false;
  if (state.splitHide.secretType === 'file') {
    hasSecret = (state.splitHide.secretFile !== null);
  } else {
    const text = document.getElementById('splitSecretTextMsg')?.value?.trim() || '';
    hasSecret = (text.length > 0);
  }

  if (!hasSecret) {
    btn.disabled = true;
    return;
  }

  const p1 = document.getElementById('splitPassword')?.value || '';
  const p2 = document.getElementById('splitPasswordConfirm')?.value || '';
  if (p1.length > 0 && p1 !== p2) {
    btn.disabled = true;
    return;
  }

  btn.disabled = false;
}

async function submitSplitHide() {
  const btn = document.getElementById('btnSplitSecret');
  const progress = document.getElementById('splitProgress');
  const label = document.getElementById('splitProgressLabel');
  const resCard = document.getElementById('splitResultCard');

  btn.disabled = true;
  progress.classList.remove('hidden');
  resCard.classList.add('hidden');

  label.textContent = 'Compressing and partitioning secret payload...';

  const formData = new FormData();
  if (state.splitHide.secretType === 'file') {
    formData.append('secret_type', 'file');
    formData.append('secret_file', state.splitHide.secretFile);
  } else {
    formData.append('secret_type', 'text');
    formData.append('message', document.getElementById('splitSecretTextMsg')?.value || '');
  }

  const pass = document.getElementById('splitPassword')?.value || '';
  if (pass.length > 0) {
    formData.append('password', pass);
  }

  if (document.getElementById('splitCompress')?.checked) {
    formData.append('compress', 'true');
  }

  state.splitHide.covers.forEach((f, idx) => {
    formData.append(`cover_${idx}`, f);
  });

  try {
    label.textContent = 'Encrypting chunks and embedding in images...';
    const json = await apiCall('/api/split-hide', formData);
    progress.classList.add('hidden');
    btn.disabled = false;

    if (!json.success) {
      showAlert('danger', json.error || Terminology.ERR_OUTPUT_ERROR);
      return;
    }

    state.splitHide.resultParts = json.parts || [];
    state.splitHide.manifestJson = json.manifest || '';

    document.getElementById('splitResultTotal').textContent = json.total_parts;
    document.getElementById('splitManifestDetails').textContent = json.manifest || '';

    const dlGrid = document.getElementById('splitPartsDownloadGrid');
    dlGrid.innerHTML = '';

    json.parts.forEach(part => {
      const card = document.createElement('div');
      card.className = 'part-download-card';
      card.innerHTML = `
        <div class="part-info">
          <strong>${escapeHtml(part.filename)}</strong>
          <span style="font-size:0.75rem; color:var(--text-muted); display:block;">Part ${part.part_num} of ${json.total_parts}</span>
        </div>
        <button type="button" class="btn btn-secondary btn-sm" onclick="downloadSingleSplitPart(${part.part_num - 1})">Download</button>
      `;
      dlGrid.appendChild(card);
    });

    resCard.classList.remove('hidden');
    showAlert('success', 'Your protected images are ready.');

  } catch (e) {
    progress.classList.add('hidden');
    btn.disabled = false;
    showAlert('danger', Terminology.ERR_SERVER_CONNECTION);
  }
}

function downloadSingleSplitPart(idx) {
  const parts = state.splitHide.resultParts;
  if (!parts || idx < 0 || idx >= parts.length) return;
  const p = parts[idx];
  const blob = base64ToBlob(p.image_base64, 'image/png');
  const url = trackBlobUrl(URL.createObjectURL(blob));

  const a = document.createElement('a');
  a.href = url;
  a.download = p.filename || `part_${p.part_num}.png`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
}

function downloadAllSplitParts() {
  const parts = state.splitHide.resultParts;
  if (!parts || parts.length === 0) return;

  if (typeof HistoryManager !== 'undefined') {
    HistoryManager.record(
      'Split file',
      state.splitHide.secretFile ? state.splitHide.secretFile.name : 'file',
      `${parts.length} parts`,
      state.splitHide.password && state.splitHide.password.length > 0
    );
  }

  parts.forEach((p, idx) => {
    setTimeout(() => {
      downloadSingleSplitPart(idx);
    }, idx * 250);
  });
}

function downloadSplitManifest() {
  if (!state.splitHide.manifestJson) return;
  const blob = new Blob([state.splitHide.manifestJson], { type: 'application/json' });
  const url = trackBlobUrl(URL.createObjectURL(blob));

  const a = document.createElement('a');
  a.href = url;
  a.download = 'manifest.json';
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
}

/* ==========================================================================
   Multi-Image Recombination Implementation (Reveal Tab)
   ========================================================================== */

function handleSplitRevPartsSelected(files) {
  if (!files || files.length === 0) return;
  for (let i = 0; i < files.length; i++) {
    state.splitReveal.parts.push(files[i]);
  }
  renderSplitRevPartsList();
  validateSplitRevForm();
}

function clearSplitRevParts() {
  state.splitReveal.parts = [];
  renderSplitRevPartsList();
  validateSplitRevForm();
}

function removeSplitRevPart(idx) {
  if (idx >= 0 && idx < state.splitReveal.parts.length) {
    state.splitReveal.parts.splice(idx, 1);
    renderSplitRevPartsList();
    validateSplitRevForm();
  }
}

function renderSplitRevPartsList() {
  const container = document.getElementById('splitRevPartsContainer');
  const grid = document.getElementById('splitRevPartsGrid');
  const countEl = document.getElementById('splitRevPartsCount');

  if (!container || !grid) return;
  const parts = state.splitReveal.parts;

  if (parts.length === 0) {
    container.classList.add('hidden');
    return;
  }

  container.classList.remove('hidden');
  countEl.textContent = `${parts.length} part image${parts.length === 1 ? '' : 's'} selected`;
  grid.innerHTML = '';

  parts.forEach((f, idx) => {
    const chip = document.createElement('div');
    chip.className = 'part-chip';
    chip.innerHTML = `
      <span class="part-idx">#${idx + 1}</span>
      <span>${escapeHtml(f.name)}</span>
      <button type="button" class="btn-icon" style="font-size:11px; margin-left:4px;" onclick="removeSplitRevPart(${idx})">✕</button>
    `;
    grid.appendChild(chip);
  });
}

function validateSplitRevForm() {
  const btn = document.getElementById('btnSplitReveal');
  if (!btn) return;
  btn.disabled = (state.splitReveal.parts.length < 2);
}

async function submitSplitReveal() {
  const btn = document.getElementById('btnSplitReveal');
  const progress = document.getElementById('splitRevProgress');
  const resCard = document.getElementById('splitRevResultCard');

  btn.disabled = true;
  progress.classList.remove('hidden');
  resCard.classList.add('hidden');

  const formData = new FormData();
  state.splitReveal.parts.forEach((f, idx) => {
    formData.append(`part_${idx}`, f);
  });

  const pass = document.getElementById('splitRevPassword')?.value || '';
  if (pass.length > 0) {
    formData.append('password', pass);
  }

  try {
    const json = await apiCall('/api/split-reveal', formData);
    progress.classList.add('hidden');
    btn.disabled = false;

    if (!json.success) {
      const splitPassInput = document.getElementById('splitRevPassword');
      if (splitPassInput) splitPassInput.value = '';
      let errMsg = json.error || Terminology.ERR_WRONG_PASSWORD;
      if (json.error && (/password|auth|tamper|corrupt/i).test(json.error)) {
        errMsg = Terminology.ERR_WRONG_PASSWORD;
      }
      showAlert('danger', errMsg);
      return;
    }

    const textBox = document.getElementById('splitRevTextBox');
    const fileBox = document.getElementById('splitRevFileBox');

    if (json.is_text) {
      textBox.classList.remove('hidden');
      fileBox.classList.add('hidden');
      document.getElementById('splitRevResultText').value = json.text || '';
      document.getElementById('splitRevPayloadTag').textContent = `${json.payload_length || 0} bytes recovered`;
      if (typeof HistoryManager !== 'undefined') {
        HistoryManager.record(
          'Recombine file',
          `${state.splitReveal.parts.length} parts`,
          Terminology.CONTENT_TEXT,
          json.is_protected
        );
      }
    } else {
      fileBox.classList.remove('hidden');
      textBox.classList.add('hidden');
      document.getElementById('splitRevFileName').textContent = json.filename || 'recovered_file.bin';
      document.getElementById('splitRevFileSize').textContent = formatBytes(json.payload_length || 0);

      const blob = base64ToBlob(json.file_base64, 'application/octet-stream');
      state.splitReveal.recoveredBlobUrl = trackBlobUrl(URL.createObjectURL(blob));
      state.splitReveal.recoveredFilename = json.filename || 'recovered_file.bin';
      state.splitReveal.isProtected = !!json.is_protected;
    }

    resCard.classList.remove('hidden');
    showAlert('success', Terminology.MSG_RECOVERED_SUCCESS);

  } catch (e) {
    progress.classList.add('hidden');
    btn.disabled = false;
    showAlert('danger', Terminology.ERR_SERVER_CONNECTION);
  }
}

function copySplitRecoveredText() {
  const text = document.getElementById('splitRevResultText')?.value || '';
  navigator.clipboard.writeText(text).then(() => {
    showAlert('success', 'Text copied to clipboard.');
  });
}

function downloadSplitRecoveredFile() {
  if (!state.splitReveal.recoveredBlobUrl) return;
  const a = document.createElement('a');
  a.href = state.splitReveal.recoveredBlobUrl;
  const filename = state.splitReveal.recoveredFilename || 'recovered_file.bin';
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);

  if (typeof HistoryManager !== 'undefined') {
    HistoryManager.record(
      'Recombine file',
      `${state.splitReveal.parts.length} parts`,
      filename,
      state.splitReveal.isProtected
    );
  }

  showAlert('success', 'Download started. Session state cleared.');
  setTimeout(() => {
    clearSplitRevParts();
    document.getElementById('splitRevResultCard')?.classList.add('hidden');
    goHome();
  }, 400);
}

/* ==========================================================================
   Privacy Toolkit Implementation
   ========================================================================== */

function handlePrivImageSelect(file) {
  if (!file) return;
  state.privacy.imageFile = file;

  const reader = new FileReader();
  reader.onload = (e) => {
    document.getElementById('privThumb').src = e.target.result;
    document.getElementById('privMetaName').textContent = file.name;
    document.getElementById('privMetaSize').textContent = formatBytes(file.size);
    document.getElementById('privDropzone').classList.add('hidden');
    document.getElementById('privImageMeta').classList.remove('hidden');
    document.getElementById('btnScanPrivacy').disabled = false;
    document.getElementById('privResultCard').classList.add('hidden');
    document.getElementById('privCleanCard').classList.add('hidden');
  };
  reader.readAsDataURL(file);
}

function resetPrivacyImage() {
  state.privacy.imageFile = null;
  state.privacy.scanResult = null;
  state.privacy.cleanBlobUrl = null;

  const input = document.getElementById('privImageInput');
  if (input) input.value = '';

  document.getElementById('privDropzone').classList.remove('hidden');
  document.getElementById('privImageMeta').classList.add('hidden');
  document.getElementById('btnScanPrivacy').disabled = true;
  document.getElementById('privResultCard').classList.add('hidden');
  document.getElementById('privCleanCard').classList.add('hidden');
}

async function submitScanPrivacy() {
  if (!state.privacy.imageFile) return;

  const btn = document.getElementById('btnScanPrivacy');
  btn.disabled = true;

  const formData = new FormData();
  formData.append('image', state.privacy.imageFile);

  try {
    const json = await apiCall('/api/metadata-scan', formData);
    btn.disabled = false;

    if (!json.success) {
      showAlert('danger', json.error || 'Failed to scan metadata.');
      return;
    }

    state.privacy.scanResult = json;

    const risk = (json.privacyRisk || (json.risk_level ? json.risk_level.toLowerCase() : 'low')).toLowerCase();
    const badge = document.getElementById('privRiskBadge');
    badge.className = 'badge-risk';
    if (risk === 'high') {
      badge.classList.add('badge-risk-high');
      badge.textContent = 'High risk';
    } else if (risk === 'medium') {
      badge.classList.add('badge-risk-med');
      badge.textContent = 'Medium risk';
    } else {
      badge.classList.add('badge-risk-low');
      badge.textContent = 'Low risk';
    }

    document.getElementById('privRiskReason').textContent = json.risk_reason || (
      risk === 'high' ? 'GPS location coordinates detected (reveals precise physical location).' :
      risk === 'medium' ? 'Device model, software fingerprint, or timestamp detected.' :
      'No sensitive geolocation or device metadata detected.'
    );

    const hasGps = Boolean(json.hasGps || json.has_gps);
    const locSection = document.getElementById('privLocationSection');
    const noGpsNotice = document.getElementById('privNoGpsNotice');

    let lat = 0, lon = 0;
    let latRef = 'N', lonRef = 'E';
    let alt = null;
    let time = null;

    if (hasGps) {
      const gps = json.gps || {};
      lat = (typeof gps.latitude === 'number') ? gps.latitude : (json.latitude || 0);
      lon = (typeof gps.longitude === 'number') ? gps.longitude : (json.longitude || 0);
      latRef = gps.latitudeRef || json.latitude_ref || (lat >= 0 ? 'N' : 'S');
      lonRef = gps.longitudeRef || json.longitude_ref || (lon >= 0 ? 'E' : 'W');
      alt = (gps.altitude != null) ? gps.altitude : (json.has_altitude ? json.altitude : null);
      time = gps.timestamp || json.gps_timestamp || json.datetime || null;

      document.getElementById('privGpsLat').textContent = `${Math.abs(lat).toFixed(6)}° ${latRef}`;
      document.getElementById('privGpsLon').textContent = `${Math.abs(lon).toFixed(6)}° ${lonRef}`;

      const altWrap = document.getElementById('privAltWrap');
      if (alt != null) {
        document.getElementById('privGpsAlt').textContent = `${alt.toFixed(1)} m`;
        altWrap.classList.remove('hidden');
      } else {
        altWrap.classList.add('hidden');
      }

      const timeWrap = document.getElementById('privTimeWrap');
      if (time) {
        document.getElementById('privGpsTime').textContent = time;
        timeWrap.classList.remove('hidden');
      } else {
        timeWrap.classList.add('hidden');
      }

      // Requirement 4 & 5: Open in Maps with URL-encoded comma between latitude and longitude
      const mapsQuery = encodeURIComponent(`${lat.toFixed(6)},${lon.toFixed(6)}`);
      const mapsUrl = `https://www.google.com/maps/search/?api=1&query=${mapsQuery}`;
      const mapsBtn = document.getElementById('btnOpenMaps');
      mapsBtn.href = mapsUrl;
      mapsBtn.setAttribute('target', '_blank');
      mapsBtn.setAttribute('rel', 'noopener noreferrer');

      locSection.classList.remove('hidden');
      noGpsNotice.classList.add('hidden');
    } else {
      locSection.classList.add('hidden');
      noGpsNotice.classList.remove('hidden');
    }

    // General Photo Information
    const camEl = document.getElementById('privValCamera');
    const camStr = `${json.camera_make || ''} ${json.camera_model || ''}`.trim();
    camEl.textContent = camStr.length > 0 ? camStr : 'None detected';

    document.getElementById('privValSoftware').textContent = json.software || 'None detected';
    document.getElementById('privValDate').textContent = json.datetime || 'None detected';
    document.getElementById('privValBytes').textContent = formatBytes(json.metadata_bytes || 0);

    // Populate Technical Details
    const techEl = document.getElementById('privTechDetails');
    if (techEl) {
      let tHtml = '<div style="display:flex;flex-direction:column;gap:0.35rem;">';
      tHtml += `<div><strong>hasGps:</strong> ${hasGps ? 'true' : 'false'}</div>`;
      if (hasGps) {
        tHtml += `<div><strong>GPSLatitude:</strong> ${lat} (${latRef})</div>`;
        tHtml += `<div><strong>GPSLongitude:</strong> ${lon} (${lonRef})</div>`;
        if (alt != null) tHtml += `<div><strong>GPSAltitude:</strong> ${alt} m</div>`;
        if (time) tHtml += `<div><strong>GPSTimeStamp:</strong> ${escapeHtml(time)}</div>`;
      }
      tHtml += `<div><strong>privacyRisk:</strong> ${escapeHtml(risk)}</div>`;
      tHtml += `<div><strong>has_exif:</strong> ${json.has_exif ? 'true' : 'false'}</div>`;
      tHtml += `<div><strong>camera_make:</strong> ${escapeHtml(json.camera_make || 'N/A')}</div>`;
      tHtml += `<div><strong>camera_model:</strong> ${escapeHtml(json.camera_model || 'N/A')}</div>`;
      tHtml += `<div><strong>software:</strong> ${escapeHtml(json.software || 'N/A')}</div>`;
      tHtml += `<div><strong>datetime:</strong> ${escapeHtml(json.datetime || 'N/A')}</div>`;
      tHtml += `<div><strong>metadata_bytes:</strong> ${json.metadata_bytes || 0}</div>`;
      tHtml += '</div>';
      techEl.innerHTML = tHtml;
    }

    document.getElementById('privResultCard').classList.remove('hidden');
    const riskLabel = risk === 'high' ? 'High' : (risk === 'medium' ? 'Medium' : 'Low');
    showAlert('info', `Scan complete: ${riskLabel.toLowerCase()} risk detected.`);

  } catch (err) {
    btn.disabled = false;
    showAlert('danger', Terminology.ERR_SERVER_CONNECTION);
  }
}

async function submitStripMetadata() {
  if (!state.privacy.imageFile) return;

  const btn = document.getElementById('btnStripMetadata');
  if (btn) btn.disabled = true;
  const btnLoc = document.getElementById('btnRemoveLocation');
  if (btnLoc) btnLoc.disabled = true;

  const formData = new FormData();
  formData.append('image', state.privacy.imageFile);

  try {
    const json = await apiCall('/api/metadata-strip', formData);
    if (btn) btn.disabled = false;
    if (btnLoc) btnLoc.disabled = false;

    if (!json.success) {
      showAlert('danger', json.error || 'Failed to strip metadata.');
      return;
    }

    const mime = (json.format === 'PNG') ? 'image/png' : 'image/jpeg';
    const blob = base64ToBlob(json.image_base64, mime);
    const blobUrl = trackBlobUrl(URL.createObjectURL(blob));

    state.privacy.cleanBlobUrl = blobUrl;
    state.privacy.cleanFilename = json.filename || 'clean_image.png';

    const noticeEl = document.getElementById('privCleanNotice');
    noticeEl.textContent = Terminology.MSG_LOCATION_REMOVED;

    document.getElementById('privCleanCard').classList.remove('hidden');
    showAlert('success', Terminology.MSG_LOCATION_REMOVED);

  } catch (err) {
    if (btn) btn.disabled = false;
    if (btnLoc) btnLoc.disabled = false;
    showAlert('danger', Terminology.ERR_SERVER_CONNECTION);
  }
}

function downloadCleanImage() {
  if (!state.privacy.cleanBlobUrl) return;

  const url = state.privacy.cleanBlobUrl;
  const filename = state.privacy.cleanFilename || 'clean_image.png';

  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);

  if (typeof HistoryManager !== 'undefined') {
    HistoryManager.record(
      'Remove metadata',
      state.privacy.imageFile ? state.privacy.imageFile.name : 'image',
      filename,
      false
    );
  }

  showAlert('success', 'Download started. Clean image saved.');

  setTimeout(() => {
    resetPrivacyImage();
    goHome();
  }, 400);
}

/* ==========================================================================
   Recent Activity History (100% Client-Side LocalStorage)
   ========================================================================== */

const HistoryManager = {
  STORAGE_KEY: 'hushframe_local_activity',
  ENABLED_KEY: 'hushframe_activity_enabled',
  LEGACY_STORAGE_KEY: 'bmp_stego_local_activity',
  LEGACY_ENABLED_KEY: 'bmp_stego_activity_enabled',

  isEnabled() {
    let val = localStorage.getItem(this.ENABLED_KEY);
    if (val === null) {
      val = localStorage.getItem(this.LEGACY_ENABLED_KEY);
    }
    return val !== 'false';
  },

  setEnabled(enabled) {
    localStorage.setItem(this.ENABLED_KEY, enabled ? 'true' : 'false');
    if (!enabled) {
      this.clear();
    } else {
      this.render();
    }
  },

  getAll() {
    if (!this.isEnabled()) return [];
    try {
      let data = localStorage.getItem(this.STORAGE_KEY);
      if (!data) {
        data = localStorage.getItem(this.LEGACY_STORAGE_KEY);
        if (data) {
          localStorage.setItem(this.STORAGE_KEY, data);
        }
      }
      return data ? JSON.parse(data) : [];
    } catch (e) {
      return [];
    }
  },

  record(action, inputName, outputName, isProtected, note = '') {
    if (!this.isEnabled()) return;
    const items = this.getAll();
    const entry = {
      id: Date.now() + Math.random().toString(36).substring(2, 7),
      time: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
      date: new Date().toLocaleDateString(),
      action,
      inputName: inputName || '—',
      outputName: outputName || '—',
      isProtected: !!isProtected,
      note: note || ''
    };
    items.unshift(entry);
    if (items.length > 50) items.pop();
    try {
      localStorage.setItem(this.STORAGE_KEY, JSON.stringify(items));
    } catch (e) {}
    this.render();
  },

  clear() {
    try {
      localStorage.removeItem(this.STORAGE_KEY);
    } catch (e) {}
    this.render();
  },

  render() {
    const table = document.getElementById('histTable');
    const tbody = document.getElementById('histTableBody');
    const emptyState = document.getElementById('histEmptyState');
    const toggle = document.getElementById('histToggle');
    if (toggle) toggle.checked = this.isEnabled();

    if (!tbody || !emptyState) return;

    if (!this.isEnabled()) {
      table.style.display = 'none';
      emptyState.style.display = 'flex';
      emptyState.innerHTML = `
        <div class="empty-state-icon">
          <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <circle cx="12" cy="12" r="10"></circle>
            <line x1="4.93" y1="4.93" x2="19.07" y2="19.07"></line>
          </svg>
        </div>
        <h4 class="empty-state-title">Activity logging is disabled</h4>
        <p class="empty-state-desc">Enable "Save activity to local storage" above to record operations in this session.</p>
      `;
      return;
    }

    const items = this.getAll();
    if (items.length === 0) {
      table.style.display = 'none';
      emptyState.style.display = 'flex';
      emptyState.innerHTML = `
        <div class="empty-state-icon">
          <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <circle cx="12" cy="12" r="10"></circle>
            <polyline points="12 6 12 12 16 14"></polyline>
          </svg>
        </div>
        <h4 class="empty-state-title">No recent activity</h4>
        <p class="empty-state-desc">Operations you perform during this session will be recorded privately in your browser.</p>
      `;
      return;
    }

    table.style.display = 'table';
    emptyState.style.display = 'none';
    tbody.innerHTML = '';

    items.forEach(item => {
      const tr = document.createElement('tr');
      const actionText = String(item.action || '');
      const actionLower = actionText.toLowerCase();

      let actionClass = 'action-neutral';
      let actionIcon = '';
      if (actionLower.includes('protect') || actionLower.includes('hide')) {
        actionClass = 'action-protect';
        actionIcon = '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>';
      } else if (actionLower.includes('recover') || actionLower.includes('reveal')) {
        actionClass = 'action-recover';
        actionIcon = '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>';
      } else if (actionLower.includes('split') || actionLower.includes('recombine')) {
        actionClass = 'action-neutral';
        actionIcon = '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="2" width="20" height="8" rx="2" ry="2"/><rect x="2" y="14" width="20" height="8" rx="2" ry="2"/><line x1="6" y1="6" x2="6.01" y2="6"/><line x1="6" y1="18" x2="6.01" y2="18"/></svg>';
      } else if (actionLower.includes('metadata') || actionLower.includes('privacy')) {
        actionClass = 'action-neutral';
        actionIcon = '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>';
      }

      const inputVal = item.inputName || '—';
      const outputVal = item.outputName || '—';

      tr.innerHTML = `
        <td class="col-timestamp">
          <div class="activity-time-wrap">
            <span class="activity-date">${escapeHtml(item.date || '')}</span>
            <span class="activity-time">${escapeHtml(item.time || '')}</span>
          </div>
        </td>
        <td class="col-action">
          <span class="activity-action-chip ${actionClass}">
            ${actionIcon}
            <span>${escapeHtml(actionText)}</span>
          </span>
        </td>
        <td class="col-file">
          <span class="activity-filename" title="${escapeHtml(inputVal)}">${escapeHtml(inputVal)}</span>
        </td>
        <td class="col-file">
          <span class="activity-filename" title="${escapeHtml(outputVal)}">${escapeHtml(outputVal)}</span>
        </td>
        <td class="col-status">
          <span class="badge ${item.isProtected ? 'badge-protected' : 'badge-unprotected'}">
            ${item.isProtected ? 'Protected' : 'Unprotected'}
          </span>
        </td>
      `;
      tbody.appendChild(tr);
    });
  }
};

function toggleHistoryEnabled(checked) {
  HistoryManager.setEnabled(checked);
}

/* ==========================================================================
   Theme Management (Light & Dark Obsidian)
   ========================================================================== */

function initTheme() {
  const saved = localStorage.getItem('hushframe_theme') || 'light';
  document.documentElement.setAttribute('data-theme', saved);
  updateThemeIcon(saved);
}

function toggleTheme() {
  const current = document.documentElement.getAttribute('data-theme') || 'light';
  const next = current === 'dark' ? 'light' : 'dark';
  document.documentElement.setAttribute('data-theme', next);
  try { localStorage.setItem('hushframe_theme', next); } catch (e) {}
  updateThemeIcon(next);
}

function updateThemeIcon(theme) {
  const moon = document.querySelector('.icon-moon');
  const sun = document.querySelector('.icon-sun');
  if (moon && sun) {
    if (theme === 'dark') {
      moon.classList.add('hidden');
      sun.classList.remove('hidden');
    } else {
      moon.classList.remove('hidden');
      sun.classList.add('hidden');
    }
  }
}

/* ==========================================================================
   Interactive LSB Bit-Plane & Pixel Sandbox
   ========================================================================== */

const sandboxState = {
  r: 178,
  g: 94,
  b: 215,
  secretBit: 1
};

function initSandbox() {
  renderSandbox();
}

function randomizeSandboxPixel() {
  sandboxState.r = Math.floor(Math.random() * 240) + 10;
  sandboxState.g = Math.floor(Math.random() * 240) + 10;
  sandboxState.b = Math.floor(Math.random() * 240) + 10;
  sandboxState.secretBit = Math.random() > 0.5 ? 1 : 0;
  renderSandbox();
}

function toggleSandboxBit() {
  sandboxState.secretBit = sandboxState.secretBit === 1 ? 0 : 1;
  renderSandbox();
}

function renderSandbox() {
  const origR = sandboxState.r;
  const stegoR = (origR & ~1) | sandboxState.secretBit;
  
  const origBin = origR.toString(2).padStart(8, '0');
  const stegoBin = stegoR.toString(2).padStart(8, '0');
  
  const origColor = `rgb(${origR}, ${sandboxState.g}, ${sandboxState.b})`;
  const stegoColor = `rgb(${stegoR}, ${sandboxState.g}, ${sandboxState.b})`;
  
  const origSwatch = document.getElementById('sbOrigSwatch');
  const stegoSwatch = document.getElementById('sbStegoSwatch');
  if (origSwatch) origSwatch.style.backgroundColor = origColor;
  if (stegoSwatch) stegoSwatch.style.backgroundColor = stegoColor;
  
  const origRgb = document.getElementById('sbOrigRgb');
  const stegoRgb = document.getElementById('sbStegoRgb');
  if (origRgb) origRgb.textContent = `RGB(${origR}, ${sandboxState.g}, ${sandboxState.b})`;
  if (stegoRgb) stegoRgb.textContent = `RGB(${stegoR}, ${sandboxState.g}, ${sandboxState.b})`;
  
  const origBits = document.getElementById('sbOrigBits');
  const stegoBits = document.getElementById('sbStegoBits');
  if (origBits) {
    origBits.innerHTML = origBin.split('').map((bit, idx) => 
      `<span class="sb-bit ${idx === 7 ? 'sb-bit-target' : ''}">${bit}</span>`
    ).join('');
  }
  if (stegoBits) {
    stegoBits.innerHTML = stegoBin.split('').map((bit, idx) => 
      `<span class="sb-bit ${idx === 7 ? 'sb-bit-modified' : ''}">${bit}</span>`
    ).join('');
  }
  
  const deltaVal = Math.abs(origR - stegoR);
  const deltaBadge = document.getElementById('sbDeltaBadge');
  if (deltaBadge) {
    deltaBadge.textContent = deltaVal === 0 ? 'Bit matches (Δ = 0)' : 'LSB flipped (Δ = 1/255 ≈ 0.39%)';
  }
}

/* ==========================================================================
   Procedural Sample Carrier Generator (1-Click Interactive Demo)
   ========================================================================== */

function loadSampleCarrier() {
  const canvas = document.createElement('canvas');
  canvas.width = 800;
  canvas.height = 600;
  const ctx = canvas.getContext('2d');
  
  // High-entropy background gradient
  const grad = ctx.createLinearGradient(0, 0, 800, 600);
  grad.addColorStop(0, '#1e1b4b');
  grad.addColorStop(0.3, '#312e81');
  grad.addColorStop(0.7, '#065f46');
  grad.addColorStop(1, '#022c22');
  ctx.fillStyle = grad;
  ctx.fillRect(0, 0, 800, 600);
  
  // High-entropy textured organic shapes
  for (let i = 0; i < 35; i++) {
    ctx.beginPath();
    const x = (Math.sin(i * 1.7) * 0.4 + 0.5) * 800;
    const y = (Math.cos(i * 1.3) * 0.4 + 0.5) * 600;
    const r = (i * 13) % 150 + 25;
    ctx.arc(x, y, r, 0, Math.PI * 2);
    ctx.fillStyle = `hsla(${(i * 37) % 360}, 75%, 65%, 0.16)`;
    ctx.fill();
  }
  
  // Lattice grid overlay
  ctx.strokeStyle = 'rgba(255, 255, 255, 0.05)';
  ctx.lineWidth = 1;
  for (let x = 0; x < 800; x += 30) {
    ctx.beginPath();
    ctx.moveTo(x, 0);
    ctx.lineTo(x, 600);
    ctx.stroke();
  }
  for (let y = 0; y < 600; y += 30) {
    ctx.beginPath();
    ctx.moveTo(0, y);
    ctx.lineTo(800, y);
    ctx.stroke();
  }

  canvas.toBlob((blob) => {
    if (!blob) return;
    const file = new File([blob], 'hushframe_sample_carrier.png', { type: 'image/png' });
    openHideScreen();
    handleHideImageSelect(file);
    showAlert('success', 'Loaded sample carrier image (800×600 PNG, 175 KB capacity). Ready to protect a file!');
  }, 'image/png');
}

/* ==========================================================================
   Live Password Entropy Evaluation
   ========================================================================== */

function evaluatePasswordEntropy(pwd) {
  if (!pwd || pwd.length === 0) {
    return { bits: 0, rating: 'Optional password', class: 'empty' };
  }
  
  let pool = 0;
  if (/[a-z]/.test(pwd)) pool += 26;
  if (/[A-Z]/.test(pwd)) pool += 26;
  if (/[0-9]/.test(pwd)) pool += 10;
  if (/[^a-zA-Z0-9]/.test(pwd)) pool += 32;
  
  const entropy = Math.round(pwd.length * Math.log2(Math.max(pool, 2)));
  
  if (entropy < 35) {
    return { bits: entropy, rating: 'Weak password', class: 'weak' };
  } else if (entropy < 60) {
    return { bits: entropy, rating: 'Moderate protection', class: 'moderate' };
  } else if (entropy < 85) {
    return { bits: entropy, rating: 'Strong protection', class: 'strong' };
  } else {
    return { bits: entropy, rating: 'Cryptographically hardened', class: 'hardened' };
  }
}

function updateEntropyUI(inputEl, fillEl, ratingEl, bitsEl) {
  if (!inputEl) return;
  const res = evaluatePasswordEntropy(inputEl.value);
  if (fillEl) {
    fillEl.className = `entropy-bar-fill ${res.class}`;
    let width = 0;
    if (res.bits > 0) width = Math.min(100, Math.max(15, Math.round((res.bits / 90) * 100)));
    fillEl.style.width = `${width}%`;
  }
  if (ratingEl) ratingEl.textContent = res.rating;
  if (bitsEl) bitsEl.textContent = res.bits > 0 ? `~${res.bits}-bit entropy` : 'Argon2id (RFC 9106)';
}

function clearLocalHistory() {
  HistoryManager.clear();
  showAlert('info', 'Recent activity cleared.');
}
