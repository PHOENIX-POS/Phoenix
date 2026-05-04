'use strict';
/**
 * Phoenix POS — Security Patch v2.0
 * يُحمَّل في كل صفحة عبر <script src="security-patch.js">
 * يعمل بعد تحميل كل شيء (window load) عشان يقدر يعدّل الدوال
 */

(function () {

  // ─── SHA-256 ───────────────────────────────────────
  async function sha256(text) {
    if (!text) return '';
    const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
    return Array.from(new Uint8Array(buf))
      .map(b => b.toString(16).padStart(2, '0')).join('');
  }

  function isHashed(v) {
    return typeof v === 'string' && /^[0-9a-f]{64}$/.test(v);
  }

  window.__sha256   = sha256;
  window.__isHashed = isHashed;

  // ─── نستنى الصفحة تتحمل كاملة ─────────────────────
  window.addEventListener('load', function () {

    // ── 1. Patch saveDB ─────────────────────────────
    var _origSaveDB = window.saveDB;
    if (typeof _origSaveDB === 'function') {
      window.saveDB = async function (db) {
        var copy = JSON.parse(JSON.stringify(db));
        for (var code of Object.keys(copy)) {
          var shop = copy[code];
          if (!shop) continue;
          if (shop.managerPassword && !isHashed(shop.managerPassword))
            shop.managerPassword = await sha256(shop.managerPassword);
          if (Array.isArray(shop.employees)) {
            for (var emp of shop.employees) {
              if (emp.password && !isHashed(emp.password))
                emp.password = await sha256(emp.password);
            }
          }
        }
        if (window._dbCache !== undefined) window._dbCache = copy;
        return _origSaveDB(copy);
      };
    }

    // ── 2. Patch loginUnified ────────────────────────
    var _origLogin = window.loginUnified;
    if (typeof _origLogin === 'function') {
      window.loginUnified = async function () {
        var passEl = document.getElementById('unifiedLoginPassword');
        if (!passEl || !passEl.value) return _origLogin();
        var raw = passEl.value;
        passEl.value = await sha256(raw);
        try   { await _origLogin(); }
        finally { passEl.value = raw; }
      };
      // الـ aliases
      window.loginManager  = window.loginUnified;
      window.loginEmployee = window.loginUnified;
    }

    // ── 3. Patch addEmployee ─────────────────────────
    var _origAddEmp = window.addEmployee;
    if (typeof _origAddEmp === 'function') {
      window.addEmployee = async function () {
        var passEl = document.getElementById('empPass');
        if (!passEl) return _origAddEmp();
        var raw = passEl.value;
        passEl.value = await sha256(raw);
        try   { await _origAddEmp(); }
        finally { passEl.value = raw; }
      };
    }

    // ── 4. Patch saveSettings ────────────────────────
    var _origSettings = window.saveSettings;
    if (typeof _origSettings === 'function') {
      window.saveSettings = async function () {
        var passEl = document.getElementById('managerSettingPassword');
        if (passEl && passEl.value) {
          var raw = passEl.value;
          passEl.value = await sha256(raw);
          try   { await _origSettings(); }
          finally { passEl.value = ''; }
        } else {
          return _origSettings();
        }
      };
    }

    // ── 5. Patch saveProfile ─────────────────────────
    var _origProfile = window.saveProfile;
    if (typeof _origProfile === 'function') {
      window.saveProfile = async function () {
        var passEl    = document.getElementById('profilePassword');
        var confirmEl = document.getElementById('profilePasswordConfirm');
        if (passEl && passEl.value) {
          var raw    = passEl.value;
          var hashed = await sha256(raw);
          passEl.value    = hashed;
          if (confirmEl) confirmEl.value = hashed;
          try   { await _origProfile(); }
          finally {
            passEl.value    = '';
            if (confirmEl) confirmEl.value = '';
          }
        } else {
          return _origProfile();
        }
      };
    }

    // ── 6. Patch devCreateStoreNew ───────────────────
    var _origDevCreate = window.devCreateStoreNew || window.devCreateStore;
    if (typeof _origDevCreate === 'function') {
      var _patchedDevCreate = async function () {
        var passEl = document.getElementById('devNewMgrPass');
        if (!passEl) return _origDevCreate();
        var raw = passEl.value;
        passEl.value = await sha256(raw);
        try   { await _origDevCreate(); }
        finally { passEl.value = ''; }
      };
      window.devCreateStoreNew = _patchedDevCreate;
      window.devCreateStore    = _patchedDevCreate;
    }

    // ── 7. Patch devSaveEdit ─────────────────────────
    var _origDevEdit = window.devSaveEdit;
    if (typeof _origDevEdit === 'function') {
      window.devSaveEdit = async function () {
        var passEl = document.getElementById('devEditMgrPass');
        if (passEl && passEl.value) {
          var raw = passEl.value;
          passEl.value = await sha256(raw);
          try   { await _origDevEdit(); }
          finally { passEl.value = ''; }
        } else {
          return _origDevEdit();
        }
      };
    }

    // ── 8. disabled ──────────────────────────────────
    window.toggleEmpPassword = function () { /* disabled for security */ };

    console.log('%c🔒 Phoenix Security Patch v2 active', 'color:#7A9A6A;font-weight:bold');
  });

})();
