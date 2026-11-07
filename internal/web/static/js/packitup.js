/* The Backup page's restore. Codes come in however is easiest: the
   webcam, a dropped or pasted screenshot, a picked file or the backup
   file. They're read here in the browser; only their text is sent. Once
   every part of a backup is in, the page moves on by itself: to the PIN
   when it has one, or straight to restoring an empty install.
   Delegated, so it works however often a boosted navigation brings the
   page back. */
(function () {
  "use strict";
  if (window.atPackItUp) return;
  window.atPackItUp = true;

  var APP = "AUTOTHROTTLE";
  var MAX_SIDE = 2000;          // a phone screenshot's modules survive this
  var CAM_SIDE = 1280;          // webcam frames at full 720p: dense codes need every pixel
  var SCAN_EVERY_MS = 150;
  var MAX_CODES_PER_IMAGE = 12;
  var B45 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:";
  var CODE = /^PIU1\*([A-Z0-9]+)\*W([A-Z0-9]+)\*S([A-Z0-9]+)\*V(\d+)\*T[A-Z0-9]+\*P(\d+)\.(\d+)\*C[0-9A-F]+\*H([0-9A-F]+)\*EB45\*(.+)$/;

  function form() { return document.querySelector("[data-piu-restore]"); }
  function q(f, sel) { return f && f.querySelector(sel); }
  function isCode(t) { return typeof t === "string" && t.indexOf("PIU1*") === 0; }

  function setStatus(f, text, tone) {
    var el = q(f, "[data-piu-status]");
    if (!el) return;
    el.textContent = text;
    el.setAttribute("data-tone", tone || "");
  }

  /* ── What the codes so far add up to ─────────────────────────── */

  // Reads the blob header's flags from part 1, so the page knows whether
  // a PIN will be needed before anything is sent.
  function lockedFrom(payload) {
    var s = payload.slice(0, 9), bytes = [];
    for (var i = 0; i + 2 < s.length; i += 3) {
      var n = B45.indexOf(s[i]) + B45.indexOf(s[i + 1]) * 45 + B45.indexOf(s[i + 2]) * 2025;
      bytes.push(n >> 8, n & 255);
    }
    return bytes.length > 4 && (bytes[4] & 2) !== 0;
  }

  function analyse(lines) {
    var groups = {}, best = null;
    lines.forEach(function (line) {
      var m = CODE.exec(line.trim());
      if (!m || m[1] !== APP) return;
      var key = m[2] + "|" + m[4] + "|" + m[7];
      var g = groups[key] || (groups[key] = { version: +m[4], total: +m[6], parts: {}, locked: false });
      g.parts[+m[5]] = true;
      if (+m[5] === 1) g.locked = lockedFrom(m[8]);
      if (!best || g.version > best.version) best = g;
    });
    if (!best) return null;
    var missing = [];
    for (var p = 1; p <= best.total; p++) if (!best.parts[p]) missing.push(p);
    best.missing = missing;
    best.complete = missing.length === 0;
    return best;
  }

  function addCodes(f, codes) {
    var area = q(f, "[data-piu-codes]");
    var have = area.value.split(/\r?\n/).map(function (s) { return s.trim(); }).filter(Boolean);
    var added = 0;
    codes.forEach(function (raw) {
      var code = String(raw).trim();
      if (isCode(code) && have.indexOf(code) < 0) { have.push(code); added++; }
    });
    area.value = have.join("\n");
    return added;
  }

  // After every new code: say where things stand, and when the backup is
  // whole, take the next step for the person.
  function progress(f, added, sourceLabel) {
    var state = analyse(q(f, "[data-piu-codes]").value.split(/\r?\n/));
    if (!state) {
      if (sourceLabel) setStatus(f, "No backup code in " + sourceLabel + ". Use a picture where the whole code is sharp and visible.", "warn");
      return;
    }
    if (added) flash(f);
    if (!state.complete) {
      setStatus(f, "Got " + (state.total - state.missing.length) + " of " + state.total + " parts. Show part " + state.missing[0] + " next.", "");
      return;
    }
    stopCamera(f);
    var lead = "Backup v" + state.version + " is ready" + (state.total > 1 ? " (" + state.total + " parts)" : "") + ".";
    var replace = q(f, "input[name=replace]");
    var pin = q(f, "[data-piu-pin]");
    if (state.locked) {
      setStatus(f, lead + " Enter its PIN" + (replace ? ", tick Replace my current setup," : "") + " and press Enter.", "good");
      pin.focus();
    } else if (!replace && f.hasAttribute("data-piu-autosubmit")) {
      setStatus(f, lead + " Restoring…", "good");
      if (!f.dataset.piuSent) { f.dataset.piuSent = "1"; submit(f); }
    } else {
      setStatus(f, lead + " Tick Replace my current setup, then Restore.", "good");
      (replace || q(f, "[data-piu-submit]")).focus();
    }
  }

  function submit(f) {
    if (typeof f.requestSubmit === "function") f.requestSubmit(q(f, "[data-piu-submit]"));
    else q(f, "[data-piu-submit]").click();
  }

  function flash(f) {
    var drop = q(f, "[data-piu-drop]");
    if (!drop) return;
    drop.classList.remove("at-piu-hit");
    void drop.offsetWidth;
    drop.classList.add("at-piu-hit");
  }

  /* ── Reading pictures and files ─────────────────────────────── */

  function detector() {
    if (!("BarcodeDetector" in window)) return null;
    try { return new window.BarcodeDetector({ formats: ["qr_code"] }); } catch (e) { return null; }
  }

  function draw(source, w, h, side) {
    var scale = Math.min(1, side / Math.max(w, h));
    var c = document.createElement("canvas");
    c.width = Math.max(1, Math.round(w * scale));
    c.height = Math.max(1, Math.round(h * scale));
    var ctx = c.getContext("2d", { willReadFrequently: true });
    ctx.drawImage(source, 0, 0, c.width, c.height);
    return { canvas: c, ctx: ctx };
  }

  // jsQR reads one code per call: read one, cover it, look again.
  function jsqrAll(c, limit) {
    if (typeof window.jsQR !== "function") return [];
    var out = [];
    for (var i = 0; i < limit; i++) {
      var img = c.ctx.getImageData(0, 0, c.canvas.width, c.canvas.height);
      var hit = window.jsQR(img.data, img.width, img.height, { inversionAttempts: "attemptBoth" });
      if (!hit) break;
      out.push(hit.data);
      var l = hit.location, pts = [l.topLeftCorner, l.topRightCorner, l.bottomRightCorner, l.bottomLeftCorner];
      var xs = pts.map(function (p) { return p.x; }), ys = pts.map(function (p) { return p.y; });
      var x0 = Math.min.apply(null, xs), y0 = Math.min.apply(null, ys);
      c.ctx.fillStyle = "#808080";
      c.ctx.fillRect(x0 - 12, y0 - 12, Math.max.apply(null, xs) - x0 + 24, Math.max.apply(null, ys) - y0 + 24);
    }
    return out;
  }

  function scanCanvas(c, limit) {
    var d = detector();
    if (!d) return Promise.resolve(jsqrAll(c, limit));
    return d.detect(c.canvas).then(function (found) {
      var codes = found.map(function (x) { return x.rawValue; });
      return codes.some(isCode) ? codes : jsqrAll(c, limit);
    }, function () { return jsqrAll(c, limit); });
  }

  function scanImageFile(file) {
    return new Promise(function (resolve, reject) {
      var url = URL.createObjectURL(file);
      var img = new Image();
      img.onload = function () {
        URL.revokeObjectURL(url);
        resolve(scanCanvas(draw(img, img.naturalWidth, img.naturalHeight, MAX_SIDE), MAX_CODES_PER_IMAGE));
      };
      img.onerror = function () { URL.revokeObjectURL(url); reject(new Error("unreadable")); };
      img.src = url;
    });
  }

  function readFiles(f, files) {
    files = Array.prototype.slice.call(files || []);
    if (!files.length) return;
    setStatus(f, "Reading " + (files.length === 1 ? (files[0].name || "the picture") : files.length + " files") + "…", "");
    var added = 0, empty = [];
    files.reduce(function (chain, file) {
      return chain.then(function () {
        var read = /^image\//.test(file.type) ? scanImageFile(file) : file.text().then(function (t) { return t.split(/\r?\n/); });
        return read.then(function (codes) {
          var n = addCodes(f, codes);
          added += n;
          if (!codes.some(isCode)) empty.push(file.name || "the pasted picture");
        }, function () { empty.push(file.name || "the pasted picture"); });
      });
    }, Promise.resolve()).then(function () {
      progress(f, added, added ? "" : empty.join(", "));
    });
  }

  /* ── Webcam ──────────────────────────────────────────────────── */

  var cam = null; // { stream, timer, form }

  function cameraAllowed() {
    return !!(window.isSecureContext && navigator.mediaDevices && navigator.mediaDevices.getUserMedia);
  }

  function startCamera(f) {
    if (cam) return;
    var video = q(f, "[data-piu-video]");
    setStatus(f, "Starting the webcam…", "");
    navigator.mediaDevices.getUserMedia({ audio: false, video: { facingMode: "environment", width: { ideal: 1280 }, height: { ideal: 720 } } })
      .then(function (stream) {
        cam = { stream: stream, form: f, timer: 0 };
        video.srcObject = stream;
        // A laptop's webcam faces you: mirror the view so it moves the way
        // you do. Only the picture is mirrored; the frames read are not.
        var facing = (stream.getVideoTracks()[0].getSettings() || {}).facingMode;
        video.classList.toggle("at-piu-mirror", facing !== "environment");
        q(f, "[data-piu-cam]").hidden = false;
        q(f, "[data-piu-cam-start]").hidden = true;
        q(f, "[data-piu-cam-stop]").hidden = false;
        setStatus(f, "Hold the code up to the webcam, about a hand's length away. On a phone, turn the brightness up.", "");
        return video.play().then(function () { loop(f, video); });
      })
      .catch(function (err) {
        stopCamera(f);
        var denied = err && (err.name === "NotAllowedError" || err.name === "SecurityError");
        setStatus(f, denied ? "The browser wasn't allowed to use the webcam. Allow it in the address bar, or drop a screenshot here instead."
          : "No webcam was found. Drop a screenshot here instead.", "warn");
      });
  }

  function loop(f, video) {
    if (!cam || cam.form !== f) return;
    var busy = video.videoWidth
      ? scanCanvas(draw(video, video.videoWidth, video.videoHeight, CAM_SIDE), 4)
      : Promise.resolve([]);
    busy.then(function (codes) {
      if (!cam || cam.form !== f) return;
      var added = addCodes(f, codes);
      if (added) progress(f, added, "");
      if (cam) cam.timer = setTimeout(function () { loop(f, video); }, SCAN_EVERY_MS);
    });
  }

  function stopCamera(f) {
    if (cam) {
      clearTimeout(cam.timer);
      cam.stream.getTracks().forEach(function (t) { t.stop(); });
      cam = null;
    }
    if (!f) return;
    var video = q(f, "[data-piu-video]");
    if (video) video.srcObject = null;
    var box = q(f, "[data-piu-cam]");
    if (box) box.hidden = true;
    var start = q(f, "[data-piu-cam-start]");
    if (start) start.hidden = !cameraAllowed();
    var stop = q(f, "[data-piu-cam-stop]");
    if (stop) stop.hidden = true;
  }

  /* ── Wiring ──────────────────────────────────────────────────── */

  function prepare() {
    var f = form();
    if (!f || f.dataset.piuReady) return;
    f.dataset.piuReady = "1";
    var start = q(f, "[data-piu-cam-start]");
    if (start) start.hidden = !cameraAllowed();
  }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", prepare);
  else prepare();
  document.addEventListener("htmx:afterSettle", prepare);
  // Leaving the page turns the webcam off.
  document.addEventListener("htmx:beforeSwap", function () { stopCamera(form()); });
  window.addEventListener("pagehide", function () { stopCamera(null); });

  document.addEventListener("click", function (e) {
    var f = form();
    if (e.target.closest("[data-piu-cam-start]")) { startCamera(f); return; }
    if (e.target.closest("[data-piu-cam-stop]")) {
      stopCamera(f);
      setStatus(f, "Webcam off.", "");
      return;
    }
    var btn = e.target.closest("[data-piu-copy]");
    if (!btn) return;
    var area = document.getElementById(btn.getAttribute("data-piu-copy"));
    if (!area) return;
    var done = function () { btn.textContent = "Copied"; setTimeout(function () { btn.textContent = "Copy the code text"; }, 1800); };
    if (navigator.clipboard && navigator.clipboard.writeText) navigator.clipboard.writeText(area.value).then(done, function () { area.select(); });
    else area.select();
  });

  document.addEventListener("change", function (e) {
    var input = e.target.closest("[data-piu-files]");
    if (!input) return;
    readFiles(input.closest("[data-piu-restore]"), input.files);
    input.value = "";
  });

  document.addEventListener("input", function (e) {
    var area = e.target.closest("[data-piu-codes]");
    if (area) progress(area.closest("[data-piu-restore]"), 1, "");
  });

  // Win+Shift+S puts the screenshot on the clipboard: paste it anywhere on
  // the page, no saving needed.
  document.addEventListener("paste", function (e) {
    var f = form();
    if (!f || !e.clipboardData) return;
    var files = [];
    Array.prototype.forEach.call(e.clipboardData.items || [], function (item) {
      if (item.kind === "file") { var file = item.getAsFile(); if (file) files.push(file); }
    });
    if (files.length) { e.preventDefault(); readFiles(f, files); return; }
    if (e.target.closest && e.target.closest("[data-piu-codes]")) return; // typing in the box itself
    var text = e.clipboardData.getData("text") || "";
    if (text.indexOf("PIU1*") >= 0) {
      e.preventDefault();
      progress(f, addCodes(f, text.split(/\r?\n/)), "the pasted text");
    }
  });

  document.addEventListener("dragover", function (e) {
    var drop = e.target.closest && e.target.closest("[data-piu-drop]");
    if (!drop) return;
    e.preventDefault();
    drop.classList.add("at-piu-over");
  });
  document.addEventListener("dragleave", function (e) {
    var drop = e.target.closest && e.target.closest("[data-piu-drop]");
    if (drop && !drop.contains(e.relatedTarget)) drop.classList.remove("at-piu-over");
  });
  document.addEventListener("drop", function (e) {
    var drop = e.target.closest && e.target.closest("[data-piu-drop]");
    if (!drop) return;
    e.preventDefault();
    drop.classList.remove("at-piu-over");
    readFiles(drop.closest("[data-piu-restore]"), e.dataTransfer && e.dataTransfer.files);
  });
})();
