/* The Backup page's restore: reads Pack It Up codes out of screenshots
   (or a saved backup file) in the browser, and puts their text in the
   form. The server only ever sees the decoded text. Delegated, so it
   works however often a boosted navigation brings the page back. */
(function () {
  "use strict";
  if (window.atPackItUp) return;
  window.atPackItUp = true;

  var MAX_SIDE = 2000; // big enough for a phone screenshot's modules
  var MAX_CODES_PER_IMAGE = 12;

  function isCode(text) { return typeof text === "string" && text.indexOf("PIU1*") === 0; }

  function loadImage(file) {
    return new Promise(function (resolve, reject) {
      var url = URL.createObjectURL(file);
      var img = new Image();
      img.onload = function () { URL.revokeObjectURL(url); resolve(img); };
      img.onerror = function () { URL.revokeObjectURL(url); reject(new Error("unreadable image")); };
      img.src = url;
    });
  }

  function canvasFor(img) {
    var scale = Math.min(1, MAX_SIDE / Math.max(img.naturalWidth, img.naturalHeight));
    var c = document.createElement("canvas");
    c.width = Math.max(1, Math.round(img.naturalWidth * scale));
    c.height = Math.max(1, Math.round(img.naturalHeight * scale));
    var ctx = c.getContext("2d", { willReadFrequently: true });
    ctx.drawImage(img, 0, 0, c.width, c.height);
    return { canvas: c, ctx: ctx };
  }

  // The browser's own reader finds every code in a picture at once.
  function nativeScan(canvas) {
    if (!("BarcodeDetector" in window)) return Promise.resolve(null);
    var detector;
    try { detector = new window.BarcodeDetector({ formats: ["qr_code"] }); } catch (e) { return Promise.resolve(null); }
    return detector.detect(canvas).then(function (found) {
      return found.map(function (f) { return f.rawValue; });
    }, function () { return null; });
  }

  // jsQR reads one code per call: read one, paint over it, look again.
  function jsqrScan(c) {
    if (typeof window.jsQR !== "function") return [];
    var out = [];
    for (var i = 0; i < MAX_CODES_PER_IMAGE; i++) {
      var data = c.ctx.getImageData(0, 0, c.canvas.width, c.canvas.height);
      var hit = window.jsQR(data.data, data.width, data.height, { inversionAttempts: "dontInvert" });
      if (!hit) break;
      out.push(hit.data);
      var l = hit.location, pts = [l.topLeftCorner, l.topRightCorner, l.bottomRightCorner, l.bottomLeftCorner];
      var xs = pts.map(function (p) { return p.x; }), ys = pts.map(function (p) { return p.y; });
      var pad = 12;
      c.ctx.fillStyle = "#808080";
      c.ctx.fillRect(Math.min.apply(null, xs) - pad, Math.min.apply(null, ys) - pad,
        Math.max.apply(null, xs) - Math.min.apply(null, xs) + 2 * pad,
        Math.max.apply(null, ys) - Math.min.apply(null, ys) + 2 * pad);
    }
    return out;
  }

  function scanImage(file) {
    return loadImage(file).then(function (img) {
      var c = canvasFor(img);
      return nativeScan(c.canvas).then(function (found) {
        if (found && found.some(isCode)) return found;
        return jsqrScan(c);
      });
    });
  }

  function readText(file) {
    return file.text().then(function (t) { return t.split(/\r?\n/); });
  }

  function addCodes(area, codes) {
    var have = area.value.split(/\r?\n/).map(function (s) { return s.trim(); }).filter(Boolean);
    var added = 0;
    codes.forEach(function (raw) {
      var code = String(raw).trim();
      if (isCode(code) && have.indexOf(code) < 0) { have.push(code); added++; }
    });
    area.value = have.join("\n");
    return added;
  }

  document.addEventListener("change", function (e) {
    var input = e.target.closest("[data-piu-files]");
    if (!input) return;
    var form = input.closest("[data-piu-restore]");
    var area = form.querySelector("[data-piu-codes]");
    var status = form.querySelector("[data-piu-status]");
    var files = Array.prototype.slice.call(input.files || []);
    if (!files.length) return;
    status.textContent = "Reading " + files.length + (files.length === 1 ? " file…" : " files…");

    var total = 0, empty = [];
    files.reduce(function (chain, file) {
      return chain.then(function () {
        var isImage = /^image\//.test(file.type);
        return (isImage ? scanImage(file) : readText(file)).then(function (codes) {
          var n = addCodes(area, codes);
          total += n;
          if (!codes.some(isCode)) empty.push(file.name);
        }, function () { empty.push(file.name); });
      });
    }, Promise.resolve()).then(function () {
      var msg = total === 0 ? "No backup codes found." :
        "Found " + total + (total === 1 ? " code." : " codes.");
      if (empty.length && total > 0) msg += " Nothing readable in " + empty.join(", ") + ".";
      if (total === 0) msg += " Use a screenshot where the whole code is visible and sharp.";
      status.textContent = msg;
      input.value = "";
    });
  });

  document.addEventListener("click", function (e) {
    var btn = e.target.closest("[data-piu-copy]");
    if (!btn) return;
    var area = document.getElementById(btn.getAttribute("data-piu-copy"));
    if (!area) return;
    var done = function () { btn.textContent = "Copied"; setTimeout(function () { btn.textContent = "Copy the code text"; }, 1800); };
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(area.value).then(done, function () { area.select(); });
    } else {
      area.select();
    }
  });
})();
