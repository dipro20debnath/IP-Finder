/* IP Finder web dashboard. Talks only to the server that served it; every value
   from the network is inserted as text, except the report sections, which the
   server builds with the HTML report's code and escapes there. */
(function () {
  "use strict";
  var TOKEN_KEY = "ipfinder-token";
  var $ = function (id) { return document.getElementById(id); };
  var token = null, info = null, world = null, controller = null, lastRun = null;

  // ------------------------------------------------------------------ helpers

  function setStatus(message, bad) {
    $("status").textContent = message || "";
    $("status").className = bad ? "bad" : "";
  }

  function detailText(detail) {
    if (Array.isArray(detail)) {  // FastAPI's validation errors
      return detail.map(function (d) { return d.msg; }).join("; ");
    }
    return detail ? String(detail) : "";
  }

  function readToken() {
    var match = /(?:^#|&)token=([^&]+)/.exec(location.hash);
    if (match) {
      token = decodeURIComponent(match[1]);
      try { sessionStorage.setItem(TOKEN_KEY, token); } catch (e) { /* private mode */ }
      // Keep the token out of the address bar, bookmarks and screenshots.
      history.replaceState(null, "", location.pathname + location.search);
    } else {
      try { token = sessionStorage.getItem(TOKEN_KEY); } catch (e) { token = null; }
    }
  }

  function TokenError() { this.name = "TokenError"; }

  function api(path, options) {
    options = options || {};
    options.headers = Object.assign({ "Authorization": "Bearer " + token }, options.headers);
    options.credentials = "omit";
    options.cache = "no-store";
    return fetch(path, options).then(function (response) {
      if (response.status === 401) {
        showTokenPanel("The token was refused. 'ipfinder serve' prints a new link each time it starts.");
        throw new TokenError();
      }
      if (!response.ok) {
        return response.json().then(function (body) {
          throw new Error(detailText(body.detail) || response.statusText);
        }, function () {
          throw new Error(response.status + " " + response.statusText);
        });
      }
      return response;
    });
  }

  function showTokenPanel(reason) {
    try { sessionStorage.removeItem(TOKEN_KEY); } catch (e) { /* ignore */ }
    if (reason) { $("token-reason").textContent = reason; }
    $("token-panel").hidden = false;
    $("lookup-panel").hidden = true;
  }

  function busy(on) {
    $("go").disabled = on || !world;
    $("me").disabled = on || !world;
    $("stop").hidden = !on;
    $("progress").hidden = !on;
  }

  // ------------------------------------------------------------------ start-up

  function start() {
    $("token-panel").hidden = true;
    api("/api/info").then(function (r) { return r.json(); }).then(function (data) {
      info = data;
      $("version").textContent = "Web dashboard, IP Finder " + data.version +
        (data.offline ? " - offline mode: only local sources, nothing leaves this computer" : "");
      $("me").hidden = data.offline;  // finding the public IP needs ip-api
      $("disclaimer").textContent = data.disclaimer;
      $("max-inputs").textContent = data.max_inputs;
      $("profile").value = data.default_profile;
      $("phrase").textContent = data.confirmation;
      $("active-warning").textContent = data.active_warning + " At most " +
        data.active_limit + " addresses per lookup; public addresses only.";
      $("active-off").hidden = data.active_allowed;
      $("active-on").hidden = !data.active_allowed;
      $("lookup-panel").hidden = false;
      $("addresses").focus();
      loadSources();
      return fetch("/static/world-110m.json").then(function (r) { return r.json(); });
    }).then(function (data) {
      world = data;
      busy(false);
    }).catch(function (error) {
      if (!(error instanceof TokenError)) { setStatus(error.message, true); }
    });
  }

  function loadSources() {
    api("/api/sources").then(function (r) { return r.json(); }).then(function (rows) {
      var body = $("source-rows");
      body.textContent = "";
      rows.forEach(function (row) {
        var tr = document.createElement("tr");
        [row.name, row.layer, row.profiles.join(", "), row.status, row.needs].forEach(function (value, i) {
          var td = document.createElement("td");
          td.textContent = value;
          if (i === 3) { td.className = row.ready ? "good" : "mid"; }
          tr.appendChild(td);
        });
        body.appendChild(tr);
      });
    }).catch(function () { /* the panel just stays empty */ });
  }

  // ------------------------------------------------------------------ lookups

  function clearResults() {
    $("results").textContent = "";
    $("error-rows").textContent = "";
    $("errors").hidden = true;
    $("exports").hidden = true;
    lastRun = null;
  }

  function addSection(event) {
    var template = document.createElement("template");
    template.innerHTML = event.html;  // built and escaped by the server (html_report.section)
    $("results").appendChild(template.content);
    if (event.map) { IPFinderMap.draw(event.map, world); }
  }

  function addError(event) {
    var tr = document.createElement("tr");
    [event.input, event.error + (event.hint ? " - " + event.hint : "")].forEach(function (value) {
      var td = document.createElement("td");
      td.textContent = value;
      tr.appendChild(td);
    });
    $("error-rows").appendChild(tr);
    $("errors").hidden = false;
  }

  function handle(event) {
    var bar = $("progress");
    if (event.event === "start") {
      bar.max = event.total;
      bar.value = 0;
    } else if (event.event === "progress") {
      bar.value = event.done;
      setStatus(event.done + " of " + event.total + " done" +
        (event.input ? "; looking up " + event.input : ""));
    } else if (event.event === "report") {
      addSection(event);
    } else if (event.event === "error") {
      addError(event);
    } else if (event.event === "done") {
      lastRun = event.run;
      $("exports").hidden = false;
      setStatus("Done: " + event.reports + " address(es) in " + event.seconds + " s" +
        (event.errors ? ", " + event.errors + " input(s) were not IP addresses" : "") + "." +
        (event.cache_warning ? " " + event.cache_warning : ""));
    } else if (event.event === "fatal") {
      setStatus(event.error, true);
    }
  }

  function readStream(response) {  // one JSON event per line, as they happen
    var reader = response.body.getReader();
    var decoder = new TextDecoder();
    var buffer = "";
    function pump() {
      return reader.read().then(function (chunk) {
        if (chunk.done) {
          if (buffer.trim()) { handle(JSON.parse(buffer)); }
          return;
        }
        buffer += decoder.decode(chunk.value, { stream: true });
        var lines = buffer.split("\n");
        buffer = lines.pop();
        lines.forEach(function (line) { if (line.trim()) { handle(JSON.parse(line)); } });
        return pump();
      });
    }
    return pump();
  }

  function lookup(text) {
    if (controller || !world) { return; }
    var active = !$("active-on").hidden && $("active").checked;
    var body = {
      text: text,
      profile: $("profile").value,
      verbose: $("verbose").checked,
      active: active,
      confirmation: active ? $("confirmation").value : ""
    };
    clearResults();
    setStatus("Starting…");
    controller = new AbortController();
    busy(true);
    api("/api/lookup", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
      signal: controller.signal
    }).then(readStream).catch(function (error) {
      if (error.name === "AbortError") {
        setStatus("Stopped. Lookups already sent may still finish in the background.");
      } else if (!(error instanceof TokenError)) {
        setStatus(error.message, true);
      }
    }).then(function () {
      controller = null;
      busy(false);
    });
  }

  function download(format) {
    if (!lastRun) { return; }
    api("/api/export/" + encodeURIComponent(lastRun) + "?format=" + format).then(function (response) {
      var match = /filename="([^"]+)"/.exec(response.headers.get("Content-Disposition") || "");
      return response.blob().then(function (blob) {
        var link = document.createElement("a");
        link.href = URL.createObjectURL(blob);
        link.download = match ? match[1] : "ipfinder." + format;
        document.body.appendChild(link);
        link.click();
        link.remove();
        setTimeout(function () { URL.revokeObjectURL(link.href); }, 10000);
      });
    }).catch(function (error) {
      if (!(error instanceof TokenError)) { setStatus(error.message, true); }
    });
  }

  // ------------------------------------------------------------------ events

  $("token-form").addEventListener("submit", function (e) {
    e.preventDefault();
    token = $("token-input").value.trim().replace(/^.*#token=/, "");
    if (!token) { return; }
    try { sessionStorage.setItem(TOKEN_KEY, token); } catch (err) { /* ignore */ }
    start();
  });

  $("lookup-form").addEventListener("submit", function (e) {
    e.preventDefault();
    lookup($("addresses").value);
  });

  $("addresses").addEventListener("keydown", function (e) {
    if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) {
      e.preventDefault();
      lookup($("addresses").value);
    }
  });

  $("me").addEventListener("click", function () {
    setStatus("Asking ip-api for this computer's public IP…");
    api("/api/me").then(function (r) { return r.json(); }).then(function (data) {
      $("addresses").value = data.ip;
      lookup(data.ip);
    }).catch(function (error) {
      if (!(error instanceof TokenError)) { setStatus(error.message, true); }
    });
  });

  $("stop").addEventListener("click", function () {
    if (controller) { controller.abort(); }
  });

  $("active").addEventListener("change", function () {
    $("confirmation").disabled = !this.checked;
    if (this.checked) { $("confirmation").focus(); }
  });

  $("file").addEventListener("change", function () {
    var file = this.files[0];
    this.value = "";
    if (!file) { return; }
    if (file.size > 200 * 1024) {
      setStatus(file.name + " is larger than 200 KB; use 'ipfinder batch' for big files.", true);
      return;
    }
    // readAsText honours a byte-order mark, so UTF-16 files from Windows
    // PowerShell load as well as UTF-8 ones (Blob.text() would assume UTF-8).
    var reader = new FileReader();
    reader.onload = function () {
      var text = String(reader.result).replace(/^﻿/, "");
      $("addresses").value = text;
      var count = text.split(/\r?\n/).filter(function (line) {
        return line.split("#")[0].trim();
      }).length;
      setStatus("Loaded " + count + " address line(s) from " + file.name + ".");
    };
    reader.onerror = function () { setStatus("Could not read " + file.name + ".", true); };
    reader.readAsText(file);
  });

  Array.prototype.forEach.call(document.querySelectorAll("#exports button"), function (button) {
    button.addEventListener("click", function () { download(button.dataset.format); });
  });

  readToken();
  if (token) { start(); } else { showTokenPanel(); }
})();
