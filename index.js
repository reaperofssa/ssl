// injector.js
// npm install http-mitm-proxy ssh2 dns2 node-forge axios

const { Proxy } = require("http-mitm-proxy");
const { Client } = require("ssh2");
const DNS2 = require("dns2");
const http = require("http");
const forge = require("node-forge");
const axios = require("axios");
const net = require("net");

// ========== CONFIG ==========
const FREE_HOSTS = ["mtn.ng", "engage2.mtn.ng", "engage1.mtn.ng"];
const USER_AGENTS = [
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Safari/605.1.15",
  "Mozilla/5.0 (Android 13; Mobile; rv:109.0) Gecko/109.0 Firefox/109.0",
];

const PROXY_PORT = 8080;   // HTTP(S) proxy port (for device)
const PROFILE_PORT = 3000; // HTTP server to serve mobileconfig (separate)
const DISGUISE_LIMIT = 5;  // mask first N requests per client before exposing real Host
const MAX_REDIRECTS = 5;

const sshConfig = {
  host: "fi358.sshocean.site",            // <-- change to your SSH host
  port: 443,                              // SSH port on provider (443 here)
  username: "sshocean-reiker",            // <-- change
  password: process.env.SSH_PASSWORD || "reiker", // prefer env var
  // optional algorithm preferences:
  algorithms: {
    cipher: ["aes256-ctr", "aes256-gcm@openssh.com", "chacha20-poly1305@openssh.com"],
    kex: ["curve25519-sha256", "ecdh-sha2-nistp256"],
    hmac: ["hmac-sha2-256", "hmac-sha2-512"],
    serverHostKey: ["ecdsa-sha2-nistp256", "rsa-sha2-512"],
  },
};
// ============================

// in-memory maps
const disguiseMap = new Map(); // clientIp -> count
const redirectMap = new Map(); // sessionKey -> count
const cookieMap = new Map();   // sessionKey -> cookie

// DNS over HTTPS (Cloudflare)
const dns = new DNS2({ upstream: [{ address: "1.1.1.1", type: "HTTPS" }] });
const dnsCache = new Map();

const proxy = new Proxy();

// ---------- generate CA cert (node-forge) ----------
const { pki } = forge;
const keys = pki.rsa.generateKeyPair(2048);
const cert = pki.createCertificate();
cert.publicKey = keys.publicKey;
cert.serialNumber = "01";
cert.validity.notBefore = new Date();
cert.validity.notAfter = new Date();
cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 1);
const attrs = [
  { name: "commonName", value: "ProxyCert" },
  { name: "organizationName", value: "Proxy" },
];
cert.setSubject(attrs);
cert.setIssuer(attrs);
cert.sign(keys.privateKey);
const certPem = pki.certificateToPem(cert);
const keyPem = pki.privateKeyToPem(keys.privateKey);

// iOS mobileconfig (simple distribution)
const mobileconfig = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>PayloadContent</key>
  <array>
    <dict>
      <key>PayloadCertificateFileName</key>
      <string>ProxyCert.crt</string>
      <key>PayloadContent</key>
      <data>${Buffer.from(certPem).toString("base64")}</data>
      <key>PayloadDescription</key>
      <string>Proxy SSL Certificate</string>
      <key>PayloadDisplayName</key>
      <string>Proxy Certificate</string>
      <key>PayloadIdentifier</key>
      <string>com.proxy.cert</string>
      <key>PayloadType</key>
      <string>com.apple.security.root</string>
      <key>PayloadUUID</key>
      <string>${forge.util.bytesToHex(forge.random.getBytesSync(16))}</string>
      <key>PayloadVersion</key>
      <integer>1</integer>
    </dict>
  </array>
  <key>PayloadDescription</key>
  <string>Installs Proxy SSL Certificate</string>
  <key>PayloadDisplayName</key>
  <string>Proxy Profile</string>
  <key>PayloadIdentifier</key>
  <string>com.proxy.profile</string>
  <key>PayloadType</key>
  <string>Configuration</string>
  <key>PayloadUUID</key>
  <string>${forge.util.bytesToHex(forge.random.getBytesSync(16))}</string>
  <key>PayloadVersion</key>
  <integer>1</integer>
</dict>
</plist>`;

// ---------- helper functions ----------
function genSessionCookie() {
  return `session_id=${forge.util.bytesToHex(forge.random.getBytesSync(16))}; Path=/; Domain=${FREE_HOSTS[0]}; HttpOnly`;
}
function clientKeyFor(ctx) {
  const ip = ctx.clientToProxyRequest.socket.remoteAddress || "unknown";
  const host = ctx.clientToProxyRequest.headers["host"] || "";
  return `${ip}:${host}`;
}
function isIspRedirect(location) {
  if (!location) return false;
  // Mark as ISP/captive redirect if it points to free host, private IPs, or common portal patterns
  const l = location.toLowerCase();
  return (
    FREE_HOSTS.some(h => l.includes(h)) ||
    l.startsWith("http://10.") ||
    l.startsWith("http://192.168.") ||
    l.includes("captiveportal") ||
    l.includes("landpage") ||
    l.includes("isp")
  );
}

// ---------- MITM TLS cert callback ----------
proxy.onCertificateRequired = (hostname, callback) => {
  // return the generated cert (simple demo)
  callback(null, { key: keyPem, cert: certPem });
};

// ---------- handle HTTP requests (non-CONNECT) ----------
proxy.onRequest((ctx, callback) => {
  try {
    const clientIp = ctx.clientToProxyRequest.socket.remoteAddress || "unknown";
    const originalHost = (ctx.clientToProxyRequest.headers["host"] || "").toLowerCase();
    const sessionKey = `${clientIp}:${originalHost}`;

    // ensure a session cookie exists
    if (!cookieMap.has(sessionKey)) cookieMap.set(sessionKey, genSessionCookie());
    const sessionCookie = cookieMap.get(sessionKey);

    // disguise logic: count per client ip (first N requests masked)
    let count = disguiseMap.get(clientIp) || 0;
    const shouldDisguise = count < DISGUISE_LIMIT && Math.random() < 0.98;

    if (shouldDisguise) {
      const rHost = FREE_HOSTS[Math.floor(Math.random() * FREE_HOSTS.length)];
      ctx.clientToProxyRequest.headers["host"] = rHost;
      ctx.clientToProxyRequest.headers["x-online-host"] = rHost;
      ctx.clientToProxyRequest.headers["user-agent"] = USER_AGENTS[Math.floor(Math.random() * USER_AGENTS.length)];
      ctx.clientToProxyRequest.headers["connection"] = "keep-alive";
      ctx.clientToProxyRequest.headers["referer"] = `https://${rHost}/`;
      ctx.clientToProxyRequest.headers["cookie"] = sessionCookie;
      disguiseMap.set(clientIp, count + 1);
      // console.log(`[DISGUISE] ${clientIp} -> ${rHost} (${count + 1}/${DISGUISE_LIMIT})`);
    } else {
      // pass real host (do not clobber)
      // console.log(`[PASS] ${clientIp} -> ${originalHost}`);
    }

    // DNS cache warm-up (non-blocking)
    if (!dnsCache.has(originalHost) && originalHost) {
      dns.resolveA(originalHost)
        .then((r) => {
          if (r && r.answers && r.answers[0] && r.answers[0].address) {
            dnsCache.set(originalHost, r.answers[0].address);
          }
        })
        .catch(() => {});
    }
  } catch (err) {
    // ignore and continue
  }

  return callback();
});

// ---------- handle responses (selective 302/403 handling) ----------
proxy.onResponse((ctx, callback) => {
  try {
    const clientIp = ctx.clientToProxyRequest.socket.remoteAddress || "unknown";
    const originalUrl = ctx.clientToProxyRequest.url || "";
    const sessionKey = `${clientIp}:${originalUrl}`;
    let redirectCount = redirectMap.get(sessionKey) || 0;

    const status = ctx.serverToProxyResponse.statusCode;
    const location = ctx.serverToProxyResponse.headers && ctx.serverToProxyResponse.headers["location"];

    if (status === 302 && isIspRedirect(location) && redirectCount < MAX_REDIRECTS) {
      // Treat as ISP trap: strip Location and convert to 200 OK
      redirectMap.set(sessionKey, redirectCount + 1);
      ctx.serverToProxyResponse.statusCode = 200;
      ctx.serverToProxyResponse.statusMessage = "OK";
      if (ctx.serverToProxyResponse.headers) delete ctx.serverToProxyResponse.headers["location"];
      // optionally write a tiny body if none will be forwarded downstream
      // but keep streaming in-place; http-mitm-proxy will continue to pipe server body (if any)
      // console.log(`[ISP REDIRECT] ${clientIp} -> stripped ${location}`);
    } else if (status === 403 || redirectCount >= MAX_REDIRECTS) {
      // full reset: regenerate cookie, reset counter and disguise next requests
      redirectMap.set(sessionKey, 0);
      const cookie = genSessionCookie();
      cookieMap.set(sessionKey, cookie);
      // mark client's disguise count to zero so next requests will be disguised
      const ip = clientIp;
      disguiseMap.set(ip, 0);
      ctx.serverToProxyResponse.statusCode = 200;
      ctx.serverToProxyResponse.statusMessage = "OK";
      if (ctx.serverToProxyResponse.headers) delete ctx.serverToProxyResponse.headers["location"];
      // write a tiny friendly body
      ctx.proxyToClientResponse.write("OK");
      // console.log(`[RESET] ${clientIp} - regenerated cookie & reset disguise`);
    }
  } catch (err) {
    // swallow
  }

  return callback();
});

// ---------- handle CONNECT (HTTPS tunnel) - forward through SSH when available ----------
let sshClient = new Client();
let sshReady = false;

function setupSSH() {
  sshClient.on("ready", () => {
    sshReady = true;
    console.log("[SSH] ready - injector can forward CONNECTs via SSH");
  });

  sshClient.on("error", (err) => {
    sshReady = false;
    console.error("[SSH] error:", err.message);
    // try reconnect after short delay
    setTimeout(() => {
      try { sshClient.connect(sshConfig); } catch (e) {}
    }, 5000);
  });

  sshClient.on("end", () => {
    sshReady = false;
    console.log("[SSH] connection ended");
  });

  sshClient.on("close", () => {
    sshReady = false;
    console.log("[SSH] connection closed - reconnecting...");
    setTimeout(() => {
      try { sshClient.connect(sshConfig); } catch (e) {}
    }, 3000);
  });

  // initiate connection
  try {
    sshClient.connect(sshConfig);
  } catch (e) {
    console.error("[SSH] connect failed:", e.message);
  }
}
setupSSH();

// http-mitm-proxy exposes onConnect for raw CONNECT handling
proxy.onConnect((req, clientSocket, head, callback) => {
  // req.url is like "target.host:443"
  const to = req.url.split(":");
  const targetHost = to[0];
  const targetPort = parseInt(to[1], 10) || 443;

  // If we have SSH, try forwarding via SSH (directTcpip)
  if (sshReady) {
    sshClient.forwardOut(
      // source address/port (arbitrary)
      "127.0.0.1",
      0,
      // target address/port (the real destination)
      targetHost,
      targetPort,
      (err, sshStream) => {
        if (err || !sshStream) {
          // fallback to direct TCP if SSH forward fails
          // console.log("[CONNECT] SSH forward failed, falling back to direct:", err && err.message);
          const serverSocket = net.connect(targetPort, targetHost, () => {
            clientSocket.write("HTTP/1.1 200 Connection Established\r\n\r\n");
            if (head && head.length) serverSocket.write(head);
            clientSocket.pipe(serverSocket);
            serverSocket.pipe(clientSocket);
          });
          serverSocket.on("error", () => clientSocket.destroy());
          return;
        }

        // success: reply connected then pipe sockets <-> sshStream
        clientSocket.write("HTTP/1.1 200 Connection Established\r\n\r\n");
        if (head && head.length) sshStream.write(head);
        clientSocket.pipe(sshStream).pipe(clientSocket);
      }
    );
  } else {
    // no SSH: fallback -> direct connect to target
    const serverSocket = net.connect(targetPort, targetHost, () => {
      clientSocket.write("HTTP/1.1 200 Connection Established\r\n\r\n");
      if (head && head.length) serverSocket.write(head);
      clientSocket.pipe(serverSocket);
      serverSocket.pipe(clientSocket);
    });
    serverSocket.on("error", () => clientSocket.destroy());
  }
});

// ---------- small HTTP server to serve mobileconfig ----------
const server = http.createServer((req, res) => {
  if (req.url === "/profile") {
    res.writeHead(200, {
      "Content-Type": "application/x-apple-aspen-config",
      "Content-Disposition": 'attachment; filename="proxy.mobileconfig"',
    });
    res.end(mobileconfig);
  } else if (req.url === "/cert") {
    // raw PEM download option
    res.writeHead(200, { "Content-Type": "application/x-pem-file" });
    res.end(certPem);
  } else {
    res.writeHead(404);
    res.end("Not found");
  }
});

// ---------- start servers ----------
proxy.listen({ port: PROXY_PORT }, () => {
  console.log(`[PROXY] HTTP(S) injector listening on :${PROXY_PORT}`);
  server.listen(PROFILE_PORT, () => {
    console.log(`[WEB] profile server listening on :${PROFILE_PORT}  (GET /profile to download mobileconfig)`);
  });
});

// ---------- optional: print public IP (ipify) ----------
(async () => {
  try {
    const r = await axios.get("https://api.ipify.org?format=json");
    console.log("[INFO] public IP:", r.data.ip);
  } catch (e) {}
})();
