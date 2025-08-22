const { Proxy } = require("http-mitm-proxy");
const axios = require("axios");
const DNS2 = require("dns2");
const { Client } = require("ssh2");
const http = require("http");
const forge = require("node-forge");

// Configuration
const freeHosts = ["hccp.com", "freehost2.com", "freehost3.com"];
const userAgents = [
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Safari/605.1.15",
  "Mozilla/5.0 (Android 13; Mobile; rv:109.0) Gecko/109.0 Firefox/109.0",
];
const proxy = new Proxy();
const dns = new DNS2({ upstream: [{ address: "1.1.1.1", type: "HTTPS" }] });
const dnsCache = new Map();
const redirectMap = new Map();
const cookieMap = new Map(); // Track session cookies per client
const maxRedirects = 5;

// Generate SSL Certificate
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

// iOS Configuration Profile
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

// SSH Configuration (sshOcean)
const sshConfig = {
  host: "fi358.sshocean.site",
  port: 443,
  username: "sshocean-reiker",
  password: process.env.SSH_PASSWORD || "reiker",
  algorithms: {
    cipher: ["aes256-ctr", "aes256-gcm@openssh.com", "chacha20-poly1305@openssh.com"],
    kex: ["curve25519-sha256", "ecdh-sha2-nistp256"],
    hmac: ["hmac-sha2-256", "hmac-sha2-512"],
    serverHostKey: ["ecdsa-sha2-nistp256", "rsa-sha2-512"],
  },
};

// SSL/TLS for Proxy
proxy.onCertificateRequired = (hostname, callback) => {
  return callback(null, { key: keyPem, cert: certPem });
};

proxy.onError((ctx, err) => {});

// Generate Session Cookie
const generateSessionCookie = () => {
  return `session_id=${forge.util.bytesToHex(forge.random.getBytesSync(16))}; Path=/; Domain=hccp.com; HttpOnly`;
};

// Proxy Request Handling
proxy.onRequest((ctx, callback) => {
  const auth = ctx.clientToProxyRequest.headers["proxy-authorization"];
  if (!auth || auth !== "Basic " + Buffer.from("username:password").toString("base64")) {
    ctx.proxyToClientResponse.writeHead(407, { "Proxy-Authenticate": "Basic" });
    ctx.endWithMessage("Proxy authentication required");
    return;
  }

  const clientIp = ctx.clientToProxyRequest.socket.remoteAddress;
  const originalHost = ctx.clientToProxyRequest.headers["host"];
  const randomHost = freeHosts[Math.floor(Math.random() * freeHosts.length)];

  // Set or get session cookie
  const sessionKey = `${clientIp}:${originalHost}`;
  if (!cookieMap.has(sessionKey)) {
    cookieMap.set(sessionKey, generateSessionCookie());
  }
  const sessionCookie = cookieMap.get(sessionKey);

  // Mimic HA Tunnel headers
  ctx.clientToProxyRequest.headers["Host"] = randomHost;
  ctx.clientToProxyRequest.headers["X-Online-Host"] = randomHost;
  ctx.clientToProxyRequest.headers["Connection"] = "keep-alive";
  ctx.clientToProxyRequest.headers["User-Agent"] =
    userAgents[Math.floor(Math.random() * userAgents.length)];
  ctx.clientToProxyRequest.headers["X-Forwarded-For"] = `192.168.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`;
  ctx.clientToProxyRequest.headers["Referer"] = `https://${randomHost}/`;
  ctx.clientToProxyRequest.headers["Accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8";
  ctx.clientToProxyRequest.headers["Accept-Language"] = "en-US,en;q=0.5";
  ctx.clientToProxyRequest.headers["Cookie"] = sessionCookie;

  // DNS over HTTPS with caching
  if (dnsCache.has(originalHost)) {
    if (Math.random() < 0.95) {
      ctx.clientToProxyRequest.headers["host"] = randomHost;
      ctx.clientToProxyRequest.headers["X-Online-Host"] = randomHost;
    }
    return callback();
  }

  dns
    .resolveA(originalHost)
    .then((result) => {
      if (result.answers[0]?.address) {
        dnsCache.set(originalHost, result.answers[0].address);
      }
      if (Math.random() < 0.95) {
        ctx.clientToProxyRequest.headers["host"] = randomHost;
        ctx.clientToProxyRequest.headers["X-Online-Host"] = randomHost;
      }
      return callback();
    })
    .catch((err) => {
      return callback();
    });

  setTimeout(() => {}, Math.random() * 50);
});

// Handle Redirects
proxy.onResponse(async (ctx, callback) => {
  const clientIp = ctx.clientToProxyRequest.socket.remoteAddress;
  const originalUrl = ctx.clientToProxyRequest.url;
  const sessionKey = `${clientIp}:${originalUrl}`;
  let redirectCount = redirectMap.get(sessionKey) || 0;

  if (ctx.serverToProxyResponse.statusCode === 302 && redirectCount < maxRedirects) {
    redirectMap.set(sessionKey, redirectCount + 1);
    const redirectUrl = ctx.serverToProxyResponse.headers["location"] || originalUrl;
    const isHccpRedirect = redirectUrl.includes("hccp.com");
    const targetUrl = isHccpRedirect ? originalUrl : redirectUrl;

    try {
      const response = await axios.get(targetUrl, {
        headers: {
          "User-Agent": userAgents[Math.floor(Math.random() * userAgents.length)],
          "Host": freeHosts[Math.floor(Math.random() * freeHosts.length)],
          "X-Online-Host": freeHosts[Math.floor(Math.random() * freeHosts.length)],
          "Connection": "keep-alive",
          "Referer": `https://${freeHosts[Math.floor(Math.random() * freeHosts.length)]}/`,
          "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
          "Accept-Language": "en-US,en;q=0.5",
          "Cookie": cookieMap.get(sessionKey),
        },
        maxRedirects: 0,
        validateStatus: (status) => status < 400,
        timeout: 5000,
      });

      ctx.serverToProxyResponse.statusCode = 200;
      ctx.serverToProxyResponse.statusMessage = "OK";
      ctx.serverToProxyResponse.headers["content-type"] = response.headers["content-type"] || "text/html";
      ctx.proxyToClientResponse.write(response.data);
      redirectMap.set(sessionKey, 0); // Reset on success
    } catch (err) {
      ctx.serverToProxyResponse.statusCode = 200;
      ctx.serverToProxyResponse.statusMessage = "OK";
      ctx.proxyToClientResponse.write("OK");
    }
  } else if (ctx.serverToProxyResponse.statusCode === 403 || redirectCount >= maxRedirects) {
    redirectMap.set(sessionKey, 0); // Reset redirect counter
    cookieMap.set(sessionKey, generateSessionCookie()); // Clear and regenerate cookie
    ctx.clientToProxyRequest.headers = {
      "Host": freeHosts[Math.floor(Math.random() * freeHosts.length)],
      "X-Online-Host": freeHosts[Math.floor(Math.random() * freeHosts.length)],
      "Connection": "keep-alive",
      "User-Agent": userAgents[Math.floor(Math.random() * userAgents.length)],
      "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
      "Accept-Language": "en-US,en;q=0.5",
      "Cookie": cookieMap.get(sessionKey),
    };
    ctx.serverToProxyResponse.statusCode = 200;
    ctx.serverToProxyResponse.statusMessage = "OK";
    ctx.proxyToClientResponse.write("Access granted");
  }

  return callback();
});

// Serve Proxy and iOS Profile
const server = http.createServer((req, res) => {
  if (req.url === "/profile") {
    res.writeHead(200, {
      "Content-Type": "application/x-apple-aspen-config",
      "Content-Disposition": 'attachment; filename="proxy.mobileconfig"',
    });
    res.end(mobileconfig);
  } else {
    res.writeHead(404);
    res.end("Not found");
  }
});

// SSH Tunnel Setup
const ssh = new Client();
ssh
  .on("ready", () => {
    ssh.forwardOut("127.0.0.1", 8080, "127.0.0.1", 8080, (err, stream) => {
      if (err) {
        return;
      }
      proxy.listen({ port: 8080 }, () => {
        server.listen(process.env.PORT || 8080);
      });
    });
  })
  .on("error", () => {
    ssh.connect({ ...sshConfig, port: 22 });
  })
  .connect(sshConfig);

// Check IP
(async () => {
  try {
    const res = await axios.get("https://api.ipify.org?format=json");
  } catch (err) {}
})();
