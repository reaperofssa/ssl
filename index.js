// ==========================
// Advanced HTTP Injector Proxy
// ==========================
//
// Dependencies:
//   npm install http-mitm-proxy axios chalk
//
// Run:
//   node proxy.js
//
// Then set your device HTTP Proxy:
//   Server = <your-server-ip>
//   Port   = 8080
//
// ==========================

const { Proxy } = require("http-mitm-proxy");
const axios = require("axios");
const chalk = require("chalk");

// ==========================
// CONFIG SECTION
// ==========================

// ISP free hosts used to disguise requests
const FREE_HOSTS = [
  "hccp.com",
  "freehost2.com",
  "zero.example.net",
  "portal.isp.com",
  "cdn-free.net"
];

// Rotate through fake user-agents
const USER_AGENTS = [
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/117 Safari/537.36",
  "Mozilla/5.0 (Android 13; Mobile; rv:109.0) Gecko/109.0 Firefox/109.0",
  "Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X) AppleWebKit/605.1.15",
  "Mozilla/5.0 (Linux; Android 11; Pixel 4) AppleWebKit/537.36 Chrome/114 Mobile Safari/537.36",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_2) AppleWebKit/605.1.15"
];

// Number of disguised requests before letting real host pass
const DISGUISE_LIMIT = 5;

// Ports to listen on
const PORT = 8080;

// ==========================
// STATE MANAGEMENT
// ==========================

// Track per-client state (IP → session info)
const sessionMap = new Map();

function getSession(clientIp) {
  if (!sessionMap.has(clientIp)) {
    sessionMap.set(clientIp, {
      count: 0,
      lastHost: null
    });
  }
  return sessionMap.get(clientIp);
}

// ==========================
// PROXY INITIALIZATION
// ==========================
const proxy = new Proxy();

// Error handler
proxy.onError((ctx, err) => {
  console.error(chalk.red("[PROXY ERROR]"), err.message);
});

// ==========================
// REQUEST HANDLER
// ==========================
proxy.onRequest((ctx, callback) => {
  const clientIp = ctx.clientToProxyRequest.socket.remoteAddress;
  const session = getSession(clientIp);

  session.count++;
  let disguise = false;

  // disguise first N requests OR after ISP block reset
  if (session.count <= DISGUISE_LIMIT) {
    disguise = true;
  }

  // Pick random disguise host + UA
  const randomHost = FREE_HOSTS[Math.floor(Math.random() * FREE_HOSTS.length)];
  const randomUA = USER_AGENTS[Math.floor(Math.random() * USER_AGENTS.length)];

  if (disguise) {
    ctx.clientToProxyRequest.headers["Host"] = randomHost;
    ctx.clientToProxyRequest.headers["X-Online-Host"] = randomHost;
    ctx.clientToProxyRequest.headers["User-Agent"] = randomUA;
    ctx.clientToProxyRequest.headers["Connection"] = "keep-alive";
    ctx.clientToProxyRequest.headers["Upgrade-Insecure-Requests"] = "1";
    ctx.clientToProxyRequest.headers["Accept-Language"] =
      ctx.clientToProxyRequest.headers["accept-language"] || "en-US,en;q=0.9";

    console.log(
      chalk.green(
        `[+] [${clientIp}] Disguised request ${session.count}/${DISGUISE_LIMIT} as ${randomHost}`
      )
    );
  } else {
    console.log(
      chalk.yellow(
        `[>] [${clientIp}] Passing real host request (count=${session.count})`
      )
    );
  }

  return callback();
});

// ==========================
// RESPONSE HANDLER
// ==========================
proxy.onResponse((ctx, callback) => {
  const clientIp = ctx.clientToProxyRequest.socket.remoteAddress;
  const session = getSession(clientIp);

  // Neutralize ISP redirect or block
  if ([301, 302, 403].includes(ctx.serverToProxyResponse.statusCode)) {
    console.log(
      chalk.red(
        `[!] [${clientIp}] ISP redirect/block detected — forcing disguise reset`
      )
    );

    // Reset disguise counter
    session.count = 0;

    // Override response so client doesn’t break
    ctx.serverToProxyResponse.statusCode = 200;
    ctx.serverToProxyResponse.statusMessage = "OK";
    delete ctx.serverToProxyResponse.headers["location"];
    ctx.serverToProxyResponse.headers["connection"] = "keep-alive";
  }

  return callback();
});

// ==========================
// BOOTSTRAP
// ==========================
(async () => {
  try {
    const res = await axios.get("https://api.ipify.org?format=json");
    console.log(chalk.cyan("[+] Proxy server public IP:"), res.data.ip);
  } catch (err) {
    console.error(chalk.red("[ERR] Could not fetch IP:"), err.message);
  }

  proxy.listen({ port: PORT }, () => {
    console.log(chalk.blueBright("\n==============================="));
    console.log(chalk.blueBright("[+] Injector Proxy Running"));
    console.log(chalk.blueBright("[*] Port:"), PORT);
    console.log(
      chalk.blueBright("[*] Configure device HTTP proxy → <server-ip>:" + PORT)
    );
    console.log(
      chalk.blueBright("[*] Traffic will be disguised with hosts:"),
      FREE_HOSTS.join(", ")
    );
    console.log(chalk.blueBright("===============================\n"));
  });
})();
