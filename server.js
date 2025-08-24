const { Proxy } = require('http-mitm-proxy');
const axios = require('axios');
const proxy = new Proxy();

proxy.onRequest(async (ctx, callback) => {
  try {
    // Log target server IP + port
    const targetHost = ctx.proxyToServerRequestOptions.host;
    const targetPort = ctx.proxyToServerRequestOptions.port;
    console.log(`📡 Request to: ${targetHost}:${targetPort}`);

    // Fetch VPS public IP from ipify
    const ipRes = await axios.get("https://api.ipify.org?format=json");
    console.log(`🌍 VPS Public IP: ${ipRes.data.ip}`);

  } catch (err) {
    console.error("Error fetching VPS IP:", err.message);
  }

  return callback();
});

// Intercept and modify response
proxy.onResponse((ctx, callback) => {
  if (ctx.clientToProxyRequest.url.includes("targetsite.com")) {
    console.log("⚡ Intercepting response from targetsite.com");

    // Change 302 → 200
    if (ctx.serverToProxyResponse.statusCode === 302) {
      ctx.serverToProxyResponse.statusCode = 200;
      ctx.serverToProxyResponse.statusMessage = "OK";
    }

    // Replace body with fake HTML
    ctx.use(Proxy.gunzip);
    ctx.onResponseData((ctx, chunk, cb) => {
      const fakeHtml = `
        <html>
          <head><title>Injected Page</title></head>
          <body>
            <h1>Proxy Success</h1>
            <p>This content was injected by the VPS MITM proxy.</p>
          </body>
        </html>
      `;
      return cb(null, Buffer.from(fakeHtml));
    });
  }

  return callback();
});

proxy.listen({ port: 8080 }, () => {
  console.log("✅ MITM Proxy running on port 8080");
});
