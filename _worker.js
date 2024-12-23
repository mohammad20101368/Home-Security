// <!--GAMFC-->version base on commit 43fad05dcdae3b723c53c226f8181fc5bd47223e, time is 2023-06-22 15:20:02 UTC<!--GAMFC-END-->.
// @ts-ignore
import { connect } from "cloudflare:sockets";

// How to generate your own UUID:
// [Windows] Press "Win + R", input cmd and run:  Powershell -NoExit -Command "[guid]::NewGuid()"
let userID = "86c50e3a-5b87-49dd-bd20-03c7f2735e40";

const proxyIPs = ["ts.hpc.tw"]; //ts.hpc.tw edgetunnel.anycast.eu.org bestproxy.onecf.eu.org cdn-all.xn--b6gac.eu.org cdn.xn--b6gac.eu.org proxy.xxxxxxxx.tk
const cn_hostnames = [''];
let CDNIP = 'www.visa.com.sg'
// http_ip
let IP1 = 'www.visa.com'
let IP2 = 'cis.visa.com'
let IP3 = 'africa.visa.com'
let IP4 = 'www.visa.com.sg'
let IP5 = 'www.visaeurope.at'
let IP6 = 'www.visa.com.mt'
let IP7 = 'qa.visamiddleeast.com'
let IP8 = 'www.speedtest.net'
let IP9 = 'www.wto.org'
let IP10 = 'www.time.is'
let IP11 = 'www.ip.sb'
let IP12 = '104.21.64.1'
let IP13 = '104.21.48.1'
let IP14 = '104.21.96.1'
let IP15 = '104.21.16.1'
let IP16 = '104.21.32.1'
let IP17 = '104.21.80.1'
let IP18 = '104.21.112.1'
let IP19 = '[2606:4700:3030::6815:4001]'
let IP20 = '[2606:4700:3030::6815:7001]'
let IP21 = '[2606:4700:3030::6815:3001]'
let IP22 = '[2606:4700:3030::6815:5001]'
let IP23 = '[2606:4700:3030::6815:6001]'
let IP24 = '[2606:4700:3030::6815:2001]'
let IP25 = '[2606:4700:3030::6815:1001]'

// https_ip
let IP26 = 'www.visa.com'
let IP27 = 'cis.visa.com'
let IP28 = 'africa.visa.com'
let IP29 = 'www.visa.com.sg'
let IP30 = 'www.visaeurope.at'
let IP31 = 'www.visa.com.mt'
let IP32 = 'qa.visamiddleeast.com'
let IP33 = 'www.speedtest.net'
let IP34 = 'www.wto.org'
let IP35 = 'www.time.is'
let IP36 = 'www.ip.sb'
let IP37 = '104.21.64.1'
let IP38 = '104.21.48.1'
let IP39 = '104.21.96.1'
let IP40 = '104.21.16.1'
let IP41 = '104.21.32.1'
let IP42 = '104.21.80.1'
let IP43 = '104.21.112.1'
let IP44 = '[2606:4700:3030::6815:4001]'
let IP45 = '[2606:4700:3030::6815:7001]'
let IP46 = '[2606:4700:3030::6815:3001]'
let IP47 = '[2606:4700:3030::6815:5001]'
let IP48 = '[2606:4700:3030::6815:6001]'
let IP49 = '[2606:4700:3030::6815:2001]'
let IP50 = '[2606:4700:3030::6815:1001]'

// http_port
let PT1 = '80'
let PT2 = '80'
let PT3 = '80'
let PT4 = '80'
let PT5 = '80'
let PT6 = '2086'
let PT7 = '80'
let PT8 = '80'
let PT9 = '80'
let PT10 = '80'
let PT11 = '80'
let PT12 = '80'
let PT13 = '80'
let PT14 = '80'
let PT15 = '80'
let PT16 = '80'
let PT17 = '80'
let PT18 = '80'
let PT19 = '80'
let PT20 = '80'
let PT21 = '80'
let PT22 = '80'
let PT23 = '80'
let PT24 = '80'
let PT25 = '80'

// https_port
let PT26 = '443'
let PT27 = '8443'
let PT28 = '8443'
let PT29 = '8443'
let PT30 = '8443'
let PT31 = '8443'
let PT32 = '443'
let PT33 = '443'
let PT34 = '443'
let PT35 = '443'
let PT36 = '443'
let PT37 = '443'
let PT38 = '443'
let PT39 = '443'
let PT40 = '443'
let PT41 = '443'
let PT42 = '443'
let PT43 = '443'
let PT44 = '443'
let PT45 = '443'
let PT46 = '443'
let PT47 = '443'
let PT48 = '443'
let PT49 = '443'
let PT50 = '443'

let proxyIP = proxyIPs[Math.floor(Math.random() * proxyIPs.length)];
let proxyPort = proxyIP.includes(':') ? proxyIP.split(':')[1] : '443';

if (!isValidUUID(userID)) {
  throw new Error("uuid is not valid");
}

export default {
  /**
   * @param {import("@cloudflare/workers-types").Request} request
   * @param {uuid: string, proxyip: string, cdnip: string, ip1: string, ip2: string, ip3: string, ip4: string, ip5: string, ip6: string, ip7: string, ip8: string, ip9: string, ip10: string, ip11: string, ip12: string, ip13: string, ip14: string, ip15: string, ip16: string, ip17: string, ip18: string, ip19: string, ip20: string, ip21: string, ip22: string, ip23: string, ip24: string, ip25: string, ip26: string, ip27: string, ip28: string, ip29: string, ip30: string, ip31: string, ip32: string, ip33: string, ip34: string, ip35: string, ip36: string, ip37: string, ip38: string, ip39: string, ip40: string, ip41: string, ip42: string, ip43: string, ip44: string, ip45: string, ip46: string, ip47: string, ip48: string, ip49: string, ip50: string, pt1: string, pt2: string, pt3: string, pt4: string, pt5: string, pt6: string, pt7: string, pt8: string, pt9: string, pt10: string, pt11: string, pt12: string, pt13: string, pt14: string, pt15: string, pt16: string, pt17: string, pt18: string, pt19: string, pt20: string, pt21: string, pt22: string, pt23: string, pt24: string, pt25: string, pt26: string, pt27: string, pt28: string, pt29: string, pt30: string, pt31: string, pt32: string, pt33: string, pt34: string, pt35: string, pt36: string, pt37: string, pt38: string, pt39: string, pt40: string, pt41: string, pt42: string, pt43: string, pt44: string, pt45: string, pt46: string, pt47: string, pt48: string, pt49: string, pt50: string} env
   * @param {import("@cloudflare/workers-types").ExecutionContext} ctx
   * @returns {Promise<Response>}
   */
  async fetch(request, env, ctx) {
    try {
      const { proxyip } = env;
      userID = env.uuid || userID;
			if (proxyip) {
				if (proxyip.includes(']:')) {
					let lastColonIndex = proxyip.lastIndexOf(':');
					proxyPort = proxyip.slice(lastColonIndex + 1);
					proxyIP = proxyip.slice(0, lastColonIndex);
					
				} else if (!proxyip.includes(']:') && !proxyip.includes(']')) {
					[proxyIP, proxyPort = '443'] = proxyip.split(':');
				} else {
					proxyPort = '443';
					proxyIP = proxyip;
				}				
			} else {
				if (proxyIP.includes(']:')) {
					let lastColonIndex = proxyIP.lastIndexOf(':');
					proxyPort = proxyIP.slice(lastColonIndex + 1);
					proxyIP = proxyIP.slice(0, lastColonIndex);	
				} else if (!proxyIP.includes(']:') && !proxyIP.includes(']')) {
					[proxyIP, proxyPort = '443'] = proxyIP.split(':');
				} else {
					proxyPort = '443';
				}	
			}
			console.log('ProxyIP:', proxyIP);
			console.log('ProxyPort:', proxyPort);
      CDNIP = env.cdnip || CDNIP;
	  IP1 = env.ip1 || IP1;
	  IP2 = env.ip2 || IP2;
	  IP3 = env.ip3 || IP3;
	  IP4 = env.ip4 || IP4;
	  IP5 = env.ip5 || IP5;
	  IP6 = env.ip6 || IP6;
	  IP7 = env.ip7 || IP7;
	  IP8 = env.ip8 || IP8;
	  IP9 = env.ip9 || IP9;
	  IP10 = env.ip10 || IP10;
	  IP11 = env.ip11 || IP11;
	  IP12 = env.ip12 || IP12;
	  IP13 = env.ip13 || IP13;
	  IP14 = env.ip14 || IP14;
	  IP15 = env.ip15 || IP15;
	  IP16 = env.ip16 || IP16;
	  IP17 = env.ip17 || IP17;
	  IP18 = env.ip18 || IP18;
	  IP19 = env.ip19 || IP19;
	  IP20 = env.ip20 || IP20;
	  IP21 = env.ip21 || IP21;
	  IP22 = env.ip22 || IP22;
	  IP23 = env.ip23 || IP23;
	  IP24 = env.ip24 || IP24;
	  IP25 = env.ip25 || IP25;
	  IP26 = env.ip26 || IP26;
	  IP27 = env.ip27 || IP27;
	  IP28 = env.ip28 || IP28;
	  IP29 = env.ip29 || IP29;
	  IP30 = env.ip30 || IP30;
	  IP31 = env.ip31 || IP31;
	  IP32 = env.ip32 || IP32;
	  IP33 = env.ip33 || IP33;
	  IP34 = env.ip34 || IP34;
	  IP35 = env.ip35 || IP35;
	  IP36 = env.ip36 || IP36;
	  IP37 = env.ip37 || IP37;
	  IP38 = env.ip38 || IP38;
	  IP39 = env.ip39 || IP39;
	  IP40 = env.ip40 || IP40;
	  IP41 = env.ip41 || IP41;
	  IP42 = env.ip42 || IP42;
	  IP43 = env.ip43 || IP43;
	  IP44 = env.ip44 || IP44;
	  IP45 = env.ip45 || IP45;
	  IP46 = env.ip46 || IP46;
	  IP47 = env.ip47 || IP47;
	  IP48 = env.ip48 || IP48;
	  IP49 = env.ip49 || IP49;
	  IP50 = env.ip50 || IP50;	  
	  PT1 = env.pt1 || PT1;
	  PT2 = env.pt2 || PT2;
	  PT3 = env.pt3 || PT3;
	  PT4 = env.pt4 || PT4;
	  PT5 = env.pt5 || PT5;
	  PT6 = env.pt6 || PT6;
	  PT7 = env.pt7 || PT7;
	  PT8 = env.pt8 || PT8;
	  PT9 = env.pt9 || PT9;
	  PT10 = env.pt10 || PT10;
	  PT11 = env.pt11 || PT11;
	  PT12 = env.pt12 || PT12;
	  PT13 = env.pt13 || PT13;
	  PT14 = env.pt14 || PT14;
	  PT15 = env.pt15 || PT15;
	  PT16 = env.pt16 || PT16;
	  PT17 = env.pt17 || PT17;
	  PT18 = env.pt18 || PT18;
	  PT19 = env.pt19 || PT19;
	  PT20 = env.pt20 || PT20;
	  PT21 = env.pt21 || PT21;
	  PT22 = env.pt22 || PT22;
	  PT23 = env.pt23 || PT23;
	  PT24 = env.pt24 || PT24;
	  PT25 = env.pt25 || PT25;
	  PT26 = env.pt26 || PT26;
	  PT27 = env.pt27 || PT27;
	  PT28 = env.pt28 || PT28;
	  PT29 = env.pt29 || PT29;
	  PT30 = env.pt30 || PT30;
	  PT31 = env.pt31 || PT31;
	  PT32 = env.pt32 || PT32;
	  PT33 = env.pt33 || PT33;
	  PT34 = env.pt34 || PT34;
	  PT35 = env.pt35 || PT35;
	  PT36 = env.pt36 || PT36;
	  PT37 = env.pt37 || PT37;
	  PT38 = env.pt38 || PT38;
	  PT39 = env.pt39 || PT39;
	  PT40 = env.pt40 || PT40;
	  PT41 = env.pt41 || PT41;
	  PT42 = env.pt42 || PT42;
	  PT43 = env.pt43 || PT43;
	  PT44 = env.pt44 || PT44;
	  PT45 = env.pt45 || PT45;
	  PT46 = env.pt46 || PT46;
	  PT47 = env.pt47 || PT47;
	  PT48 = env.pt48 || PT48;
	  PT49 = env.pt49 || PT49;
	  PT50 = env.pt50 || PT50;
      const upgradeHeader = request.headers.get("Upgrade");
      const url = new URL(request.url);
      if (!upgradeHeader || upgradeHeader !== "websocket") {
        const url = new URL(request.url);
        switch (url.pathname) {
          case `/${userID}`: {
            const vlessConfig = getVLESSConfig(userID, request.headers.get("Host"));
            return new Response(`${vlessConfig}`, {
              status: 200,
              headers: {
                "Content-Type": "text/html;charset=utf-8",
              },
            });
          }
		  case `/${userID}/ty`: {
			const tyConfig = gettyConfig(userID, request.headers.get('Host'));
			return new Response(`${tyConfig}`, {
				status: 200,
				headers: {
					"Content-Type": "text/plain;charset=utf-8",
				}
			});
		}
		case `/${userID}/cl`: {
			const clConfig = getclConfig(userID, request.headers.get('Host'));
			return new Response(`${clConfig}`, {
				status: 200,
				headers: {
					"Content-Type": "text/plain;charset=utf-8",
				}
			});
		}
		case `/${userID}/sb`: {
			const sbConfig = getsbConfig(userID, request.headers.get('Host'));
			return new Response(`${sbConfig}`, {
				status: 200,
				headers: {
					"Content-Type": "application/json;charset=utf-8",
				}
			});
		}
		case `/${userID}/pty`: {
			const ptyConfig = getptyConfig(userID, request.headers.get('Host'));
			return new Response(`${ptyConfig}`, {
				status: 200,
				headers: {
					"Content-Type": "text/plain;charset=utf-8",
				}
			});
		}
		case `/${userID}/pcl`: {
			const pclConfig = getpclConfig(userID, request.headers.get('Host'));
			return new Response(`${pclConfig}`, {
				status: 200,
				headers: {
					"Content-Type": "text/plain;charset=utf-8",
				}
			});
		}
		case `/${userID}/psb`: {
			const psbConfig = getpsbConfig(userID, request.headers.get('Host'));
			return new Response(`${psbConfig}`, {
				status: 200,
				headers: {
					"Content-Type": "application/json;charset=utf-8",
				}
			});
		}
          default:
            // return new Response('Not found', { status: 404 });
            // For any other path, reverse proxy to 'ramdom website' and return the original response, caching it in the process
            if (cn_hostnames.includes('')) {
            return new Response(JSON.stringify(request.cf, null, 4), {
              status: 200,
              headers: {
                "Content-Type": "application/json;charset=utf-8",
              },
            });
            }
            const randomHostname = cn_hostnames[Math.floor(Math.random() * cn_hostnames.length)];
            const newHeaders = new Headers(request.headers);
            newHeaders.set("cf-connecting-ip", "1.2.3.4");
            newHeaders.set("x-forwarded-for", "1.2.3.4");
            newHeaders.set("x-real-ip", "1.2.3.4");
            newHeaders.set("referer", "https://www.google.com/search?q=edtunnel");
            // Use fetch to proxy the request to 15 different domains
            const proxyUrl = "https://" + randomHostname + url.pathname + url.search;
            let modifiedRequest = new Request(proxyUrl, {
              method: request.method,
              headers: newHeaders,
              body: request.body,
              redirect: "manual",
            });
            const proxyResponse = await fetch(modifiedRequest, { redirect: "manual" });
            // Check for 302 or 301 redirect status and return an error response
            if ([301, 302].includes(proxyResponse.status)) {
              return new Response(`Redirects to ${randomHostname} are not allowed.`, {
                status: 403,
                statusText: "Forbidden",
              });
            }
            // Return the response from the proxy server
            return proxyResponse;
        }
      } else {
			if(url.pathname.includes('/pyip='))
			{
				const tmp_ip=url.pathname.split("=")[1];
				if(isValidIP(tmp_ip))
				{
					proxyIP=tmp_ip;
					if (proxyIP.includes(']:')) {
						let lastColonIndex = proxyIP.lastIndexOf(':');
						proxyPort = proxyIP.slice(lastColonIndex + 1);
						proxyIP = proxyIP.slice(0, lastColonIndex);	
					} else if (!proxyIP.includes(']:') && !proxyIP.includes(']')) {
						[proxyIP, proxyPort = '443'] = proxyIP.split(':');
					} else {
						proxyPort = '443';
					}
				}	
			}
        return await vlessOverWSHandler(request);
		}
    } catch (err) {
      /** @type {Error} */ let e = err;
      return new Response(e.toString());
    }
  },
};

function isValidIP(ip) {
    var reg = /^[\s\S]*$/;
    return reg.test(ip);
}

/**
 *
 * @param {import("@cloudflare/workers-types").Request} request
 */
async function vlessOverWSHandler(request) {
  /** @type {import("@cloudflare/workers-types").WebSocket[]} */
  // @ts-ignore
  const webSocketPair = new WebSocketPair();
  const [client, webSocket] = Object.values(webSocketPair);

  webSocket.accept();

  let address = "";
  let portWithRandomLog = "";
  const log = (/** @type {string} */ info, /** @type {string | undefined} */ event) => {
    console.log(`[${address}:${portWithRandomLog}] ${info}`, event || "");
  };
  const earlyDataHeader = request.headers.get("sec-websocket-protocol") || "";

  const readableWebSocketStream = makeReadableWebSocketStream(webSocket, earlyDataHeader, log);

  /** @type {{ value: import("@cloudflare/workers-types").Socket | null}}*/
  let remoteSocketWapper = {
    value: null,
  };
  let udpStreamWrite = null;
  let isDns = false;

  // ws --> remote
  readableWebSocketStream
    .pipeTo(
      new WritableStream({
        async write(chunk, controller) {
          if (isDns && udpStreamWrite) {
            return udpStreamWrite(chunk);
          }
          if (remoteSocketWapper.value) {
            const writer = remoteSocketWapper.value.writable.getWriter();
            await writer.write(chunk);
            writer.releaseLock();
            return;
          }

          const {
            hasError,
            message,
            portRemote = 443,
            addressRemote = "",
            rawDataIndex,
            vlessVersion = new Uint8Array([0, 0]),
            isUDP,
          } = await processVlessHeader(chunk, userID);
          address = addressRemote;
          portWithRandomLog = `${portRemote}--${Math.random()} ${isUDP ? "udp " : "tcp "} `;
          if (hasError) {
            // controller.error(message);
            throw new Error(message); // cf seems has bug, controller.error will not end stream
            // webSocket.close(1000, message);
            return;
          }
          // if UDP but port not DNS port, close it
          if (isUDP) {
            if (portRemote === 53) {
              isDns = true;
            } else {
              // controller.error('UDP proxy only enable for DNS which is port 53');
              throw new Error("UDP proxy only enable for DNS which is port 53"); // cf seems has bug, controller.error will not end stream
              return;
            }
          }
          // ["version", "附加信息长度 N"]
          const vlessResponseHeader = new Uint8Array([vlessVersion[0], 0]);
          const rawClientData = chunk.slice(rawDataIndex);

          // TODO: support udp here when cf runtime has udp support
          if (isDns) {
            const { write } = await handleUDPOutBound(webSocket, vlessResponseHeader, log);
            udpStreamWrite = write;
            udpStreamWrite(rawClientData);
            return;
          }
          handleTCPOutBound(
            remoteSocketWapper,
            addressRemote,
            portRemote,
            rawClientData,
            webSocket,
            vlessResponseHeader,
            log
          );
        },
        close() {
          log(`readableWebSocketStream is close`);
        },
        abort(reason) {
          log(`readableWebSocketStream is abort`, JSON.stringify(reason));
        },
      })
    )
    .catch((err) => {
      log("readableWebSocketStream pipeTo error", err);
    });

  return new Response(null, {
    status: 101,
    // @ts-ignore
    webSocket: client,
  });
}

/**
 * Checks if a given UUID is present in the API response.
 * @param {string} targetUuid The UUID to search for.
 * @returns {Promise<boolean>} A Promise that resolves to true if the UUID is present in the API response, false otherwise.
 */
async function checkUuidInApiResponse(targetUuid) {
  // Check if any of the environment variables are empty

  try {
    const apiResponse = await getApiResponse();
    if (!apiResponse) {
      return false;
    }
    const isUuidInResponse = apiResponse.users.some((user) => user.uuid === targetUuid);
    return isUuidInResponse;
  } catch (error) {
    console.error("Error:", error);
    return false;
  }
}

/**
 * Handles outbound TCP connections.
 *
 * @param {any} remoteSocket
 * @param {string} addressRemote The remote address to connect to.
 * @param {number} portRemote The remote port to connect to.
 * @param {Uint8Array} rawClientData The raw client data to write.
 * @param {import("@cloudflare/workers-types").WebSocket} webSocket The WebSocket to pass the remote socket to.
 * @param {Uint8Array} vlessResponseHeader The VLESS response header.
 * @param {function} log The logging function.
 * @returns {Promise<void>} The remote socket.
 */
async function handleTCPOutBound(
  remoteSocket,
  addressRemote,
  portRemote,
  rawClientData,
  webSocket,
  vlessResponseHeader,
  log
) {
  async function connectAndWrite(address, port) {
    if (/^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?).){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/.test(address)) address = `${atob('d3d3Lg==')}${address}${atob('LnNzbGlwLmlv')}`;
    /** @type {import("@cloudflare/workers-types").Socket} */
    const tcpSocket = connect({
      hostname: address,
      port: port,
    });
    remoteSocket.value = tcpSocket;
    log(`connected to ${address}:${port}`);
    const writer = tcpSocket.writable.getWriter();
    await writer.write(rawClientData); // first write, nomal is tls client hello
    writer.releaseLock();
    return tcpSocket;
  }

  // if the cf connect tcp socket have no incoming data, we retry to redirect ip
  async function retry() {
    const tcpSocket = await connectAndWrite(proxyIP || addressRemote, proxyPort || portRemote);
    // no matter retry success or not, close websocket
    tcpSocket.closed
      .catch((error) => {
        console.log("retry tcpSocket closed error", error);
      })
      .finally(() => {
        safeCloseWebSocket(webSocket);
      });
    remoteSocketToWS(tcpSocket, webSocket, vlessResponseHeader, null, log);
  }

  const tcpSocket = await connectAndWrite(addressRemote, portRemote);

  // when remoteSocket is ready, pass to websocket
  // remote--> ws
  remoteSocketToWS(tcpSocket, webSocket, vlessResponseHeader, retry, log);
}

/**
 *
 * @param {import("@cloudflare/workers-types").WebSocket} webSocketServer
 * @param {string} earlyDataHeader for ws 0rtt
 * @param {(info: string)=> void} log for ws 0rtt
 */
function makeReadableWebSocketStream(webSocketServer, earlyDataHeader, log) {
  let readableStreamCancel = false;
  const stream = new ReadableStream({
    start(controller) {
      webSocketServer.addEventListener("message", (event) => {
        if (readableStreamCancel) {
          return;
        }
        const message = event.data;
        controller.enqueue(message);
      });

      // The event means that the client closed the client -> server stream.
      // However, the server -> client stream is still open until you call close() on the server side.
      // The WebSocket protocol says that a separate close message must be sent in each direction to fully close the socket.
      webSocketServer.addEventListener("close", () => {
        // client send close, need close server
        // if stream is cancel, skip controller.close
        safeCloseWebSocket(webSocketServer);
        if (readableStreamCancel) {
          return;
        }
        controller.close();
      });
      webSocketServer.addEventListener("error", (err) => {
        log("webSocketServer has error");
        controller.error(err);
      });
      // for ws 0rtt
      const { earlyData, error } = base64ToArrayBuffer(earlyDataHeader);
      if (error) {
        controller.error(error);
      } else if (earlyData) {
        controller.enqueue(earlyData);
      }
    },

    pull(controller) {
      // if ws can stop read if stream is full, we can implement backpressure
      // https://streams.spec.whatwg.org/#example-rs-push-backpressure
    },
    cancel(reason) {
      // 1. pipe WritableStream has error, this cancel will called, so ws handle server close into here
      // 2. if readableStream is cancel, all controller.close/enqueue need skip,
      // 3. but from testing controller.error still work even if readableStream is cancel
      if (readableStreamCancel) {
        return;
      }
      log(`ReadableStream was canceled, due to ${reason}`);
      readableStreamCancel = true;
      safeCloseWebSocket(webSocketServer);
    },
  });

  return stream;
}

// https://xtls.github.io/development/protocols/vless.html
// https://github.com/zizifn/excalidraw-backup/blob/main/v2ray-protocol.excalidraw

/**
 *
 * @param { ArrayBuffer} vlessBuffer
 * @param {string} userID
 * @returns
 */
async function processVlessHeader(vlessBuffer, userID) {
  if (vlessBuffer.byteLength < 24) {
    return {
      hasError: true,
      message: "invalid data",
    };
  }
  const version = new Uint8Array(vlessBuffer.slice(0, 1));
  let isValidUser = false;
  let isUDP = false;
  const slicedBuffer = new Uint8Array(vlessBuffer.slice(1, 17));
  const slicedBufferString = stringify(slicedBuffer);

  const uuids = userID.includes(",") ? userID.split(",") : [userID];

  const checkUuidInApi = await checkUuidInApiResponse(slicedBufferString);
  isValidUser = uuids.some((userUuid) => checkUuidInApi || slicedBufferString === userUuid.trim());

  console.log(`checkUuidInApi: ${await checkUuidInApiResponse(slicedBufferString)}, userID: ${slicedBufferString}`);

  if (!isValidUser) {
    return {
      hasError: true,
      message: "invalid user",
    };
  }

  const optLength = new Uint8Array(vlessBuffer.slice(17, 18))[0];
  //skip opt for now

  const command = new Uint8Array(vlessBuffer.slice(18 + optLength, 18 + optLength + 1))[0];

  // 0x01 TCP
  // 0x02 UDP
  // 0x03 MUX
  if (command === 1) {
  } else if (command === 2) {
    isUDP = true;
  } else {
    return {
      hasError: true,
      message: `command ${command} is not support, command 01-tcp,02-udp,03-mux`,
    };
  }
  const portIndex = 18 + optLength + 1;
  const portBuffer = vlessBuffer.slice(portIndex, portIndex + 2);
  // port is big-Endian in raw data etc 80 == 0x005d
  const portRemote = new DataView(portBuffer).getUint16(0);

  let addressIndex = portIndex + 2;
  const addressBuffer = new Uint8Array(vlessBuffer.slice(addressIndex, addressIndex + 1));

  // 1--> ipv4  addressLength =4
  // 2--> domain name addressLength=addressBuffer[1]
  // 3--> ipv6  addressLength =16
  const addressType = addressBuffer[0];
  let addressLength = 0;
  let addressValueIndex = addressIndex + 1;
  let addressValue = "";
  switch (addressType) {
    case 1:
      addressLength = 4;
      addressValue = new Uint8Array(vlessBuffer.slice(addressValueIndex, addressValueIndex + addressLength)).join(".");
      break;
    case 2:
      addressLength = new Uint8Array(vlessBuffer.slice(addressValueIndex, addressValueIndex + 1))[0];
      addressValueIndex += 1;
      addressValue = new TextDecoder().decode(vlessBuffer.slice(addressValueIndex, addressValueIndex + addressLength));
      break;
    case 3:
      addressLength = 16;
      const dataView = new DataView(vlessBuffer.slice(addressValueIndex, addressValueIndex + addressLength));
      // 2001:0db8:85a3:0000:0000:8a2e:0370:7334
      const ipv6 = [];
      for (let i = 0; i < 8; i++) {
        ipv6.push(dataView.getUint16(i * 2).toString(16));
      }
      addressValue = ipv6.join(":");
      // seems no need add [] for ipv6
      break;
    default:
      return {
        hasError: true,
        message: `invild  addressType is ${addressType}`,
      };
  }
  if (!addressValue) {
    return {
      hasError: true,
      message: `addressValue is empty, addressType is ${addressType}`,
    };
  }

  return {
    hasError: false,
    addressRemote: addressValue,
    addressType,
    portRemote,
    rawDataIndex: addressValueIndex + addressLength,
    vlessVersion: version,
    isUDP,
  };
}

/**
 *
 * @param {import("@cloudflare/workers-types").Socket} remoteSocket
 * @param {import("@cloudflare/workers-types").WebSocket} webSocket
 * @param {ArrayBuffer} vlessResponseHeader
 * @param {(() => Promise<void>) | null} retry
 * @param {*} log
 */
async function remoteSocketToWS(remoteSocket, webSocket, vlessResponseHeader, retry, log) {
  // remote--> ws
  let remoteChunkCount = 0;
  let chunks = [];
  /** @type {ArrayBuffer | null} */
  let vlessHeader = vlessResponseHeader;
  let hasIncomingData = false; // check if remoteSocket has incoming data
  await remoteSocket.readable
    .pipeTo(
      new WritableStream({
        start() {},
        /**
         *
         * @param {Uint8Array} chunk
         * @param {*} controller
         */
        async write(chunk, controller) {
          hasIncomingData = true;
          // remoteChunkCount++;
          if (webSocket.readyState !== WS_READY_STATE_OPEN) {
            controller.error("webSocket.readyState is not open, maybe close");
          }
          if (vlessHeader) {
            webSocket.send(await new Blob([vlessHeader, chunk]).arrayBuffer());
            vlessHeader = null;
          } else {
            // seems no need rate limit this, CF seems fix this??..
            // if (remoteChunkCount > 20000) {
            // 	// cf one package is 4096 byte(4kb),  4096 * 20000 = 80M
            // 	await delay(1);
            // }
            webSocket.send(chunk);
          }
        },
        close() {
          log(`remoteConnection!.readable is close with hasIncomingData is ${hasIncomingData}`);
          // safeCloseWebSocket(webSocket); // no need server close websocket frist for some case will casue HTTP ERR_CONTENT_LENGTH_MISMATCH issue, client will send close event anyway.
        },
        abort(reason) {
          console.error(`remoteConnection!.readable abort`, reason);
        },
      })
    )
    .catch((error) => {
      console.error(`remoteSocketToWS has exception `, error.stack || error);
      safeCloseWebSocket(webSocket);
    });

  // seems is cf connect socket have error,
  // 1. Socket.closed will have error
  // 2. Socket.readable will be close without any data coming
  if (hasIncomingData === false && retry) {
    log(`retry`);
    retry();
  }
}

/**
 *
 * @param {string} base64Str
 * @returns
 */
function base64ToArrayBuffer(base64Str) {
  if (!base64Str) {
    return { error: null };
  }
  try {
    // go use modified Base64 for URL rfc4648 which js atob not support
    base64Str = base64Str.replace(/-/g, "+").replace(/_/g, "/");
    const decode = atob(base64Str);
    const arryBuffer = Uint8Array.from(decode, (c) => c.charCodeAt(0));
    return { earlyData: arryBuffer.buffer, error: null };
  } catch (error) {
    return { error };
  }
}

/**
 * This is not real UUID validation
 * @param {string} uuid
 */
function isValidUUID(uuid) {
  const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[4][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
  return uuidRegex.test(uuid);
}

const WS_READY_STATE_OPEN = 1;
const WS_READY_STATE_CLOSING = 2;
/**
 * Normally, WebSocket will not has exceptions when close.
 * @param {import("@cloudflare/workers-types").WebSocket} socket
 */
function safeCloseWebSocket(socket) {
  try {
    if (socket.readyState === WS_READY_STATE_OPEN || socket.readyState === WS_READY_STATE_CLOSING) {
      socket.close();
    }
  } catch (error) {
    console.error("safeCloseWebSocket error", error);
  }
}

const byteToHex = [];
for (let i = 0; i < 256; ++i) {
  byteToHex.push((i + 256).toString(16).slice(1));
}
function unsafeStringify(arr, offset = 0) {
  return (
    byteToHex[arr[offset + 0]] +
    byteToHex[arr[offset + 1]] +
    byteToHex[arr[offset + 2]] +
    byteToHex[arr[offset + 3]] +
    "-" +
    byteToHex[arr[offset + 4]] +
    byteToHex[arr[offset + 5]] +
    "-" +
    byteToHex[arr[offset + 6]] +
    byteToHex[arr[offset + 7]] +
    "-" +
    byteToHex[arr[offset + 8]] +
    byteToHex[arr[offset + 9]] +
    "-" +
    byteToHex[arr[offset + 10]] +
    byteToHex[arr[offset + 11]] +
    byteToHex[arr[offset + 12]] +
    byteToHex[arr[offset + 13]] +
    byteToHex[arr[offset + 14]] +
    byteToHex[arr[offset + 15]]
  ).toLowerCase();
}
function stringify(arr, offset = 0) {
  const uuid = unsafeStringify(arr, offset);
  if (!isValidUUID(uuid)) {
    throw TypeError("Stringified UUID is invalid");
  }
  return uuid;
}
 
/**
 *
 * @param {import("@cloudflare/workers-types").WebSocket} webSocket
 * @param {ArrayBuffer} vlessResponseHeader
 * @param {(string)=> void} log
 */
async function handleUDPOutBound(webSocket, vlessResponseHeader, log) {
  let isVlessHeaderSent = false;
  const transformStream = new TransformStream({
    start(controller) {},
    transform(chunk, controller) {
      // udp message 2 byte is the the length of udp data
      // TODO: this should have bug, beacsue maybe udp chunk can be in two websocket message
      for (let index = 0; index < chunk.byteLength; ) {
        const lengthBuffer = chunk.slice(index, index + 2);
        const udpPakcetLength = new DataView(lengthBuffer).getUint16(0);
        const udpData = new Uint8Array(chunk.slice(index + 2, index + 2 + udpPakcetLength));
        index = index + 2 + udpPakcetLength;
        controller.enqueue(udpData);
      }
    },
    flush(controller) {},
  });

  // only handle dns udp for now
  transformStream.readable
    .pipeTo(
      new WritableStream({
        async write(chunk) {
          const resp = await fetch(
            dohURL, // dns server url
            {
              method: "POST",
              headers: {
                "content-type": "application/dns-message",
              },
              body: chunk,
            }
          );
          const dnsQueryResult = await resp.arrayBuffer();
          const udpSize = dnsQueryResult.byteLength;
          // console.log([...new Uint8Array(dnsQueryResult)].map((x) => x.toString(16)));
          const udpSizeBuffer = new Uint8Array([(udpSize >> 8) & 0xff, udpSize & 0xff]);
          if (webSocket.readyState === WS_READY_STATE_OPEN) {
            log(`doh success and dns message length is ${udpSize}`);
            if (isVlessHeaderSent) {
              webSocket.send(await new Blob([udpSizeBuffer, dnsQueryResult]).arrayBuffer());
            } else {
              webSocket.send(await new Blob([vlessResponseHeader, udpSizeBuffer, dnsQueryResult]).arrayBuffer());
              isVlessHeaderSent = true;
            }
          }
        },
      })
    )
    .catch((error) => {
      log("dns udp has error" + error);
    });

  const writer = transformStream.writable.getWriter();

  return {
    /**
     *
     * @param {Uint8Array} chunk
     */
    write(chunk) {
      writer.write(chunk);
    },
  };
}

/**
 *
 * @param {string} userID
 * @param {string | null} hostName
 * @returns {string}
 */
function getVLESSConfig(userID, hostName) {
  const wvlessws = `vless\u003A//${userID}\u0040${CDNIP}:8880?encryption=none&security=none&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#${hostName}`;
  const pvlesswstls = `vless\u003A//${userID}\u0040${CDNIP}:8443?encryption=none&security=tls&type=ws&host=${hostName}&sni=${hostName}&fp=random&path=%2F%3Fed%3D2560#${hostName}`;
  const note = `甬哥博客地址：https://ygkkk.blogspot.com\n甬哥YouTube频道：https://www.youtube.com/@ygkkk\n甬哥TG电报群组：https://t.me/ygkkktg\n甬哥TG电报频道：https://t.me/ygkkktgpd\n\nProxyIP全局运行中：${proxyIP}`;
  const ty = `https://${hostName}/${userID}/ty`
  const cl = `https://${hostName}/${userID}/cl`
  const sb = `https://${hostName}/${userID}/sb`
  const pty = `https://${hostName}/${userID}/pty`
  const pcl = `https://${hostName}/${userID}/pcl`
  const psb = `https://${hostName}/${userID}/psb`
  const noteshow = note.replace(/\n/g, '<br>');
  const displayHtml = `
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-QWTKZyjpPEjISv5WaRU9OFeRpok6YctnYmDr5pNlyT2bRjXh0JMhjY6hW+ALEwIH" crossorigin="anonymous">
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js" integrity="sha384-YvpcrYf0tY3lHB60NNkmXc5s9fDVZLESaAA55NDzOxhy9GkcIdslK1eN7N6jIeHz" crossorigin="anonymous"></script>
<style>
.limited-width {
    max-width: 200px;
    overflow: auto;
    word-wrap: break-word;
}
</style>
</head>
<script>
function copyToClipboard(text) {
  const input = document.createElement('textarea');
  input.style.position = 'fixed';
  input.style.opacity = 0;
  input.value = text;
  document.body.appendChild(input);
  input.select();
  document.execCommand('Copy');
  document.body.removeChild(input);
  alert('已复制到剪贴板');
}
</script>
`;
if (hostName.includes("workers.dev")) {
return `
<br>
<br>
${displayHtml}
<body>
<div class="container">
    <div class="row">
        <div class="col-md-12">
            <h1>Cloudflare-workers/pages-vless代理脚本 V24.12.22</h1>
	    <hr>
            <p>${noteshow}</p>
            <hr>
	    <hr>
	    <hr>
            <br>
            <br>
            <h3>1：CF-workers-vless+ws节点</h3>
			<table class="table">
				<thead>
					<tr>
						<th>节点特色：</th>
						<th>单节点链接如下：</th>
					</tr>
				</thead>
				<tbody>
					<tr>
						<td class="limited-width">关闭了TLS加密，无视域名阻断</td>
						<td class="limited-width">${wvlessws}</td>
						<td><button class="btn btn-primary" onclick="copyToClipboard('${wvlessws}')">点击复制链接</button></td>
					</tr>
				</tbody>
			</table>
            <h5>客户端参数如下：</h5>
            <ul>
                <li>客户端地址(address)：自定义的域名 或者 优选域名 或者 优选IP 或者 反代IP</li>
                <li>端口(port)：7个http端口可任意选择(80、8080、8880、2052、2082、2086、2095)，或反代IP对应端口</li>
                <li>用户ID(uuid)：${userID}</li>
                <li>传输协议(network)：ws 或者 websocket</li>
                <li>伪装域名(host)：${hostName}</li>
                <li>路径(path)：/?ed=2560</li>
		<li>传输安全(TLS)：关闭</li>
            </ul>
            <hr>
			<hr>
			<hr>
            <br>
            <br>
            <h3>2：CF-workers-vless+ws+tls节点</h3>
			<table class="table">
				<thead>
					<tr>
						<th>节点特色：</th>
						<th>单节点链接如下：</th>
					</tr>
				</thead>
				<tbody>
					<tr>
						<td class="limited-width">启用了TLS加密，<br>如果客户端支持分片(Fragment)功能，建议开启，防止域名阻断</td>
						<td class="limited-width">${pvlesswstls}</td>	
						<td><button class="btn btn-primary" onclick="copyToClipboard('${pvlesswstls}')">点击复制链接</button></td>
					</tr>
				</tbody>
			</table>
            <h5>客户端参数如下：</h5>
            <ul>
                <li>客户端地址(address)：自定义的域名 或者 优选域名 或者 优选IP 或者 反代IP</li>
                <li>端口(port)：6个https端口可任意选择(443、8443、2053、2083、2087、2096)，或反代IP对应端口</li>
                <li>用户ID(uuid)：${userID}</li>
                <li>传输协议(network)：ws 或者 websocket</li>
                <li>伪装域名(host)：${hostName}</li>
                <li>路径(path)：/?ed=2560</li>
                <li>传输安全(TLS)：开启</li>
                <li>跳过证书验证(allowlnsecure)：false</li>
			</ul>
			<hr>
			<hr>
			<hr>
			<br>	
			<br>
			<h3>3：聚合通用、Clash-meta、Sing-box订阅链接如下：</h3>
			<hr>
			<p>注意：<br>1、默认每个订阅链接包含TLS+非TLS共13个端口节点<br>2、当前workers域名作为订阅链接，需通过代理进行订阅更新<br>3、如使用的客户端不支持分片功能，则TLS节点不可用</p>
			<hr>
			<table class="table">
					<thead>
						<tr>
							<th>聚合通用订阅链接：</th>
						</tr>
					</thead>
					<tbody>
						<tr>
							<td class="limited-width">${ty}</td>	
							<td><button class="btn btn-primary" onclick="copyToClipboard('${ty}')">点击复制链接</button></td>
						</tr>
					</tbody>
				</table>	

				<table class="table">
						<thead>
							<tr>
								<th>Clash-meta订阅链接：</th>
							</tr>
						</thead>
						<tbody>
							<tr>
								<td class="limited-width">${cl}</td>	
								<td><button class="btn btn-primary" onclick="copyToClipboard('${cl}')">点击复制链接</button></td>
							</tr>
						</tbody>
					</table>

					<table class="table">
					<thead>
						<tr>
							<th>Sing-box订阅链接：</th>
						</tr>
					</thead>
					<tbody>
						<tr>
							<td class="limited-width">${sb}</td>	
							<td><button class="btn btn-primary" onclick="copyToClipboard('${sb}')">点击复制链接</button></td>
						</tr>
					</tbody>
				</table>
				<br>
				<br>
        </div>
    </div>
</div>
</body>
`;
  } else {
    return `
<br>
<br>
${displayHtml}
<body>
<div class="container">
    <div class="row">
        <div class="col-md-12">
            <h1>Cloudflare-workers/pages-vless代理脚本 V24.12.22</h1>
			<hr>
            <p>${noteshow}</p>
            <hr>
			<hr>
			<hr>
            <br>
            <br>
            <h3>1：CF-pages/workers/自定义域-vless+ws+tls节点</h3>
			<table class="table">
				<thead>
					<tr>
						<th>节点特色：</th>
						<th>单节点链接如下：</th>
					</tr>
				</thead>
				<tbody>
					<tr>
						<td class="limited-width">启用了TLS加密，<br>如果客户端支持分片(Fragment)功能，可开启，防止域名阻断</td>
						<td class="limited-width">${pvlesswstls}</td>
						<td><button class="btn btn-primary" onclick="copyToClipboard('${pvlesswstls}')">点击复制链接</button></td>
					</tr>
				</tbody>
			</table>
            <h5>客户端参数如下：</h5>
            <ul>
                <li>客户端地址(address)：自定义的域名 或者 优选域名 或者 优选IP 或者 反代IP</li>
                <li>端口(port)：6个https端口可任意选择(443、8443、2053、2083、2087、2096)，或反代IP对应端口</li>
                <li>用户ID(uuid)：${userID}</li>
                <li>传输协议(network)：ws 或者 websocket</li>
                <li>伪装域名(host)：${hostName}</li>
                <li>路径(path)：/?ed=2560</li>
                <li>传输安全(TLS)：开启</li>
                <li>跳过证书验证(allowlnsecure)：false</li>
			</ul>
            <hr>
			<hr>
			<hr>
            <br>
            <br>
			<h3>2：聚合通用、Clash-meta、Sing-box订阅链接如下：</h3>
			<hr>
			<p>注意：以下订阅链接仅6个TLS端口节点</p>
			<hr>
			<table class="table">
					<thead>
						<tr>
							<th>聚合通用订阅链接：</th>
						</tr>
					</thead>
					<tbody>
						<tr>
							<td class="limited-width">${pty}</td>	
							<td><button class="btn btn-primary" onclick="copyToClipboard('${pty}')">点击复制链接</button></td>
						</tr>
					</tbody>
				</table>	

				<table class="table">
						<thead>
							<tr>
								<th>Clash-meta订阅链接：</th>
							</tr>
						</thead>
						<tbody>
							<tr>
								<td class="limited-width">${pcl}</td>	
								<td><button class="btn btn-primary" onclick="copyToClipboard('${pcl}')">点击复制链接</button></td>
							</tr>
						</tbody>
					</table>

					<table class="table">
					<thead>
						<tr>
							<th>Sing-box订阅链接：</th>
						</tr>
					</thead>
					<tbody>
						<tr>
							<td class="limited-width">${psb}</td>	
							<td><button class="btn btn-primary" onclick="copyToClipboard('${psb}')">点击复制链接</button></td>
						</tr>
					</tbody>
				</table>
				<br>
				<br>
        </div>
    </div>
</div>
</body>
`;
  }
}

function gettyConfig(userID, hostName) {
	const vlessshare = btoa(`vless\u003A//${userID}\u0040${IP1}:${PT1}?encryption=none&security=none&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V1_${IP1}_${PT1}\nvless\u003A//${userID}\u0040${IP2}:${PT2}?encryption=none&security=none&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V2_${IP2}_${PT2}\nvless\u003A//${userID}\u0040${IP3}:${PT3}?encryption=none&security=none&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V3_${IP3}_${PT3}\nvless\u003A//${userID}\u0040${IP4}:${PT4}?encryption=none&security=none&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V4_${IP4}_${PT4}\nvless\u003A//${userID}\u0040${IP5}:${PT5}?encryption=none&security=none&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V5_${IP5}_${PT5}\nvless\u003A//${userID}\u0040${IP6}:${PT6}?encryption=none&security=none&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V6_${IP6}_${PT6}\nvless\u003A//${userID}\u0040${IP7}:${PT7}?encryption=none&security=none&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V7_${IP7}_${PT7}\nvless\u003A//${userID}\u0040${IP8}:${PT8}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V8_${IP8}_${PT8}\nvless\u003A//${userID}\u0040${IP9}:${PT9}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V9_${IP9}_${PT9}\nvless\u003A//${userID}\u0040${IP10}:${PT10}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V10_${IP10}_${PT10}\nvless\u003A//${userID}\u0040${IP11}:${PT11}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V11_${IP11}_${PT11}\nvless\u003A//${userID}\u0040${IP12}:${PT12}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V12_${IP12}_${PT12}\nvless\u003A//${userID}\u0040${IP13}:${PT13}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V13_${IP13}_${PT13}`);
		return `${vlessshare}`
	}

function getclConfig(userID, hostName) {
return `
port: 7890
allow-lan: true
mode: rule
log-level: info
unified-delay: true
global-client-fingerprint: chrome
dns:
  enable: true
  listen: :53
  ipv6: true
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16
  default-nameserver: 
    - 223.5.5.5
    - 114.114.114.114
    - 8.8.8.8
  nameserver:
    - https://dns.alidns.com/dns-query
    - https://doh.pub/dns-query
  fallback:
    - https://1.0.0.1/dns-query
    - tls://dns.google
  fallback-filter:
    geoip: true
    geoip-code: CN
    ipcidr:
      - 240.0.0.0/4

proxies:
- name: CF_V1_${IP1}_${PT1}
  type: vless
  server: ${IP1}
  port: ${PT1}
  uuid: ${userID}
  udp: false
  tls: false
  network: ws
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}

- name: CF_V2_${IP2}_${PT2}
  type: vless
  server: ${IP2}
  port: ${PT2}
  uuid: ${userID}
  udp: false
  tls: false
  network: ws
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}

- name: CF_V3_${IP3}_${PT3}
  type: vless
  server: ${IP3}
  port: ${PT3}
  uuid: ${userID}
  udp: false
  tls: false
  network: ws
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}

- name: CF_V4_${IP4}_${PT4}
  type: vless
  server: ${IP4}
  port: ${PT4}
  uuid: ${userID}
  udp: false
  tls: false
  network: ws
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}

- name: CF_V5_${IP5}_${PT5}
  type: vless
  server: ${IP5}
  port: ${PT5}
  uuid: ${userID}
  udp: false
  tls: false
  network: ws
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}

- name: CF_V6_${IP6}_${PT6}
  type: vless
  server: ${IP6}
  port: ${PT6}
  uuid: ${userID}
  udp: false
  tls: false
  network: ws
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}

- name: CF_V7_${IP7}_${PT7}
  type: vless
  server: ${IP7}
  port: ${PT7}
  uuid: ${userID}
  udp: false
  tls: false
  network: ws
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}

- name: CF_V8_${IP8}_${PT8}
  type: vless
  server: ${IP8}
  port: ${PT8}
  uuid: ${userID}
  udp: false
  tls: false
  network: ws
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}

- name: CF_V9_${IP9}_${PT9}
  type: vless
  server: ${IP9}
  port: ${PT9}
  uuid: ${userID}
  udp: false
  tls: false
  network: ws
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}

- name: CF_V10_${IP10}_${PT10}
  type: vless
  server: ${IP10}
  port: ${PT10}
  uuid: ${userID}
  udp: false
  tls: false
  network: ws
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}

- name: CF_V11_${IP11}_${PT11}
  type: vless
  server: ${IP11}
  port: ${PT11}
  uuid: ${userID}
  udp: false
  tls: false
  network: ws
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}

- name: CF_V12_${IP12}_${PT12}
  type: vless
  server: ${IP12}
  port: ${PT12}
  uuid: ${userID}
  udp: false
  tls: false
  network: ws
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}

- name: CF_V13_${IP13}_${PT13}
  type: vless
  server: ${IP13}
  port: ${PT13}
  uuid: ${userID}
  udp: false
  tls: false
  network: ws
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}

- name: CF_V14_${IP14}_${PT14}
  type: vless
  server: ${IP14}
  port: ${PT14}
  uuid: ${userID}
  udp: false
  tls: false
  network: ws
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}

- name: CF_V15_${IP15}_${PT15}
  type: vless
  server: ${IP15}
  port: ${PT15}
  uuid: ${userID}
  udp: false
  tls: false
  network: ws
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}

- name: CF_V16_${IP16}_${PT16}
  type: vless
  server: ${IP16}
  port: ${PT16}
  uuid: ${userID}
  udp: false
  tls: false
  network: ws
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}

- name: CF_V17_${IP17}_${PT17}
  type: vless
  server: ${IP17}
  port: ${PT17}
  uuid: ${userID}
  udp: false
  tls: false
  network: ws
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}

- name: CF_V18_${IP18}_${PT18}
  type: vless
  server: ${IP18}
  port: ${PT18}
  uuid: ${userID}
  udp: false
  tls: false
  network: ws
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}

- name: CF_V19_${IP19}_${PT19}
  type: vless
  server: ${IP19}
  port: ${PT19}
  uuid: ${userID}
  udp: false
  tls: false
  network: ws
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}

- name: CF_V20_${IP20}_${PT20}
  type: vless
  server: ${IP20}
  port: ${PT20}
  uuid: ${userID}
  udp: false
  tls: false
  network: ws
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}

- name: CF_V21_${IP21}_${PT21}
  type: vless
  server: ${IP21}
  port: ${PT21}
  uuid: ${userID}
  udp: false
  tls: false
  network: ws
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}

- name: CF_V22_${IP22}_${PT22}
  type: vless
  server: ${IP22}
  port: ${PT22}
  uuid: ${userID}
  udp: false
  tls: false
  network: ws
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}

- name: CF_V23_${IP23}_${PT23}
  type: vless
  server: ${IP23}
  port: ${PT23}
  uuid: ${userID}
  udp: false
  tls: false
  network: ws
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}

- name: CF_V24_${IP24}_${PT24}
  type: vless
  server: ${IP24}
  port: ${PT24}
  uuid: ${userID}
  udp: false
  tls: false
  network: ws
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}

- name: CF_V25_${IP25}_${PT25}
  type: vless
  server: ${IP25}
  port: ${PT25}
  uuid: ${userID}
  udp: false
  tls: false
  network: ws
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}

- name: CF_V26_${IP26}_${PT26}
  type: vless
  server: ${IP26}
  port: ${PT26}
  uuid: ${userID}
  udp: false
  tls: true
  network: ws
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}
      
- name: CF_V27_${IP27}_${PT27}
  type: vless
  server: ${IP27}
  port: ${PT27}
  uuid: ${userID}
  udp: false
  tls: true
  network: ws
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}
      
- name: CF_V28_${IP28}_${PT28}
  type: vless
  server: ${IP28}
  port: ${PT28}
  uuid: ${userID}
  udp: false
  tls: true
  network: ws
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}
      
- name: CF_V29_${IP29}_${PT29}
  type: vless
  server: ${IP29}
  port: ${PT29}
  uuid: ${userID}
  udp: false
  tls: true
  network: ws
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}
      
- name: CF_V30_${IP30}_${PT30}
  type: vless
  server: ${IP30}
  port: ${PT30}
  uuid: ${userID}
  udp: false
  tls: true
  network: ws
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}
      
- name: CF_V31_${IP31}_${PT31}
  type: vless
  server: ${IP31}
  port: ${PT31}
  uuid: ${userID}
  udp: false
  tls: true
  network: ws
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}
      
- name: CF_V32_${IP32}_${PT32}
  type: vless
  server: ${IP32}
  port: ${PT32}
  uuid: ${userID}
  udp: false
  tls: true
  network: ws
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}
      
- name: CF_V33_${IP33}_${PT33}
  type: vless
  server: ${IP33}
  port: ${PT33}
  uuid: ${userID}
  udp: false
  tls: true
  network: ws
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}
      
- name: CF_V34_${IP34}_${PT34}
  type: vless
  server: ${IP34}
  port: ${PT34}
  uuid: ${userID}
  udp: false
  tls: true
  network: ws
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}
      
- name: CF_V35_${IP35}_${PT35}
  type: vless
  server: ${IP35}
  port: ${PT35}
  uuid: ${userID}
  udp: false
  tls: true
  network: ws
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}
      
- name: CF_V36_${IP36}_${PT36}
  type: vless
  server: ${IP36}
  port: ${PT36}
  uuid: ${userID}
  udp: false
  tls: true
  network: ws
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}
      
- name: CF_V37_${IP37}_${PT37}
  type: vless
  server: ${IP37}
  port: ${PT37}
  uuid: ${userID}
  udp: false
  tls: true
  network: ws
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}
      
- name: CF_V38_${IP38}_${PT38}
  type: vless
  server: ${IP38}
  port: ${PT38}
  uuid: ${userID}
  udp: false
  tls: true
  network: ws
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}
      
- name: CF_V39_${IP39}_${PT39}
  type: vless
  server: ${IP39}
  port: ${PT39}
  uuid: ${userID}
  udp: false
  tls: true
  network: ws
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}
      
- name: CF_V40_${IP40}_${PT40}
  type: vless
  server: ${IP40}
  port: ${PT40}
  uuid: ${userID}
  udp: false
  tls: true
  network: ws
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}
      
- name: CF_V41_${IP41}_${PT41}
  type: vless
  server: ${IP41}
  port: ${PT41}
  uuid: ${userID}
  udp: false
  tls: true
  network: ws
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}
      
- name: CF_V42_${IP42}_${PT42}
  type: vless
  server: ${IP42}
  port: ${PT42}
  uuid: ${userID}
  udp: false
  tls: true
  network: ws
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}
      
- name: CF_V43_${IP43}_${PT43}
  type: vless
  server: ${IP43}
  port: ${PT43}
  uuid: ${userID}
  udp: false
  tls: true
  network: ws
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}
      
- name: CF_V44_${IP44}_${PT44}
  type: vless
  server: ${IP44}
  port: ${PT44}
  uuid: ${userID}
  udp: false
  tls: true
  network: ws
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}
      
- name: CF_V45_${IP45}_${PT45}
  type: vless
  server: ${IP45}
  port: ${PT45}
  uuid: ${userID}
  udp: false
  tls: true
  network: ws
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}
      
- name: CF_V46_${IP46}_${PT46}
  type: vless
  server: ${IP46}
  port: ${PT46}
  uuid: ${userID}
  udp: false
  tls: true
  network: ws
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}
      
- name: CF_V47_${IP47}_${PT47}
  type: vless
  server: ${IP47}
  port: ${PT47}
  uuid: ${userID}
  udp: false
  tls: true
  network: ws
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}
      
- name: CF_V48_${IP48}_${PT48}
  type: vless
  server: ${IP48}
  port: ${PT48}
  uuid: ${userID}
  udp: false
  tls: true
  network: ws
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}
      
- name: CF_V49_${IP49}_${PT49}
  type: vless
  server: ${IP49}
  port: ${PT49}
  uuid: ${userID}
  udp: false
  tls: true
  network: ws
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}
      
- name: CF_V50_${IP50}_${PT50}
  type: vless
  server: ${IP50}
  port: ${PT50}
  uuid: ${userID}
  udp: false
  tls: true
  network: ws
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}

proxy-groups:
- name: 负载均衡
  type: load-balance
  url: http://www.gstatic.com/generate_204
  interval: 300
  proxies:
    - CF_V1_${IP1}_${PT1}
    - CF_V2_${IP2}_${PT2}
    - CF_V3_${IP3}_${PT3}
    - CF_V4_${IP4}_${PT4}
    - CF_V5_${IP5}_${PT5}
    - CF_V6_${IP6}_${PT6}
    - CF_V7_${IP7}_${PT7}
    - CF_V8_${IP8}_${PT8}
    - CF_V9_${IP9}_${PT9}
    - CF_V10_${IP10}_${PT10}
    - CF_V11_${IP11}_${PT11}
    - CF_V12_${IP12}_${PT12}
    - CF_V13_${IP13}_${PT13}
    - CF_V14_${IP14}_${PT14}
    - CF_V15_${IP15}_${PT15}
    - CF_V16_${IP16}_${PT16}
    - CF_V17_${IP17}_${PT17}
    - CF_V18_${IP18}_${PT18}
    - CF_V19_${IP19}_${PT19}
    - CF_V20_${IP20}_${PT20}
    - CF_V21_${IP21}_${PT21}
    - CF_V22_${IP22}_${PT22}
    - CF_V23_${IP23}_${PT23}
    - CF_V24_${IP24}_${PT24}
    - CF_V25_${IP25}_${PT25}
    - CF_V26_${IP26}_${PT26}
    - CF_V27_${IP27}_${PT27}
    - CF_V28_${IP28}_${PT28}
    - CF_V29_${IP29}_${PT29}
    - CF_V30_${IP30}_${PT30}
    - CF_V31_${IP31}_${PT31}
    - CF_V32_${IP32}_${PT32}
    - CF_V33_${IP33}_${PT33}
    - CF_V34_${IP34}_${PT34}
    - CF_V35_${IP35}_${PT35}
    - CF_V36_${IP36}_${PT36}
    - CF_V37_${IP37}_${PT37}
    - CF_V38_${IP38}_${PT38}
    - CF_V39_${IP39}_${PT39}
    - CF_V40_${IP40}_${PT40}
    - CF_V41_${IP41}_${PT41}
    - CF_V42_${IP42}_${PT42}
    - CF_V43_${IP43}_${PT43}
    - CF_V44_${IP44}_${PT44}
    - CF_V45_${IP45}_${PT45}
    - CF_V46_${IP46}_${PT46}
    - CF_V47_${IP47}_${PT47}
    - CF_V48_${IP48}_${PT48}
    - CF_V49_${IP49}_${PT49}
    - CF_V50_${IP50}_${PT50}

- name: 自动选择
  type: url-test
  url: http://www.gstatic.com/generate_204
  interval: 300
  tolerance: 50
  proxies:
    - CF_V1_${IP1}_${PT1}
    - CF_V2_${IP2}_${PT2}
    - CF_V3_${IP3}_${PT3}
    - CF_V4_${IP4}_${PT4}
    - CF_V5_${IP5}_${PT5}
    - CF_V6_${IP6}_${PT6}
    - CF_V7_${IP7}_${PT7}
    - CF_V8_${IP8}_${PT8}
    - CF_V9_${IP9}_${PT9}
    - CF_V10_${IP10}_${PT10}
    - CF_V11_${IP11}_${PT11}
    - CF_V12_${IP12}_${PT12}
    - CF_V13_${IP13}_${PT13}
    - CF_V14_${IP14}_${PT14}
    - CF_V15_${IP15}_${PT15}
    - CF_V16_${IP16}_${PT16}
    - CF_V17_${IP17}_${PT17}
    - CF_V18_${IP18}_${PT18}
    - CF_V19_${IP19}_${PT19}
    - CF_V20_${IP20}_${PT20}
    - CF_V21_${IP21}_${PT21}
    - CF_V22_${IP22}_${PT22}
    - CF_V23_${IP23}_${PT23}
    - CF_V24_${IP24}_${PT24}
    - CF_V25_${IP25}_${PT25}
    - CF_V26_${IP26}_${PT26}
    - CF_V27_${IP27}_${PT27}
    - CF_V28_${IP28}_${PT28}
    - CF_V29_${IP29}_${PT29}
    - CF_V30_${IP30}_${PT30}
    - CF_V31_${IP31}_${PT31}
    - CF_V32_${IP32}_${PT32}
    - CF_V33_${IP33}_${PT33}
    - CF_V34_${IP34}_${PT34}
    - CF_V35_${IP35}_${PT35}
    - CF_V36_${IP36}_${PT36}
    - CF_V37_${IP37}_${PT37}
    - CF_V38_${IP38}_${PT38}
    - CF_V39_${IP39}_${PT39}
    - CF_V40_${IP40}_${PT40}
    - CF_V41_${IP41}_${PT41}
    - CF_V42_${IP42}_${PT42}
    - CF_V43_${IP43}_${PT43}
    - CF_V44_${IP44}_${PT44}
    - CF_V45_${IP45}_${PT45}
    - CF_V46_${IP46}_${PT46}
    - CF_V47_${IP47}_${PT47}
    - CF_V48_${IP48}_${PT48}
    - CF_V49_${IP49}_${PT49}
    - CF_V50_${IP50}_${PT50}

- name: 🌍选择代理
  type: select
  proxies:
    - 负载均衡
    - 自动选择
    - DIRECT
    - CF_V1_${IP1}_${PT1}
    - CF_V2_${IP2}_${PT2}
    - CF_V3_${IP3}_${PT3}
    - CF_V4_${IP4}_${PT4}
    - CF_V5_${IP5}_${PT5}
    - CF_V6_${IP6}_${PT6}
    - CF_V7_${IP7}_${PT7}
    - CF_V8_${IP8}_${PT8}
    - CF_V9_${IP9}_${PT9}
    - CF_V10_${IP10}_${PT10}
    - CF_V11_${IP11}_${PT11}
    - CF_V12_${IP12}_${PT12}
    - CF_V13_${IP13}_${PT13}
    - CF_V14_${IP14}_${PT14}
    - CF_V15_${IP15}_${PT15}
    - CF_V16_${IP16}_${PT16}
    - CF_V17_${IP17}_${PT17}
    - CF_V18_${IP18}_${PT18}
    - CF_V19_${IP19}_${PT19}
    - CF_V20_${IP20}_${PT20}
    - CF_V21_${IP21}_${PT21}
    - CF_V22_${IP22}_${PT22}
    - CF_V23_${IP23}_${PT23}
    - CF_V24_${IP24}_${PT24}
    - CF_V25_${IP25}_${PT25}
    - CF_V26_${IP26}_${PT26}
    - CF_V27_${IP27}_${PT27}
    - CF_V28_${IP28}_${PT28}
    - CF_V29_${IP29}_${PT29}
    - CF_V30_${IP30}_${PT30}
    - CF_V31_${IP31}_${PT31}
    - CF_V32_${IP32}_${PT32}
    - CF_V33_${IP33}_${PT33}
    - CF_V34_${IP34}_${PT34}
    - CF_V35_${IP35}_${PT35}
    - CF_V36_${IP36}_${PT36}
    - CF_V37_${IP37}_${PT37}
    - CF_V38_${IP38}_${PT38}
    - CF_V39_${IP39}_${PT39}
    - CF_V40_${IP40}_${PT40}
    - CF_V41_${IP41}_${PT41}
    - CF_V42_${IP42}_${PT42}
    - CF_V43_${IP43}_${PT43}
    - CF_V44_${IP44}_${PT44}
    - CF_V45_${IP45}_${PT45}
    - CF_V46_${IP46}_${PT46}
    - CF_V47_${IP47}_${PT47}
    - CF_V48_${IP48}_${PT48}
    - CF_V49_${IP49}_${PT49}
    - CF_V50_${IP50}_${PT50}

rules:
  - GEOIP,LAN,DIRECT
  - GEOIP,CN,DIRECT
  - MATCH,🌍选择代理`
}
	
function getsbConfig(userID, hostName) {
return `{
	  "log": {
		"disabled": false,
		"level": "info",
		"timestamp": true
	  },
	  "experimental": {
		"clash_api": {
		  "external_controller": "127.0.0.1:9090",
		  "external_ui": "ui",
		  "external_ui_download_url": "",
		  "external_ui_download_detour": "",
		  "secret": "",
		  "default_mode": "Rule"
		},
		"cache_file": {
		  "enabled": true,
		  "path": "cache.db",
		  "store_fakeip": true
		}
	  },
	  "dns": {
		"servers": [
		  {
			"tag": "proxydns",
			"address": "tls://8.8.8.8/dns-query",
			"detour": "select"
		  },
		  {
			"tag": "localdns",
			"address": "h3://223.5.5.5/dns-query",
			"detour": "direct"
		  },
		  {
			"address": "rcode://refused",
			"tag": "block"
		  },
		  {
			"tag": "dns_fakeip",
			"address": "fakeip"
		  }
		],
		"rules": [
		  {
			"outbound": "any",
			"server": "localdns",
			"disable_cache": true
		  },
		  {
			"clash_mode": "Global",
			"server": "proxydns"
		  },
		  {
			"clash_mode": "Direct",
			"server": "localdns"
		  },
		  {
			"rule_set": "geosite-cn",
			"server": "localdns"
		  },
		  {
			"rule_set": "geosite-geolocation-!cn",
			"server": "proxydns"
		  },
		  {
			"rule_set": "geosite-geolocation-!cn",
			"query_type": [
			  "A",
			  "AAAA"
			],
			"server": "dns_fakeip"
		  }
		],
		"fakeip": {
		  "enabled": true,
		  "inet4_range": "198.18.0.0/15",
		  "inet6_range": "fc00::/18"
		},
		"independent_cache": true,
		"final": "proxydns"
	  },
	  "inbounds": [
		{
		  "type": "tun",
		  "inet4_address": "172.19.0.1/30",
		  "inet6_address": "fd00::1/126",
		  "auto_route": true,
		  "strict_route": true,
		  "sniff": true,
		  "sniff_override_destination": true,
		  "domain_strategy": "prefer_ipv4"
		}
	  ],
	  "outbounds": [
		{
		  "tag": "select",
		  "type": "selector",
		  "default": "auto",
		  "outbounds": [
			"auto",
        "CF_V1_${IP1}_${PT1}",
        "CF_V2_${IP2}_${PT2}",
        "CF_V3_${IP3}_${PT3}",
        "CF_V4_${IP4}_${PT4}",
        "CF_V5_${IP5}_${PT5}",
        "CF_V6_${IP6}_${PT6}",
        "CF_V7_${IP7}_${PT7}",
        "CF_V8_${IP8}_${PT8}",
        "CF_V9_${IP9}_${PT9}",
        "CF_V10_${IP10}_${PT10}",
        "CF_V11_${IP11}_${PT11}",
        "CF_V12_${IP12}_${PT12}",
        "CF_V13_${IP13}_${PT13}",
        "CF_V14_${IP14}_${PT14}",
        "CF_V15_${IP15}_${PT15}",
        "CF_V16_${IP16}_${PT16}",
        "CF_V17_${IP17}_${PT17}",
        "CF_V18_${IP18}_${PT18}",
        "CF_V19_${IP19}_${PT19}",
        "CF_V20_${IP20}_${PT20}",
        "CF_V21_${IP21}_${PT21}",
        "CF_V22_${IP22}_${PT22}",
        "CF_V23_${IP23}_${PT23}",
        "CF_V24_${IP24}_${PT24}",
        "CF_V25_${IP25}_${PT25}",
        "CF_V26_${IP26}_${PT26}",
        "CF_V27_${IP27}_${PT27}",
        "CF_V28_${IP28}_${PT28}",
        "CF_V29_${IP29}_${PT29}",
        "CF_V30_${IP30}_${PT30}",
        "CF_V31_${IP31}_${PT31}",
        "CF_V32_${IP32}_${PT32}",
        "CF_V33_${IP33}_${PT33}",
        "CF_V34_${IP34}_${PT34}",
        "CF_V35_${IP35}_${PT35}",
        "CF_V36_${IP36}_${PT36}",
        "CF_V37_${IP37}_${PT37}",
        "CF_V38_${IP38}_${PT38}",
        "CF_V39_${IP39}_${PT39}",
        "CF_V40_${IP40}_${PT40}",
        "CF_V41_${IP41}_${PT41}",
        "CF_V42_${IP42}_${PT42}",
        "CF_V43_${IP43}_${PT43}",
        "CF_V44_${IP44}_${PT44}",
        "CF_V45_${IP45}_${PT45}",
        "CF_V46_${IP46}_${PT46}",
        "CF_V47_${IP47}_${PT47}",
        "CF_V48_${IP48}_${PT48}",
        "CF_V49_${IP49}_${PT49}",
        "CF_V50_${IP50}_${PT50}"
		  ]
		},
		        {
          "server": "${IP1}",
          "server_port": ${PT1},
          "tag": "CF_V1_${IP1}_${PT1}",
          "packet_encoding": "packetaddr",
          "transport": {
            "headers": {
              "Host": [
                "${hostName}"
              ]
            },
            "path": "/?ed=2560",
            "type": "ws"
          },
          "type": "vless",
          "uuid": "${userID}"
        },
		        {
          "server": "${IP2}",
          "server_port": ${PT2},
          "tag": "CF_V2_${IP2}_${PT2}",
          "packet_encoding": "packetaddr",
          "transport": {
            "headers": {
              "Host": [
                "${hostName}"
              ]
            },
            "path": "/?ed=2560",
            "type": "ws"
          },
          "type": "vless",
          "uuid": "${userID}"
        }, 
		       {
          "server": "${IP3}",
          "server_port": ${PT3},
          "tag": "CF_V3_${IP3}_${PT3}",
          "packet_encoding": "packetaddr",
          "transport": {
            "headers": {
              "Host": [
                "${hostName}"
              ]
            },
            "path": "/?ed=2560",
            "type": "ws"
          },
          "type": "vless",
          "uuid": "${userID}"
        }, 
		       {
          "server": "${IP4}",
          "server_port": ${PT4},
          "tag": "CF_V4_${IP4}_${PT4}",
          "packet_encoding": "packetaddr",
          "transport": {
            "headers": {
              "Host": [
                "${hostName}"
              ]
            },
            "path": "/?ed=2560",
            "type": "ws"
          },
          "type": "vless",
          "uuid": "${userID}"
        },
		        {
          "server": "${IP5}",
          "server_port": ${PT5},
          "tag": "CF_V5_${IP5}_${PT5}",
          "packet_encoding": "packetaddr",
          "transport": {
            "headers": {
              "Host": [
                "${hostName}"
              ]
            },
            "path": "/?ed=2560",
            "type": "ws"
          },
          "type": "vless",
          "uuid": "${userID}"
        },  
		      {
          "server": "${IP6}",
          "server_port": ${PT6},
          "tag": "CF_V6_${IP6}_${PT6}",
          "packet_encoding": "packetaddr",
          "transport": {
            "headers": {
              "Host": [
                "${hostName}"
              ]
            },
            "path": "/?ed=2560",
            "type": "ws"
          },
          "type": "vless",
          "uuid": "${userID}"
        },
		        {
          "server": "${IP7}",
          "server_port": ${PT7},
          "tag": "CF_V7_${IP7}_${PT7}",
          "packet_encoding": "packetaddr",
          "transport": {
            "headers": {
              "Host": [
                "${hostName}"
              ]
            },
            "path": "/?ed=2560",
            "type": "ws"
          },
          "type": "vless",
          "uuid": "${userID}"
        },
		        {
          "server": "${IP8}",
          "server_port": ${PT8},
          "tag": "CF_V8_${IP8}_${PT8}",
          "packet_encoding": "packetaddr",
          "transport": {
            "headers": {
              "Host": [
                "${hostName}"
              ]
            },
            "path": "/?ed=2560",
            "type": "ws"
          },
          "type": "vless",
          "uuid": "${userID}"
        },
		        {
          "server": "${IP9}",
          "server_port": ${PT9},
          "tag": "CF_V9_${IP9}_${PT9}",
          "packet_encoding": "packetaddr",
          "transport": {
            "headers": {
              "Host": [
                "${hostName}"
              ]
            },
            "path": "/?ed=2560",
            "type": "ws"
          },
          "type": "vless",
          "uuid": "${userID}"
        },
		        {
          "server": "${IP10}",
          "server_port": ${PT10},
          "tag": "CF_V10_${IP10}_${PT10}",
          "packet_encoding": "packetaddr",
          "transport": {
            "headers": {
              "Host": [
                "${hostName}"
              ]
            },
            "path": "/?ed=2560",
            "type": "ws"
          },
          "type": "vless",
          "uuid": "${userID}"
        },
		        {
          "server": "${IP11}",
          "server_port": ${PT11},
          "tag": "CF_V11_${IP11}_${PT11}",
          "packet_encoding": "packetaddr",
          "transport": {
            "headers": {
              "Host": [
                "${hostName}"
              ]
            },
            "path": "/?ed=2560",
            "type": "ws"
          },
          "type": "vless",
          "uuid": "${userID}"
        },
		        {
          "server": "${IP12}",
          "server_port": ${PT12},
          "tag": "CF_V12_${IP12}_${PT12}",
          "packet_encoding": "packetaddr",
          "transport": {
            "headers": {
              "Host": [
                "${hostName}"
              ]
            },
            "path": "/?ed=2560",
            "type": "ws"
          },
          "type": "vless",
          "uuid": "${userID}"
        },
		        {
          "server": "${IP13}",
          "server_port": ${PT13},
          "tag": "CF_V13_${IP13}_${PT13}",
          "packet_encoding": "packetaddr",
          "transport": {
            "headers": {
              "Host": [
                "${hostName}"
              ]
            },
            "path": "/?ed=2560",
            "type": "ws"
          },
          "type": "vless",
          "uuid": "${userID}"
        },
		        {
          "server": "${IP14}",
          "server_port": ${PT14},
          "tag": "CF_V14_${IP14}_${PT14}",
          "packet_encoding": "packetaddr",
          "transport": {
            "headers": {
              "Host": [
                "${hostName}"
              ]
            },
            "path": "/?ed=2560",
            "type": "ws"
          },
          "type": "vless",
          "uuid": "${userID}"
        },
		        {
          "server": "${IP15}",
          "server_port": ${PT15},
          "tag": "CF_V15_${IP15}_${PT15}",
          "packet_encoding": "packetaddr",
          "transport": {
            "headers": {
              "Host": [
                "${hostName}"
              ]
            },
            "path": "/?ed=2560",
            "type": "ws"
          },
          "type": "vless",
          "uuid": "${userID}"
        },
		        {
          "server": "${IP16}",
          "server_port": ${PT16},
          "tag": "CF_V16_${IP16}_${PT16}",
          "packet_encoding": "packetaddr",
          "transport": {
            "headers": {
              "Host": [
                "${hostName}"
              ]
            },
            "path": "/?ed=2560",
            "type": "ws"
          },
          "type": "vless",
          "uuid": "${userID}"
        },
		        {
          "server": "${IP17}",
          "server_port": ${PT17},
          "tag": "CF_V17_${IP17}_${PT17}",
          "packet_encoding": "packetaddr",
          "transport": {
            "headers": {
              "Host": [
                "${hostName}"
              ]
            },
            "path": "/?ed=2560",
            "type": "ws"
          },
          "type": "vless",
          "uuid": "${userID}"
        },
		        {
          "server": "${IP18}",
          "server_port": ${PT18},
          "tag": "CF_V18_${IP18}_${PT18}",
          "packet_encoding": "packetaddr",
          "transport": {
            "headers": {
              "Host": [
                "${hostName}"
              ]
            },
            "path": "/?ed=2560",
            "type": "ws"
          },
          "type": "vless",
          "uuid": "${userID}"
        },
		        {
          "server": "${IP19}",
          "server_port": ${PT19},
          "tag": "CF_V19_${IP19}_${PT19}",
          "packet_encoding": "packetaddr",
          "transport": {
            "headers": {
              "Host": [
                "${hostName}"
              ]
            },
            "path": "/?ed=2560",
            "type": "ws"
          },
          "type": "vless",
          "uuid": "${userID}"
        },
		        {
          "server": "${IP20}",
          "server_port": ${PT20},
          "tag": "CF_V20_${IP20}_${PT20}",
          "packet_encoding": "packetaddr",
          "transport": {
            "headers": {
              "Host": [
                "${hostName}"
              ]
            },
            "path": "/?ed=2560",
            "type": "ws"
          },
          "type": "vless",
          "uuid": "${userID}"
        },
		        {
          "server": "${IP21}",
          "server_port": ${PT21},
          "tag": "CF_V21_${IP21}_${PT21}",
          "packet_encoding": "packetaddr",
          "transport": {
            "headers": {
              "Host": [
                "${hostName}"
              ]
            },
            "path": "/?ed=2560",
            "type": "ws"
          },
          "type": "vless",
          "uuid": "${userID}"
        },
		        {
          "server": "${IP22}",
          "server_port": ${PT22},
          "tag": "CF_V22_${IP22}_${PT22}",
          "packet_encoding": "packetaddr",
          "transport": {
            "headers": {
              "Host": [
                "${hostName}"
              ]
            },
            "path": "/?ed=2560",
            "type": "ws"
          },
          "type": "vless",
          "uuid": "${userID}"
        },
		        {
          "server": "${IP23}",
          "server_port": ${PT23},
          "tag": "CF_V23_${IP23}_${PT23}",
          "packet_encoding": "packetaddr",
          "transport": {
            "headers": {
              "Host": [
                "${hostName}"
              ]
            },
            "path": "/?ed=2560",
            "type": "ws"
          },
          "type": "vless",
          "uuid": "${userID}"
        },
		        {
          "server": "${IP24}",
          "server_port": ${PT24},
          "tag": "CF_V24_${IP24}_${PT24}",
          "packet_encoding": "packetaddr",
          "transport": {
            "headers": {
              "Host": [
                "${hostName}"
              ]
            },
            "path": "/?ed=2560",
            "type": "ws"
          },
          "type": "vless",
          "uuid": "${userID}"
        },
		        {
          "server": "${IP25}",
          "server_port": ${PT25},
          "tag": "CF_V25_${IP25}_${PT25}",
          "packet_encoding": "packetaddr",
          "transport": {
            "headers": {
              "Host": [
                "${hostName}"
              ]
            },
            "path": "/?ed=2560",
            "type": "ws"
          },
          "type": "vless",
          "uuid": "${userID}"
        },
		{     
		  "server": "${IP26}",
		  "server_port": ${PT26},
		  "tag": "CF_V26_${IP26}_${PT26}",
		  "tls": {
			"enabled": true,
			"server_name": "${hostName}",
			"insecure": false,
			"utls": {
			  "enabled": true,
			  "fingerprint": "chrome"
			}
		  },
		  "packet_encoding": "packetaddr",
		  "transport": {
			"headers": {
			  "Host": [
				"${hostName}"
			  ]
			},
			"path": "/?ed=2560",
			"type": "ws"
		  },
		  "type": "vless",
		  "uuid": "${userID}"
		},
		{
		  "server": "${IP27}",
		  "server_port": ${PT27},
		  "tag": "CF_V27_${IP27}_${PT27}",
		  "tls": {
			"enabled": true,
			"server_name": "${hostName}",
			"insecure": false,
			"utls": {
			  "enabled": true,
			  "fingerprint": "chrome"
			}
		  },
		  "packet_encoding": "packetaddr",
		  "transport": {
			"headers": {
			  "Host": [
				"${hostName}"
			  ]
			},
			"path": "/?ed=2560",
			"type": "ws"
		  },
		  "type": "vless",
		  "uuid": "${userID}"
		},
		{
		  "server": "${IP28}",
		  "server_port": ${PT28},
		  "tag": "CF_V28_${IP28}_${PT28}",
		  "tls": {
			"enabled": true,
			"server_name": "${hostName}",
			"insecure": false,
			"utls": {
			  "enabled": true,
			  "fingerprint": "chrome"
			}
		  },
		  "packet_encoding": "packetaddr",
		  "transport": {
			"headers": {
			  "Host": [
				"${hostName}"
			  ]
			},
			"path": "/?ed=2560",
			"type": "ws"
		  },
		  "type": "vless",
		  "uuid": "${userID}"
		},
		{
		  "server": "${IP29}",
		  "server_port": ${PT29},
		  "tag": "CF_V29_${IP29}_${PT29}",
		  "tls": {
			"enabled": true,
			"server_name": "${hostName}",
			"insecure": false,
			"utls": {
			  "enabled": true,
			  "fingerprint": "chrome"
			}
		  },
		  "packet_encoding": "packetaddr",
		  "transport": {
			"headers": {
			  "Host": [
				"${hostName}"
			  ]
			},
			"path": "/?ed=2560",
			"type": "ws"
		  },
		  "type": "vless",
		  "uuid": "${userID}"
		},
		{
		  "server": "${IP30}",
		  "server_port": ${PT30},
		  "tag": "CF_V30_${IP30}_${PT30}",
		  "tls": {
			"enabled": true,
			"server_name": "${hostName}",
			"insecure": false,
			"utls": {
			  "enabled": true,
			  "fingerprint": "chrome"
			}
		  },
		  "packet_encoding": "packetaddr",
		  "transport": {
			"headers": {
			  "Host": [
				"${hostName}"
			  ]
			},
			"path": "/?ed=2560",
			"type": "ws"
		  },
		  "type": "vless",
		  "uuid": "${userID}"
		},
		{
		  "server": "${IP31}",
		  "server_port": ${PT31},
		  "tag": "CF_V31_${IP31}_${PT31}",
		  "tls": {
			"enabled": true,
			"server_name": "${hostName}",
			"insecure": false,
			"utls": {
			  "enabled": true,
			  "fingerprint": "chrome"
			}
		  },
		  "packet_encoding": "packetaddr",
		  "transport": {
			"headers": {
			  "Host": [
				"${hostName}"
			  ]
			},
			"path": "/?ed=2560",
			"type": "ws"
		  },
		  "type": "vless",
		  "uuid": "${userID}"
		},
				{
		  "server": "${IP32}",
		  "server_port": ${PT32},
		  "tag": "CF_V32_${IP32}_${PT32}",
		  "tls": {
			"enabled": true,
			"server_name": "${hostName}",
			"insecure": false,
			"utls": {
			  "enabled": true,
			  "fingerprint": "chrome"
			}
		  },
		  "packet_encoding": "packetaddr",
		  "transport": {
			"headers": {
			  "Host": [
				"${hostName}"
			  ]
			},
			"path": "/?ed=2560",
			"type": "ws"
		  },
		  "type": "vless",
		  "uuid": "${userID}"
		},
				{
		  "server": "${IP33}",
		  "server_port": ${PT33},
		  "tag": "CF_V33_${IP33}_${PT33}",
		  "tls": {
			"enabled": true,
			"server_name": "${hostName}",
			"insecure": false,
			"utls": {
			  "enabled": true,
			  "fingerprint": "chrome"
			}
		  },
		  "packet_encoding": "packetaddr",
		  "transport": {
			"headers": {
			  "Host": [
				"${hostName}"
			  ]
			},
			"path": "/?ed=2560",
			"type": "ws"
		  },
		  "type": "vless",
		  "uuid": "${userID}"
		},
				{
		  "server": "${IP34}",
		  "server_port": ${PT34},
		  "tag": "CF_V34_${IP34}_${PT34}",
		  "tls": {
			"enabled": true,
			"server_name": "${hostName}",
			"insecure": false,
			"utls": {
			  "enabled": true,
			  "fingerprint": "chrome"
			}
		  },
		  "packet_encoding": "packetaddr",
		  "transport": {
			"headers": {
			  "Host": [
				"${hostName}"
			  ]
			},
			"path": "/?ed=2560",
			"type": "ws"
		  },
		  "type": "vless",
		  "uuid": "${userID}"
		},
				{
		  "server": "${IP35}",
		  "server_port": ${PT35},
		  "tag": "CF_V35_${IP35}_${PT35}",
		  "tls": {
			"enabled": true,
			"server_name": "${hostName}",
			"insecure": false,
			"utls": {
			  "enabled": true,
			  "fingerprint": "chrome"
			}
		  },
		  "packet_encoding": "packetaddr",
		  "transport": {
			"headers": {
			  "Host": [
				"${hostName}"
			  ]
			},
			"path": "/?ed=2560",
			"type": "ws"
		  },
		  "type": "vless",
		  "uuid": "${userID}"
		},
				{
		  "server": "${IP36}",
		  "server_port": ${PT36},
		  "tag": "CF_V36_${IP36}_${PT36}",
		  "tls": {
			"enabled": true,
			"server_name": "${hostName}",
			"insecure": false,
			"utls": {
			  "enabled": true,
			  "fingerprint": "chrome"
			}
		  },
		  "packet_encoding": "packetaddr",
		  "transport": {
			"headers": {
			  "Host": [
				"${hostName}"
			  ]
			},
			"path": "/?ed=2560",
			"type": "ws"
		  },
		  "type": "vless",
		  "uuid": "${userID}"
		},
				{
		  "server": "${IP37}",
		  "server_port": ${PT37},
		  "tag": "CF_V37_${IP37}_${PT37}",
		  "tls": {
			"enabled": true,
			"server_name": "${hostName}",
			"insecure": false,
			"utls": {
			  "enabled": true,
			  "fingerprint": "chrome"
			}
		  },
		  "packet_encoding": "packetaddr",
		  "transport": {
			"headers": {
			  "Host": [
				"${hostName}"
			  ]
			},
			"path": "/?ed=2560",
			"type": "ws"
		  },
		  "type": "vless",
		  "uuid": "${userID}"
		},
				{
		  "server": "${IP38}",
		  "server_port": ${PT38},
		  "tag": "CF_V38_${IP38}_${PT38}",
		  "tls": {
			"enabled": true,
			"server_name": "${hostName}",
			"insecure": false,
			"utls": {
			  "enabled": true,
			  "fingerprint": "chrome"
			}
		  },
		  "packet_encoding": "packetaddr",
		  "transport": {
			"headers": {
			  "Host": [
				"${hostName}"
			  ]
			},
			"path": "/?ed=2560",
			"type": "ws"
		  },
		  "type": "vless",
		  "uuid": "${userID}"
		},
				{
		  "server": "${IP39}",
		  "server_port": ${PT39},
		  "tag": "CF_V39_${IP39}_${PT39}",
		  "tls": {
			"enabled": true,
			"server_name": "${hostName}",
			"insecure": false,
			"utls": {
			  "enabled": true,
			  "fingerprint": "chrome"
			}
		  },
		  "packet_encoding": "packetaddr",
		  "transport": {
			"headers": {
			  "Host": [
				"${hostName}"
			  ]
			},
			"path": "/?ed=2560",
			"type": "ws"
		  },
		  "type": "vless",
		  "uuid": "${userID}"
		},
				{
		  "server": "${IP40}",
		  "server_port": ${PT40},
		  "tag": "CF_V40_${IP40}_${PT40}",
		  "tls": {
			"enabled": true,
			"server_name": "${hostName}",
			"insecure": false,
			"utls": {
			  "enabled": true,
			  "fingerprint": "chrome"
			}
		  },
		  "packet_encoding": "packetaddr",
		  "transport": {
			"headers": {
			  "Host": [
				"${hostName}"
			  ]
			},
			"path": "/?ed=2560",
			"type": "ws"
		  },
		  "type": "vless",
		  "uuid": "${userID}"
		},
				{
		  "server": "${IP41}",
		  "server_port": ${PT41},
		  "tag": "CF_V41_${IP41}_${PT41}",
		  "tls": {
			"enabled": true,
			"server_name": "${hostName}",
			"insecure": false,
			"utls": {
			  "enabled": true,
			  "fingerprint": "chrome"
			}
		  },
		  "packet_encoding": "packetaddr",
		  "transport": {
			"headers": {
			  "Host": [
				"${hostName}"
			  ]
			},
			"path": "/?ed=2560",
			"type": "ws"
		  },
		  "type": "vless",
		  "uuid": "${userID}"
		},
				{
		  "server": "${IP42}",
		  "server_port": ${PT42},
		  "tag": "CF_V42_${IP42}_${PT42}",
		  "tls": {
			"enabled": true,
			"server_name": "${hostName}",
			"insecure": false,
			"utls": {
			  "enabled": true,
			  "fingerprint": "chrome"
			}
		  },
		  "packet_encoding": "packetaddr",
		  "transport": {
			"headers": {
			  "Host": [
				"${hostName}"
			  ]
			},
			"path": "/?ed=2560",
			"type": "ws"
		  },
		  "type": "vless",
		  "uuid": "${userID}"
		},
				{
		  "server": "${IP43}",
		  "server_port": ${PT43},
		  "tag": "CF_V43_${IP43}_${PT43}",
		  "tls": {
			"enabled": true,
			"server_name": "${hostName}",
			"insecure": false,
			"utls": {
			  "enabled": true,
			  "fingerprint": "chrome"
			}
		  },
		  "packet_encoding": "packetaddr",
		  "transport": {
			"headers": {
			  "Host": [
				"${hostName}"
			  ]
			},
			"path": "/?ed=2560",
			"type": "ws"
		  },
		  "type": "vless",
		  "uuid": "${userID}"
		},
				{
		  "server": "${IP44}",
		  "server_port": ${PT44},
		  "tag": "CF_V44_${IP44}_${PT44}",
		  "tls": {
			"enabled": true,
			"server_name": "${hostName}",
			"insecure": false,
			"utls": {
			  "enabled": true,
			  "fingerprint": "chrome"
			}
		  },
		  "packet_encoding": "packetaddr",
		  "transport": {
			"headers": {
			  "Host": [
				"${hostName}"
			  ]
			},
			"path": "/?ed=2560",
			"type": "ws"
		  },
		  "type": "vless",
		  "uuid": "${userID}"
		},
				{
		  "server": "${IP45}",
		  "server_port": ${PT45},
		  "tag": "CF_V45_${IP45}_${PT45}",
		  "tls": {
			"enabled": true,
			"server_name": "${hostName}",
			"insecure": false,
			"utls": {
			  "enabled": true,
			  "fingerprint": "chrome"
			}
		  },
		  "packet_encoding": "packetaddr",
		  "transport": {
			"headers": {
			  "Host": [
				"${hostName}"
			  ]
			},
			"path": "/?ed=2560",
			"type": "ws"
		  },
		  "type": "vless",
		  "uuid": "${userID}"
		},
				{
		  "server": "${IP46}",
		  "server_port": ${PT46},
		  "tag": "CF_V46_${IP46}_${PT46}",
		  "tls": {
			"enabled": true,
			"server_name": "${hostName}",
			"insecure": false,
			"utls": {
			  "enabled": true,
			  "fingerprint": "chrome"
			}
		  },
		  "packet_encoding": "packetaddr",
		  "transport": {
			"headers": {
			  "Host": [
				"${hostName}"
			  ]
			},
			"path": "/?ed=2560",
			"type": "ws"
		  },
		  "type": "vless",
		  "uuid": "${userID}"
		},
				{
		  "server": "${IP47}",
		  "server_port": ${PT47},
		  "tag": "CF_V47_${IP47}_${PT47}",
		  "tls": {
			"enabled": true,
			"server_name": "${hostName}",
			"insecure": false,
			"utls": {
			  "enabled": true,
			  "fingerprint": "chrome"
			}
		  },
		  "packet_encoding": "packetaddr",
		  "transport": {
			"headers": {
			  "Host": [
				"${hostName}"
			  ]
			},
			"path": "/?ed=2560",
			"type": "ws"
		  },
		  "type": "vless",
		  "uuid": "${userID}"
		},
				{
		  "server": "${IP48}",
		  "server_port": ${PT48},
		  "tag": "CF_V48_${IP48}_${PT48}",
		  "tls": {
			"enabled": true,
			"server_name": "${hostName}",
			"insecure": false,
			"utls": {
			  "enabled": true,
			  "fingerprint": "chrome"
			}
		  },
		  "packet_encoding": "packetaddr",
		  "transport": {
			"headers": {
			  "Host": [
				"${hostName}"
			  ]
			},
			"path": "/?ed=2560",
			"type": "ws"
		  },
		  "type": "vless",
		  "uuid": "${userID}"
		},
				{
		  "server": "${IP49}",
		  "server_port": ${PT49},
		  "tag": "CF_V49_${IP49}_${PT49}",
		  "tls": {
			"enabled": true,
			"server_name": "${hostName}",
			"insecure": false,
			"utls": {
			  "enabled": true,
			  "fingerprint": "chrome"
			}
		  },
		  "packet_encoding": "packetaddr",
		  "transport": {
			"headers": {
			  "Host": [
				"${hostName}"
			  ]
			},
			"path": "/?ed=2560",
			"type": "ws"
		  },
		  "type": "vless",
		  "uuid": "${userID}"
		},
				{
		  "server": "${IP50}",
		  "server_port": ${PT50},
		  "tag": "CF_V50_${IP50}_${PT50}",
		  "tls": {
			"enabled": true,
			"server_name": "${hostName}",
			"insecure": false,
			"utls": {
			  "enabled": true,
			  "fingerprint": "chrome"
			}
		  },
		  "packet_encoding": "packetaddr",
		  "transport": {
			"headers": {
			  "Host": [
				"${hostName}"
			  ]
			},
			"path": "/?ed=2560",
			"type": "ws"
		  },
		  "type": "vless",
		  "uuid": "${userID}"
		},
		{
		  "tag": "direct",
		  "type": "direct"
		},
		{
		  "tag": "block",
		  "type": "block"
		},
		{
		  "tag": "dns-out",
		  "type": "dns"
		},
		{
		  "tag": "auto",
		  "type": "urltest",
		  "outbounds": [
        "CF_V1_${IP1}_${PT1}",
        "CF_V2_${IP2}_${PT2}",
        "CF_V3_${IP3}_${PT3}",
        "CF_V4_${IP4}_${PT4}",
        "CF_V5_${IP5}_${PT5}",
        "CF_V6_${IP6}_${PT6}",
        "CF_V7_${IP7}_${PT7}",
        "CF_V8_${IP8}_${PT8}",
        "CF_V9_${IP9}_${PT9}",
        "CF_V10_${IP10}_${PT10}",
        "CF_V11_${IP11}_${PT11}",
        "CF_V12_${IP12}_${PT12}",
        "CF_V13_${IP13}_${PT13}",
        "CF_V14_${IP14}_${PT14}",
        "CF_V15_${IP15}_${PT15}",
        "CF_V16_${IP16}_${PT16}",
        "CF_V17_${IP17}_${PT17}",
        "CF_V18_${IP18}_${PT18}",
        "CF_V19_${IP19}_${PT19}",
        "CF_V20_${IP20}_${PT20}",
        "CF_V21_${IP21}_${PT21}",
        "CF_V22_${IP22}_${PT22}",
        "CF_V23_${IP23}_${PT23}",
        "CF_V24_${IP24}_${PT24}",
        "CF_V25_${IP25}_${PT25}",
        "CF_V26_${IP26}_${PT26}",
        "CF_V27_${IP27}_${PT27}",
        "CF_V28_${IP28}_${PT28}",
        "CF_V29_${IP29}_${PT29}",
        "CF_V30_${IP30}_${PT30}",
        "CF_V31_${IP31}_${PT31}",
        "CF_V32_${IP32}_${PT32}",
        "CF_V33_${IP33}_${PT33}",
        "CF_V34_${IP34}_${PT34}",
        "CF_V35_${IP35}_${PT35}",
        "CF_V36_${IP36}_${PT36}",
        "CF_V37_${IP37}_${PT37}",
        "CF_V38_${IP38}_${PT38}",
        "CF_V39_${IP39}_${PT39}",
        "CF_V40_${IP40}_${PT40}",
        "CF_V41_${IP41}_${PT41}",
        "CF_V42_${IP42}_${PT42}",
        "CF_V43_${IP43}_${PT43}",
        "CF_V44_${IP44}_${PT44}",
        "CF_V45_${IP45}_${PT45}",
        "CF_V46_${IP46}_${PT46}",
        "CF_V47_${IP47}_${PT47}",
        "CF_V48_${IP48}_${PT48}",
        "CF_V49_${IP49}_${PT49}",
        "CF_V50_${IP50}_${PT50}"
		  ],
		  "url": "https://www.gstatic.com/generate_204",
		  "interval": "1m",
		  "tolerance": 50,
		  "interrupt_exist_connections": false
		}
	  ],
	  "route": {
		"rule_set": [
		  {
			"tag": "geosite-geolocation-!cn",
			"type": "remote",
			"format": "binary",
			"url": "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geosite/geolocation-!cn.srs",
			"download_detour": "select",
			"update_interval": "1d"
		  },
		  {
			"tag": "geosite-cn",
			"type": "remote",
			"format": "binary",
			"url": "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geosite/geolocation-cn.srs",
			"download_detour": "select",
			"update_interval": "1d"
		  },
		  {
			"tag": "geoip-cn",
			"type": "remote",
			"format": "binary",
			"url": "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geoip/cn.srs",
			"download_detour": "select",
			"update_interval": "1d"
		  }
		],
		"auto_detect_interface": true,
		"final": "select",
		"rules": [
		  {
			"outbound": "dns-out",
			"protocol": "dns"
		  },
		  {
			"clash_mode": "Direct",
			"outbound": "direct"
		  },
		  {
			"clash_mode": "Global",
			"outbound": "select"
		  },
		  {
			"rule_set": "geoip-cn",
			"outbound": "direct"
		  },
		  {
			"rule_set": "geosite-cn",
			"outbound": "direct"
		  },
		  {
			"ip_is_private": true,
			"outbound": "direct"
		  },
		  {
			"rule_set": "geosite-geolocation-!cn",
			"outbound": "select"
		  }
		]
	  },
	  "ntp": {
		"enabled": true,
		"server": "time.apple.com",
		"server_port": 123,
		"interval": "30m",
		"detour": "direct"
	  }
	}`
}

function getptyConfig(userID, hostName) {
	const vlessshare = btoa(`vless\u003A//${userID}\u0040${IP8}:${PT8}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V8_${IP8}_${PT8}\nvless\u003A//${userID}\u0040${IP9}:${PT9}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V9_${IP9}_${PT9}\nvless\u003A//${userID}\u0040${IP10}:${PT10}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V10_${IP10}_${PT10}\nvless\u003A//${userID}\u0040${IP11}:${PT11}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V11_${IP11}_${PT11}\nvless\u003A//${userID}\u0040${IP12}:${PT12}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V12_${IP12}_${PT12}\nvless\u003A//${userID}\u0040${IP13}:${PT13}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V13_${IP13}_${PT13}`);	
		return `${vlessshare}`
	}
	
function getpclConfig(userID, hostName) {
return `
port: 7890
allow-lan: true
mode: rule
log-level: info
unified-delay: true
global-client-fingerprint: chrome
dns:
  enable: true
  listen: :53
  ipv6: true
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16
  default-nameserver: 
    - 223.5.5.5
    - 114.114.114.114
    - 8.8.8.8
  nameserver:
    - https://dns.alidns.com/dns-query
    - https://doh.pub/dns-query
  fallback:
    - https://1.0.0.1/dns-query
    - tls://dns.google
  fallback-filter:
    geoip: true
    geoip-code: CN
    ipcidr:
      - 240.0.0.0/4

proxies:
- name: CF_V26_${IP26}_${PT26}
  type: vless
  server: ${IP26}
  port: ${PT26}
  uuid: ${userID}
  udp: false
  tls: true
  network: ws
  servername: ${hostName}
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}
      
- name: CF_V27_${IP27}_${PT27}
  type: vless
  server: ${IP27}
  port: ${PT27}
  uuid: ${userID}
  udp: false
  tls: true
  network: ws
    servername: ${hostName}
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}
      
- name: CF_V28_${IP28}_${PT28}
  type: vless
  server: ${IP28}
  port: ${PT28}
  uuid: ${userID}
  udp: false
  tls: true
  network: ws
    servername: ${hostName}
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}
      
- name: CF_V29_${IP29}_${PT29}
  type: vless
  server: ${IP29}
  port: ${PT29}
  uuid: ${userID}
  udp: false
  tls: true
  network: ws
    servername: ${hostName}
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}
      
- name: CF_V30_${IP30}_${PT30}
  type: vless
  server: ${IP30}
  port: ${PT30}
  uuid: ${userID}
  udp: false
  tls: true
  network: ws
    servername: ${hostName}
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}
      
- name: CF_V31_${IP31}_${PT31}
  type: vless
  server: ${IP31}
  port: ${PT31}
  uuid: ${userID}
  udp: false
  tls: true
  network: ws
    servername: ${hostName}
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}
      
- name: CF_V32_${IP32}_${PT32}
  type: vless
  server: ${IP32}
  port: ${PT32}
  uuid: ${userID}
  udp: false
  tls: true
  network: ws
    servername: ${hostName}
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}
      
- name: CF_V33_${IP33}_${PT33}
  type: vless
  server: ${IP33}
  port: ${PT33}
  uuid: ${userID}
  udp: false
  tls: true
  network: ws
    servername: ${hostName}
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}
      
- name: CF_V34_${IP34}_${PT34}
  type: vless
  server: ${IP34}
  port: ${PT34}
  uuid: ${userID}
  udp: false
  tls: true
  network: ws
    servername: ${hostName}
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}
      
- name: CF_V35_${IP35}_${PT35}
  type: vless
  server: ${IP35}
  port: ${PT35}
  uuid: ${userID}
  udp: false
  tls: true
  network: ws
    servername: ${hostName}
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}
      
- name: CF_V36_${IP36}_${PT36}
  type: vless
  server: ${IP36}
  port: ${PT36}
  uuid: ${userID}
  udp: false
  tls: true
  network: ws
    servername: ${hostName}
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}
      
- name: CF_V37_${IP37}_${PT37}
  type: vless
  server: ${IP37}
  port: ${PT37}
  uuid: ${userID}
  udp: false
  tls: true
  network: ws
    servername: ${hostName}
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}
      
- name: CF_V38_${IP38}_${PT38}
  type: vless
  server: ${IP38}
  port: ${PT38}
  uuid: ${userID}
  udp: false
  tls: true
  network: ws
    servername: ${hostName}
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}
      
- name: CF_V39_${IP39}_${PT39}
  type: vless
  server: ${IP39}
  port: ${PT39}
  uuid: ${userID}
  udp: false
  tls: true
  network: ws
    servername: ${hostName}
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}
      
- name: CF_V40_${IP40}_${PT40}
  type: vless
  server: ${IP40}
  port: ${PT40}
  uuid: ${userID}
  udp: false
  tls: true
  network: ws
    servername: ${hostName}
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}
      
- name: CF_V41_${IP41}_${PT41}
  type: vless
  server: ${IP41}
  port: ${PT41}
  uuid: ${userID}
  udp: false
  tls: true
  network: ws
    servername: ${hostName}
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}
      
- name: CF_V42_${IP42}_${PT42}
  type: vless
  server: ${IP42}
  port: ${PT42}
  uuid: ${userID}
  udp: false
  tls: true
  network: ws
    servername: ${hostName}
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}
      
- name: CF_V43_${IP43}_${PT43}
  type: vless
  server: ${IP43}
  port: ${PT43}
  uuid: ${userID}
  udp: false
  tls: true
  network: ws
    servername: ${hostName}
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}
      
- name: CF_V44_${IP44}_${PT44}
  type: vless
  server: ${IP44}
  port: ${PT44}
  uuid: ${userID}
  udp: false
  tls: true
  network: ws
    servername: ${hostName}
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}
      
- name: CF_V45_${IP45}_${PT45}
  type: vless
  server: ${IP45}
  port: ${PT45}
  uuid: ${userID}
  udp: false
  tls: true
  network: ws
    servername: ${hostName}
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}
      
- name: CF_V46_${IP46}_${PT46}
  type: vless
  server: ${IP46}
  port: ${PT46}
  uuid: ${userID}
  udp: false
  tls: true
  network: ws
    servername: ${hostName}
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}
      
- name: CF_V47_${IP47}_${PT47}
  type: vless
  server: ${IP47}
  port: ${PT47}
  uuid: ${userID}
  udp: false
  tls: true
  network: ws
    servername: ${hostName}
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}
      
- name: CF_V48_${IP48}_${PT48}
  type: vless
  server: ${IP48}
  port: ${PT48}
  uuid: ${userID}
  udp: false
  tls: true
  network: ws
    servername: ${hostName}
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}
      
- name: CF_V49_${IP49}_${PT49}
  type: vless
  server: ${IP49}
  port: ${PT49}
  uuid: ${userID}
  udp: false
  tls: true
  network: ws
    servername: ${hostName}
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}
      
- name: CF_V50_${IP50}_${PT50}
  type: vless
  server: ${IP50}
  port: ${PT50}
  uuid: ${userID}
  udp: false
  tls: true
  network: ws
    servername: ${hostName}
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}

proxy-groups:
- name: 负载均衡
  type: load-balance
  url: http://www.gstatic.com/generate_204
  interval: 300
  proxies:
  	- CF_V26_${IP26}_${PT26}
    - CF_V27_${IP27}_${PT27}
    - CF_V28_${IP28}_${PT28}
    - CF_V29_${IP29}_${PT29}
    - CF_V30_${IP30}_${PT30}
    - CF_V31_${IP31}_${PT31}
    - CF_V32_${IP32}_${PT32}
    - CF_V33_${IP33}_${PT33}
    - CF_V34_${IP34}_${PT34}
    - CF_V35_${IP35}_${PT35}
    - CF_V36_${IP36}_${PT36}
    - CF_V37_${IP37}_${PT37}
    - CF_V38_${IP38}_${PT38}
    - CF_V39_${IP39}_${PT39}
    - CF_V40_${IP40}_${PT40}
    - CF_V41_${IP41}_${PT41}
    - CF_V42_${IP42}_${PT42}
    - CF_V43_${IP43}_${PT43}
    - CF_V44_${IP44}_${PT44}
    - CF_V45_${IP45}_${PT45}
    - CF_V46_${IP46}_${PT46}
    - CF_V47_${IP47}_${PT47}
    - CF_V48_${IP48}_${PT48}
    - CF_V49_${IP49}_${PT49}
    - CF_V50_${IP50}_${PT50}

- name: 自动选择
  type: url-test
  url: http://www.gstatic.com/generate_204
  interval: 300
  tolerance: 50
  proxies:
  	- CF_V26_${IP26}_${PT26}
    - CF_V27_${IP27}_${PT27}
    - CF_V28_${IP28}_${PT28}
    - CF_V29_${IP29}_${PT29}
    - CF_V30_${IP30}_${PT30}
    - CF_V31_${IP31}_${PT31}
    - CF_V32_${IP32}_${PT32}
    - CF_V33_${IP33}_${PT33}
    - CF_V34_${IP34}_${PT34}
    - CF_V35_${IP35}_${PT35}
    - CF_V36_${IP36}_${PT36}
    - CF_V37_${IP37}_${PT37}
    - CF_V38_${IP38}_${PT38}
    - CF_V39_${IP39}_${PT39}
    - CF_V40_${IP40}_${PT40}
    - CF_V41_${IP41}_${PT41}
    - CF_V42_${IP42}_${PT42}
    - CF_V43_${IP43}_${PT43}
    - CF_V44_${IP44}_${PT44}
    - CF_V45_${IP45}_${PT45}
    - CF_V46_${IP46}_${PT46}
    - CF_V47_${IP47}_${PT47}
    - CF_V48_${IP48}_${PT48}
    - CF_V49_${IP49}_${PT49}
    - CF_V50_${IP50}_${PT50}

- name: 🌍选择代理
  type: select
  proxies:
    - 负载均衡
    - 自动选择
    - DIRECT
  	- CF_V26_${IP26}_${PT26}
    - CF_V27_${IP27}_${PT27}
    - CF_V28_${IP28}_${PT28}
    - CF_V29_${IP29}_${PT29}
    - CF_V30_${IP30}_${PT30}
    - CF_V31_${IP31}_${PT31}
    - CF_V32_${IP32}_${PT32}
    - CF_V33_${IP33}_${PT33}
    - CF_V34_${IP34}_${PT34}
    - CF_V35_${IP35}_${PT35}
    - CF_V36_${IP36}_${PT36}
    - CF_V37_${IP37}_${PT37}
    - CF_V38_${IP38}_${PT38}
    - CF_V39_${IP39}_${PT39}
    - CF_V40_${IP40}_${PT40}
    - CF_V41_${IP41}_${PT41}
    - CF_V42_${IP42}_${PT42}
    - CF_V43_${IP43}_${PT43}
    - CF_V44_${IP44}_${PT44}
    - CF_V45_${IP45}_${PT45}
    - CF_V46_${IP46}_${PT46}
    - CF_V47_${IP47}_${PT47}
    - CF_V48_${IP48}_${PT48}
    - CF_V49_${IP49}_${PT49}
    - CF_V50_${IP50}_${PT50}

rules:
  - GEOIP,LAN,DIRECT
  - GEOIP,CN,DIRECT
  - MATCH,🌍选择代理`
}
		
function getpsbConfig(userID, hostName) {
return `{
		  "log": {
			"disabled": false,
			"level": "info",
			"timestamp": true
		  },
		  "experimental": {
			"clash_api": {
			  "external_controller": "127.0.0.1:9090",
			  "external_ui": "ui",
			  "external_ui_download_url": "",
			  "external_ui_download_detour": "",
			  "secret": "",
			  "default_mode": "Rule"
			},
			"cache_file": {
			  "enabled": true,
			  "path": "cache.db",
			  "store_fakeip": true
			}
		  },
		  "dns": {
			"servers": [
			  {
				"tag": "proxydns",
				"address": "tls://8.8.8.8/dns-query",
				"detour": "select"
			  },
			  {
				"tag": "localdns",
				"address": "h3://223.5.5.5/dns-query",
				"detour": "direct"
			  },
			  {
				"address": "rcode://refused",
				"tag": "block"
			  },
			  {
				"tag": "dns_fakeip",
				"address": "fakeip"
			  }
			],
			"rules": [
			  {
				"outbound": "any",
				"server": "localdns",
				"disable_cache": true
			  },
			  {
				"clash_mode": "Global",
				"server": "proxydns"
			  },
			  {
				"clash_mode": "Direct",
				"server": "localdns"
			  },
			  {
				"rule_set": "geosite-cn",
				"server": "localdns"
			  },
			  {
				"rule_set": "geosite-geolocation-!cn",
				"server": "proxydns"
			  },
			  {
				"rule_set": "geosite-geolocation-!cn",
				"query_type": [
				  "A",
				  "AAAA"
				],
				"server": "dns_fakeip"
			  }
			],
			"fakeip": {
			  "enabled": true,
			  "inet4_range": "198.18.0.0/15",
			  "inet6_range": "fc00::/18"
			},
			"independent_cache": true,
			"final": "proxydns"
		  },
		  "inbounds": [
			{
			  "type": "tun",
			  "inet4_address": "172.19.0.1/30",
			  "inet6_address": "fd00::1/126",
			  "auto_route": true,
			  "strict_route": true,
			  "sniff": true,
			  "sniff_override_destination": true,
			  "domain_strategy": "prefer_ipv4"
			}
		  ],
		  "outbounds": [
			{
			  "tag": "select",
			  "type": "selector",
			  "default": "auto",
			  "outbounds": [
				"auto",
                "CF_V26_${IP26}_${PT26}",
                "CF_V27_${IP27}_${PT27}",
                "CF_V28_${IP28}_${PT28}",
                "CF_V29_${IP29}_${PT29}",
                "CF_V30_${IP30}_${PT30}",
                "CF_V31_${IP31}_${PT31}",
                "CF_V32_${IP32}_${PT32}",
                "CF_V33_${IP33}_${PT33}",
                "CF_V34_${IP34}_${PT34}",
                "CF_V35_${IP35}_${PT35}",
                "CF_V36_${IP36}_${PT36}",
                "CF_V37_${IP37}_${PT37}",
                "CF_V38_${IP38}_${PT38}",
                "CF_V39_${IP39}_${PT39}",
                "CF_V40_${IP40}_${PT40}",
                "CF_V41_${IP41}_${PT41}",
                "CF_V42_${IP42}_${PT42}",
                "CF_V43_${IP43}_${PT43}",
                "CF_V44_${IP44}_${PT44}",
                "CF_V45_${IP45}_${PT45}",
                "CF_V46_${IP46}_${PT46}",
                "CF_V47_${IP47}_${PT47}",
                "CF_V48_${IP48}_${PT48}",
                "CF_V49_${IP49}_${PT49}",
                "CF_V50_${IP50}_${PT50}"
			  ]
			},
						{
			  "server": "${IP26}",
			  "server_port": ${PT26},
			  "tag": "CF_V26_${IP26}_${PT26}",
			  "tls": {
				"enabled": true,
				"server_name": "${hostName}",
				"insecure": false,
				"utls": {
				  "enabled": true,
				  "fingerprint": "chrome"
				}
			  },
			  "packet_encoding": "packetaddr",
			  "transport": {
				"headers": {
				  "Host": [
					"${hostName}"
				  ]
				},
				"path": "/?ed=2560",
				"type": "ws"
			  },
			  "type": "vless",
			  "uuid": "${userID}"
			},
			{
			  "server": "${IP27}",
			  "server_port": ${PT27},
			  "tag": "CF_V27_${IP27}_${PT27}",
			  "tls": {
				"enabled": true,
				"server_name": "${hostName}",
				"insecure": false,
				"utls": {
				  "enabled": true,
				  "fingerprint": "chrome"
				}
			  },
			  "packet_encoding": "packetaddr",
			  "transport": {
				"headers": {
				  "Host": [
					"${hostName}"
				  ]
				},
				"path": "/?ed=2560",
				"type": "ws"
			  },
			  "type": "vless",
			  "uuid": "${userID}"
			},
			{
			  "server": "${IP28}",
			  "server_port": ${PT28},
			  "tag": "CF_V28_${IP28}_${PT28}",
			  "tls": {
				"enabled": true,
				"server_name": "${hostName}",
				"insecure": false,
				"utls": {
				  "enabled": true,
				  "fingerprint": "chrome"
				}
			  },
			  "packet_encoding": "packetaddr",
			  "transport": {
				"headers": {
				  "Host": [
					"${hostName}"
				  ]
				},
				"path": "/?ed=2560",
				"type": "ws"
			  },
			  "type": "vless",
			  "uuid": "${userID}"
			},
			{
			  "server": "${IP29}",
			  "server_port": ${PT29},
			  "tag": "CF_V29_${IP29}_${PT29}",
			  "tls": {
				"enabled": true,
				"server_name": "${hostName}",
				"insecure": false,
				"utls": {
				  "enabled": true,
				  "fingerprint": "chrome"
				}
			  },
			  "packet_encoding": "packetaddr",
			  "transport": {
				"headers": {
				  "Host": [
					"${hostName}"
				  ]
				},
				"path": "/?ed=2560",
				"type": "ws"
			  },
			  "type": "vless",
			  "uuid": "${userID}"
			},
			{
			  "server": "${IP30}",
			  "server_port": ${PT30},
			  "tag": "CF_V30_${IP30}_${PT30}",
			  "tls": {
				"enabled": true,
				"server_name": "${hostName}",
				"insecure": false,
				"utls": {
				  "enabled": true,
				  "fingerprint": "chrome"
				}
			  },
			  "packet_encoding": "packetaddr",
			  "transport": {
				"headers": {
				  "Host": [
					"${hostName}"
				  ]
				},
				"path": "/?ed=2560",
				"type": "ws"
			  },
			  "type": "vless",
			  "uuid": "${userID}"
			},
			{
			  "server": "${IP31}",
			  "server_port": ${PT31},
			  "tag": "CF_V31_${IP31}_${PT31}",
			  "tls": {
				"enabled": true,
				"server_name": "${hostName}",
				"insecure": false,
				"utls": {
				  "enabled": true,
				  "fingerprint": "chrome"
				}
			  },
			  "packet_encoding": "packetaddr",
			  "transport": {
				"headers": {
				  "Host": [
					"${hostName}"
				  ]
				},
				"path": "/?ed=2560",
				"type": "ws"
			  },
			  "type": "vless",
			  "uuid": "${userID}"
			},
						{
			  "server": "${IP32}",
			  "server_port": ${PT32},
			  "tag": "CF_V32_${IP32}_${PT32}",
			  "tls": {
				"enabled": true,
				"server_name": "${hostName}",
				"insecure": false,
				"utls": {
				  "enabled": true,
				  "fingerprint": "chrome"
				}
			  },
			  "packet_encoding": "packetaddr",
			  "transport": {
				"headers": {
				  "Host": [
					"${hostName}"
				  ]
				},
				"path": "/?ed=2560",
				"type": "ws"
			  },
			  "type": "vless",
			  "uuid": "${userID}"
			},
						{
			  "server": "${IP33}",
			  "server_port": ${PT33},
			  "tag": "CF_V33_${IP33}_${PT33}",
			  "tls": {
				"enabled": true,
				"server_name": "${hostName}",
				"insecure": false,
				"utls": {
				  "enabled": true,
				  "fingerprint": "chrome"
				}
			  },
			  "packet_encoding": "packetaddr",
			  "transport": {
				"headers": {
				  "Host": [
					"${hostName}"
				  ]
				},
				"path": "/?ed=2560",
				"type": "ws"
			  },
			  "type": "vless",
			  "uuid": "${userID}"
			},
						{
			  "server": "${IP34}",
			  "server_port": ${PT34},
			  "tag": "CF_V34_${IP34}_${PT34}",
			  "tls": {
				"enabled": true,
				"server_name": "${hostName}",
				"insecure": false,
				"utls": {
				  "enabled": true,
				  "fingerprint": "chrome"
				}
			  },
			  "packet_encoding": "packetaddr",
			  "transport": {
				"headers": {
				  "Host": [
					"${hostName}"
				  ]
				},
				"path": "/?ed=2560",
				"type": "ws"
			  },
			  "type": "vless",
			  "uuid": "${userID}"
			},
						{
			  "server": "${IP35}",
			  "server_port": ${PT35},
			  "tag": "CF_V35_${IP35}_${PT35}",
			  "tls": {
				"enabled": true,
				"server_name": "${hostName}",
				"insecure": false,
				"utls": {
				  "enabled": true,
				  "fingerprint": "chrome"
				}
			  },
			  "packet_encoding": "packetaddr",
			  "transport": {
				"headers": {
				  "Host": [
					"${hostName}"
				  ]
				},
				"path": "/?ed=2560",
				"type": "ws"
			  },
			  "type": "vless",
			  "uuid": "${userID}"
			},
						{
			  "server": "${IP36}",
			  "server_port": ${PT36},
			  "tag": "CF_V36_${IP36}_${PT36}",
			  "tls": {
				"enabled": true,
				"server_name": "${hostName}",
				"insecure": false,
				"utls": {
				  "enabled": true,
				  "fingerprint": "chrome"
				}
			  },
			  "packet_encoding": "packetaddr",
			  "transport": {
				"headers": {
				  "Host": [
					"${hostName}"
				  ]
				},
				"path": "/?ed=2560",
				"type": "ws"
			  },
			  "type": "vless",
			  "uuid": "${userID}"
			},
						{
			  "server": "${IP37}",
			  "server_port": ${PT37},
			  "tag": "CF_V37_${IP37}_${PT37}",
			  "tls": {
				"enabled": true,
				"server_name": "${hostName}",
				"insecure": false,
				"utls": {
				  "enabled": true,
				  "fingerprint": "chrome"
				}
			  },
			  "packet_encoding": "packetaddr",
			  "transport": {
				"headers": {
				  "Host": [
					"${hostName}"
				  ]
				},
				"path": "/?ed=2560",
				"type": "ws"
			  },
			  "type": "vless",
			  "uuid": "${userID}"
			},
						{
			  "server": "${IP38}",
			  "server_port": ${PT38},
			  "tag": "CF_V38_${IP38}_${PT38}",
			  "tls": {
				"enabled": true,
				"server_name": "${hostName}",
				"insecure": false,
				"utls": {
				  "enabled": true,
				  "fingerprint": "chrome"
				}
			  },
			  "packet_encoding": "packetaddr",
			  "transport": {
				"headers": {
				  "Host": [
					"${hostName}"
				  ]
				},
				"path": "/?ed=2560",
				"type": "ws"
			  },
			  "type": "vless",
			  "uuid": "${userID}"
			},
						{
			  "server": "${IP39}",
			  "server_port": ${PT39},
			  "tag": "CF_V39_${IP39}_${PT39}",
			  "tls": {
				"enabled": true,
				"server_name": "${hostName}",
				"insecure": false,
				"utls": {
				  "enabled": true,
				  "fingerprint": "chrome"
				}
			  },
			  "packet_encoding": "packetaddr",
			  "transport": {
				"headers": {
				  "Host": [
					"${hostName}"
				  ]
				},
				"path": "/?ed=2560",
				"type": "ws"
			  },
			  "type": "vless",
			  "uuid": "${userID}"
			},
						{
			  "server": "${IP40}",
			  "server_port": ${PT40},
			  "tag": "CF_V40_${IP40}_${PT40}",
			  "tls": {
				"enabled": true,
				"server_name": "${hostName}",
				"insecure": false,
				"utls": {
				  "enabled": true,
				  "fingerprint": "chrome"
				}
			  },
			  "packet_encoding": "packetaddr",
			  "transport": {
				"headers": {
				  "Host": [
					"${hostName}"
				  ]
				},
				"path": "/?ed=2560",
				"type": "ws"
			  },
			  "type": "vless",
			  "uuid": "${userID}"
			},
						{
			  "server": "${IP41}",
			  "server_port": ${PT41},
			  "tag": "CF_V41_${IP41}_${PT41}",
			  "tls": {
				"enabled": true,
				"server_name": "${hostName}",
				"insecure": false,
				"utls": {
				  "enabled": true,
				  "fingerprint": "chrome"
				}
			  },
			  "packet_encoding": "packetaddr",
			  "transport": {
				"headers": {
				  "Host": [
					"${hostName}"
				  ]
				},
				"path": "/?ed=2560",
				"type": "ws"
			  },
			  "type": "vless",
			  "uuid": "${userID}"
			},
						{
			  "server": "${IP42}",
			  "server_port": ${PT42},
			  "tag": "CF_V42_${IP42}_${PT42}",
			  "tls": {
				"enabled": true,
				"server_name": "${hostName}",
				"insecure": false,
				"utls": {
				  "enabled": true,
				  "fingerprint": "chrome"
				}
			  },
			  "packet_encoding": "packetaddr",
			  "transport": {
				"headers": {
				  "Host": [
					"${hostName}"
				  ]
				},
				"path": "/?ed=2560",
				"type": "ws"
			  },
			  "type": "vless",
			  "uuid": "${userID}"
			},
						{
			  "server": "${IP43}",
			  "server_port": ${PT43},
			  "tag": "CF_V43_${IP43}_${PT43}",
			  "tls": {
				"enabled": true,
				"server_name": "${hostName}",
				"insecure": false,
				"utls": {
				  "enabled": true,
				  "fingerprint": "chrome"
				}
			  },
			  "packet_encoding": "packetaddr",
			  "transport": {
				"headers": {
				  "Host": [
					"${hostName}"
				  ]
				},
				"path": "/?ed=2560",
				"type": "ws"
			  },
			  "type": "vless",
			  "uuid": "${userID}"
			},
						{
			  "server": "${IP44}",
			  "server_port": ${PT44},
			  "tag": "CF_V44_${IP44}_${PT44}",
			  "tls": {
				"enabled": true,
				"server_name": "${hostName}",
				"insecure": false,
				"utls": {
				  "enabled": true,
				  "fingerprint": "chrome"
				}
			  },
			  "packet_encoding": "packetaddr",
			  "transport": {
				"headers": {
				  "Host": [
					"${hostName}"
				  ]
				},
				"path": "/?ed=2560",
				"type": "ws"
			  },
			  "type": "vless",
			  "uuid": "${userID}"
			},
						{
			  "server": "${IP45}",
			  "server_port": ${PT45},
			  "tag": "CF_V45_${IP45}_${PT45}",
			  "tls": {
				"enabled": true,
				"server_name": "${hostName}",
				"insecure": false,
				"utls": {
				  "enabled": true,
				  "fingerprint": "chrome"
				}
			  },
			  "packet_encoding": "packetaddr",
			  "transport": {
				"headers": {
				  "Host": [
					"${hostName}"
				  ]
				},
				"path": "/?ed=2560",
				"type": "ws"
			  },
			  "type": "vless",
			  "uuid": "${userID}"
			},
						{
			  "server": "${IP46}",
			  "server_port": ${PT46},
			  "tag": "CF_V46_${IP46}_${PT46}",
			  "tls": {
				"enabled": true,
				"server_name": "${hostName}",
				"insecure": false,
				"utls": {
				  "enabled": true,
				  "fingerprint": "chrome"
				}
			  },
			  "packet_encoding": "packetaddr",
			  "transport": {
				"headers": {
				  "Host": [
					"${hostName}"
				  ]
				},
				"path": "/?ed=2560",
				"type": "ws"
			  },
			  "type": "vless",
			  "uuid": "${userID}"
			},
						{
			  "server": "${IP47}",
			  "server_port": ${PT47},
			  "tag": "CF_V47_${IP47}_${PT47}",
			  "tls": {
				"enabled": true,
				"server_name": "${hostName}",
				"insecure": false,
				"utls": {
				  "enabled": true,
				  "fingerprint": "chrome"
				}
			  },
			  "packet_encoding": "packetaddr",
			  "transport": {
				"headers": {
				  "Host": [
					"${hostName}"
				  ]
				},
				"path": "/?ed=2560",
				"type": "ws"
			  },
			  "type": "vless",
			  "uuid": "${userID}"
			},
						{
			  "server": "${IP48}",
			  "server_port": ${PT48},
			  "tag": "CF_V48_${IP48}_${PT48}",
			  "tls": {
				"enabled": true,
				"server_name": "${hostName}",
				"insecure": false,
				"utls": {
				  "enabled": true,
				  "fingerprint": "chrome"
				}
			  },
			  "packet_encoding": "packetaddr",
			  "transport": {
				"headers": {
				  "Host": [
					"${hostName}"
				  ]
				},
				"path": "/?ed=2560",
				"type": "ws"
			  },
			  "type": "vless",
			  "uuid": "${userID}"
			},
						{
			  "server": "${IP49}",
			  "server_port": ${PT49},
			  "tag": "CF_V49_${IP49}_${PT49}",
			  "tls": {
				"enabled": true,
				"server_name": "${hostName}",
				"insecure": false,
				"utls": {
				  "enabled": true,
				  "fingerprint": "chrome"
				}
			  },
			  "packet_encoding": "packetaddr",
			  "transport": {
				"headers": {
				  "Host": [
					"${hostName}"
				  ]
				},
				"path": "/?ed=2560",
				"type": "ws"
			  },
			  "type": "vless",
			  "uuid": "${userID}"
			},
						{
			  "server": "${IP50}",
			  "server_port": ${PT50},
			  "tag": "CF_V50_${IP50}_${PT50}",
			  "tls": {
				"enabled": true,
				"server_name": "${hostName}",
				"insecure": false,
				"utls": {
				  "enabled": true,
				  "fingerprint": "chrome"
				}
			  },
			  "packet_encoding": "packetaddr",
			  "transport": {
				"headers": {
				  "Host": [
					"${hostName}"
				  ]
				},
				"path": "/?ed=2560",
				"type": "ws"
			  },
			  "type": "vless",
			  "uuid": "${userID}"
			},
			{
			  "tag": "direct",
			  "type": "direct"
			},
			{
			  "tag": "block",
			  "type": "block"
			},
			{
			  "tag": "dns-out",
			  "type": "dns"
			},
			{
			  "tag": "auto",
			  "type": "urltest",
			  "outbounds": [
                "CF_V26_${IP26}_${PT26}",
                "CF_V27_${IP27}_${PT27}",
                "CF_V28_${IP28}_${PT28}",
                "CF_V29_${IP29}_${PT29}",
                "CF_V30_${IP30}_${PT30}",
                "CF_V31_${IP31}_${PT31}",
                "CF_V32_${IP32}_${PT32}",
                "CF_V33_${IP33}_${PT33}",
                "CF_V34_${IP34}_${PT34}",
                "CF_V35_${IP35}_${PT35}",
                "CF_V36_${IP36}_${PT36}",
                "CF_V37_${IP37}_${PT37}",
                "CF_V38_${IP38}_${PT38}",
                "CF_V39_${IP39}_${PT39}",
                "CF_V40_${IP40}_${PT40}",
                "CF_V41_${IP41}_${PT41}",
                "CF_V42_${IP42}_${PT42}",
                "CF_V43_${IP43}_${PT43}",
                "CF_V44_${IP44}_${PT44}",
                "CF_V45_${IP45}_${PT45}",
                "CF_V46_${IP46}_${PT46}",
                "CF_V47_${IP47}_${PT47}",
                "CF_V48_${IP48}_${PT48}",
                "CF_V49_${IP49}_${PT49}",
                "CF_V50_${IP50}_${PT50}"
			  ],
			  "url": "https://www.gstatic.com/generate_204",
			  "interval": "1m",
			  "tolerance": 50,
			  "interrupt_exist_connections": false
			}
		  ],
		  "route": {
			"rule_set": [
			  {
				"tag": "geosite-geolocation-!cn",
				"type": "remote",
				"format": "binary",
				"url": "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geosite/geolocation-!cn.srs",
				"download_detour": "select",
				"update_interval": "1d"
			  },
			  {
				"tag": "geosite-cn",
				"type": "remote",
				"format": "binary",
				"url": "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geosite/geolocation-cn.srs",
				"download_detour": "select",
				"update_interval": "1d"
			  },
			  {
				"tag": "geoip-cn",
				"type": "remote",
				"format": "binary",
				"url": "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geoip/cn.srs",
				"download_detour": "select",
				"update_interval": "1d"
			  }
			],
			"auto_detect_interface": true,
			"final": "select",
			"rules": [
			  {
				"outbound": "dns-out",
				"protocol": "dns"
			  },
			  {
				"clash_mode": "Direct",
				"outbound": "direct"
			  },
			  {
				"clash_mode": "Global",
				"outbound": "select"
			  },
			  {
				"rule_set": "geoip-cn",
				"outbound": "direct"
			  },
			  {
				"rule_set": "geosite-cn",
				"outbound": "direct"
			  },
			  {
				"ip_is_private": true,
				"outbound": "direct"
			  },
			  {
				"rule_set": "geosite-geolocation-!cn",
				"outbound": "select"
			  }
			]
		  },
		  "ntp": {
			"enabled": true,
			"server": "time.apple.com",
			"server_port": 123,
			"interval": "30m",
			"detour": "direct"
		  }
		}`;
} 
