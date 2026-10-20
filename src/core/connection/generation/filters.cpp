#include "core/CoreUtils.hpp"
#include "core/connection/Generation.hpp"
#include "utils/QvHelpers.hpp"

#include <QJsonDocument>
#include <QSet>

#define QV_MODULE_NAME "ConfigFilters"

namespace Qv2ray::core::connection::generation::filters
{
    void OutboundMarkSettingFilter(CONFIGROOT &root, const int mark)
    {
        for (auto i = 0; i < root["outbounds"].toArray().count(); i++)
        {
            QJsonIO::SetValue(root, mark, "outbounds", i, "streamSettings", "sockopt", "mark");
        }
    }

    void RemoveEmptyMuxFilter(CONFIGROOT &root)
    {
        for (auto i = 0; i < root["outbounds"].toArray().count(); i++)
        {
            if (!QJsonIO::GetValue(root, "outbounds", i, "mux", "enabled").toBool(false))
            {
                QJsonIO::SetValue(root, QJsonIO::Undefined, "outbounds", i, "mux");
            }
        }
    }

    void DNSInterceptFilter(CONFIGROOT &root, const bool have_tproxy, const bool have_tproxy_v6, const bool have_socks)
    {
        // Static DNS Objects
        static const QJsonObject dnsOutboundObj{ { "protocol", "dns" }, { "tag", "dns-out" } };

        QJsonArray dnsRouteInTag;

        if (have_tproxy)
            dnsRouteInTag.append("tproxy_IN");
        if (have_tproxy_v6)
            dnsRouteInTag.append("tproxy_IN_V6");
        if (have_socks)
            dnsRouteInTag.append("socks_IN");

        // If no UDP inbound, then DNS outbound is useless.
        if (dnsRouteInTag.isEmpty())
            return;

        const QJsonObject dnsRoutingRuleObj{ { "outboundTag", "dns-out" }, { "port", "53" }, { "type", "field" }, { "inboundTag", dnsRouteInTag } };

        // DNS Outbound
        QJsonIO::SetValue(root, dnsOutboundObj, "outbounds", root["outbounds"].toArray().count());
        // DNS Route
        auto _rules = QJsonIO::GetValue(root, "routing", "rules").toArray();
        _rules.prepend(dnsRoutingRuleObj);
        QJsonIO::SetValue(root, _rules, "routing", "rules");
    }

    void BypassBTFilter(CONFIGROOT &root)
    {
        static const QJsonObject bypassBTRuleObj{ { "protocol", QJsonArray{ "bittorrent" } },
                                                  { "outboundTag", OUTBOUND_TAG_DIRECT },
                                                  { "type", "field" } };
        auto _rules = QJsonIO::GetValue(root, "routing", "rules").toArray();
        _rules.prepend(bypassBTRuleObj);
        QJsonIO::SetValue(root, _rules, "routing", "rules");
    }

    void mKCPSeedFilter(CONFIGROOT &root)
    {
        for (auto i = 0; i < root["outbounds"].toArray().count(); i++)
        {
            const auto seedItem = QJsonIO::GetValue(root, "outbounds", i, "streamSettings", "kcpSettings", "seed");
            bool shouldProcess = !seedItem.isNull() && !seedItem.isUndefined();
            bool isEmptySeed = seedItem.toString().isEmpty();
            if (shouldProcess && isEmptySeed)
                QJsonIO::SetValue(root, QJsonIO::Undefined, "outbounds", i, "streamSettings", "kcpSettings", "seed");
        }
    }

    void FillupTagsFilter(CONFIGROOT &root, const QString &subKey)
    {
        for (auto i = 0; i < root[subKey].toArray().count(); i++)
        {
            if (QJsonIO::GetValue(root, subKey, i, "tag").toString().isEmpty())
            {
                const auto tag = GenerateRandomString(8);
                QJsonIO::SetValue(root, tag, subKey, i, "tag");
            }
        }
    }

    namespace
    {
        QString FirstHostHeader(const QJsonObject &headers)
        {
            for (const auto &key : headers.keys())
            {
                if (key.compare("host", Qt::CaseInsensitive) == 0)
                    return headers[key].toString();
            }
            return {};
        }

        void RemoveHostHeaders(QJsonObject &headers)
        {
            for (const auto &key : headers.keys())
            {
                if (key.compare("host", Qt::CaseInsensitive) == 0)
                    headers.remove(key);
            }
        }

        void EnsureVlessVisionFlow(QJsonObject &entry)
        {
            auto settings = entry["settings"].toObject();
            auto vnext = settings["vnext"].toArray();
            for (auto i = 0; i < vnext.count(); i++)
            {
                auto server = vnext[i].toObject();
                auto users = server["users"].toArray();
                for (auto j = 0; j < users.count(); j++)
                {
                    auto user = users[j].toObject();
                    if (user["flow"].toString().isEmpty())
                        user["flow"] = "xtls-rprx-vision";
                    users[j] = user;
                }
                server["users"] = users;
                vnext[i] = server;
            }
            settings["vnext"] = vnext;
            entry["settings"] = settings;
        }

        void NormalizeRangeField(QJsonObject &object, const QString &key)
        {
            if (!object.contains(key))
                return;
            const auto value = object[key];
            if (value.isString() || value.isDouble())
                return;
            if (value.isObject())
            {
                const auto obj = value.toObject();
                const auto from = obj["from"].toInt(obj["left"].toInt());
                const auto to = obj["to"].toInt(obj["right"].toInt(from));
                object[key] = from == to ? QJsonValue(from) : QJsonValue(QStringLiteral("%1-%2").arg(from).arg(to));
            }
        }

        void NormalizeRangeFields(QJsonObject &object)
        {
            for (const auto &key : { "xPaddingBytes", "sessionIDLength", "uplinkChunkSize", "scMaxEachPostBytes", "scMinPostsIntervalMs",
                                     "scStreamUpServerSecs" })
                NormalizeRangeField(object, key);

            auto xmux = object["xmux"].toObject();
            if (!xmux.isEmpty())
            {
                for (const auto &key : { "maxConcurrency", "maxConnections", "cMaxReuseTimes", "hMaxRequestTimes", "hMaxReusableSecs" })
                    NormalizeRangeField(xmux, key);
                object["xmux"] = xmux;
            }
        }

        void MigrateWebSocketHost(QJsonObject &ws)
        {
            auto headers = ws["headers"].toObject();
            const auto headerHost = FirstHostHeader(headers);
            if (ws["host"].toString().isEmpty() && !headerHost.isEmpty())
                ws["host"] = headerHost;
            if (!ws["host"].toString().isEmpty())
            {
                // v2ray-core reads the Host header, Xray-core reads "host".
                headers["Host"] = ws["host"].toString();
            }
            ws["headers"] = headers;
        }

        void NormalizeStreamObject(QJsonObject &entry)
        {
            auto stream = entry["streamSettings"].toObject();
            if (stream.isEmpty())
                return;

            // Xray-core's "method" is an alias of "network".  Always emit the
            // portable "network" spelling.
            if (stream["network"].toString().isEmpty() && !stream["method"].toString().isEmpty())
                stream["network"] = stream["method"];
            stream.remove("method");

            auto network = stream["network"].toString().toLower();
            if (network == "raw")
                network = "tcp";
            else if (network == "websocket")
                network = "ws";
            else if (network == "mkcp")
                network = "kcp";
            else if (network == "gun")
                network = "grpc";
            else if (network == "h2")
                network = "http";
            else if (network == "ds")
                network = "domainsocket";
            if (network.isEmpty())
                network = "tcp";
            stream["network"] = network;

            // Keep transport setting aliases in sync.  "tcpSettings" and
            // "grpcSettings" are understood by both cores.
            if (!stream.contains("tcpSettings") && stream.contains("rawSettings"))
                stream["tcpSettings"] = stream["rawSettings"];
            if (!stream.contains("grpcSettings") && stream.contains("gunSettings"))
                stream["grpcSettings"] = stream["gunSettings"];
            if (!stream.contains("xhttpSettings") && stream.contains("splithttpSettings"))
                stream["xhttpSettings"] = stream["splithttpSettings"];
            if (!stream.contains("splithttpSettings") && stream.contains("xhttpSettings"))
                stream["splithttpSettings"] = stream["xhttpSettings"];

            auto ws = stream["wsSettings"].toObject();
            if (!ws.isEmpty())
            {
                MigrateWebSocketHost(ws);
                stream["wsSettings"] = ws;
            }

            auto httpupgrade = stream["httpupgradeSettings"].toObject();
            if (!httpupgrade.isEmpty())
            {
                auto headers = httpupgrade["headers"].toObject();
                const auto headerHost = FirstHostHeader(headers);
                if (httpupgrade["host"].toString().isEmpty() && !headerHost.isEmpty())
                    httpupgrade["host"] = headerHost;
                RemoveHostHeaders(headers);
                httpupgrade["headers"] = headers;
                stream["httpupgradeSettings"] = httpupgrade;
            }

            auto xhttp = stream["xhttpSettings"].toObject();
            if (!xhttp.isEmpty())
            {
                auto headers = xhttp["headers"].toObject();
                const auto headerHost = FirstHostHeader(headers);
                if (xhttp["host"].toString().isEmpty() && !headerHost.isEmpty())
                    xhttp["host"] = headerHost;
                RemoveHostHeaders(headers);
                xhttp["headers"] = headers;
                NormalizeRangeFields(xhttp);
                stream["xhttpSettings"] = xhttp;
            }

            auto security = stream["security"].toString().toLower();
            if (security == "xtls")
            {
                // Both modern v2ray-core and Xray-core removed the XTLS
                // transport security.  Vision is a VLESS flow over TLS now.
                stream["security"] = security = "tls";
                const auto tls = stream["tlsSettings"].toObject();
                if (tls.isEmpty() && stream.contains("xtlsSettings"))
                    stream["tlsSettings"] = stream["xtlsSettings"];
                stream.remove("xtlsSettings");
                if (entry["protocol"].toString() == "vless")
                    EnsureVlessVisionFlow(entry);
            }

            entry["streamSettings"] = stream;
        }

        void StripInternalRuleFields(QJsonObject &rule)
        {
            rule.remove("QV2RAY_RULE_ENABLED");
            rule.remove("QV2RAY_RULE_TAG");
            rule.remove("QV2RAY_RULE_USE_BALANCER");
        }

        void ApplyXrayStreamCompatibility(QJsonObject &entry)
        {
            auto stream = entry["streamSettings"].toObject();
            if (stream.isEmpty())
                return;

            auto network = stream["network"].toString().toLower();
            if (network == "http")
            {
                // HTTP/2 transport was removed from Xray.  Its replacement is
                // XHTTP stream-one / auto over HTTP/2.
                const auto http = stream["httpSettings"].toObject();
                QJsonObject xhttp;
                const auto host = http["host"].toArray().isEmpty() ? http["host"].toString() : http["host"].toArray().first().toString();
                if (!host.isEmpty())
                    xhttp["host"] = host;
                if (!http["path"].toString().isEmpty())
                    xhttp["path"] = http["path"];
                const auto httpHeaders = http["headers"].toObject();
                QJsonObject xhttpHeaders;
                for (const auto &key : httpHeaders.keys())
                {
                    const auto value = httpHeaders.value(key);
                    const auto text = value.isArray() ? value.toArray().first().toString() : value.toString();
                    if (!text.isEmpty() && key.compare("host", Qt::CaseInsensitive) != 0)
                        xhttpHeaders[key] = text;
                }
                if (!xhttpHeaders.isEmpty())
                    xhttp["headers"] = xhttpHeaders;
                xhttp["mode"] = "auto";
                stream.remove("httpSettings");
                stream["network"] = "xhttp";
                stream["xhttpSettings"] = xhttp;
                LOG("Migrating Xray HTTP/2 transport to XHTTP.");
            }
            else if (network == "quic")
            {
                // QUIC transport was removed from Xray; XHTTP stream-one is
                // the documented replacement.
                QJsonObject xhttp;
                xhttp["path"] = "/";
                xhttp["mode"] = "stream-one";
                stream.remove("quicSettings");
                stream["network"] = "xhttp";
                stream["xhttpSettings"] = xhttp;
                stream["security"] = "tls";
                auto tls = stream["tlsSettings"].toObject();
                tls["alpn"] = QJsonArray{ "h3" };
                stream["tlsSettings"] = tls;
                LOG("Migrating Xray QUIC transport to XHTTP/3.");
            }
            else if (network == "domainsocket")
            {
                LOG("Xray-core does not support the domainsocket transport; please migrate to RAW/TCP.");
            }
            else if (network == "hy2" || network == "hysteria2")
            {
                // v2ray-core calls this transport hysteria2/hy2, Xray-core
                // calls it hysteria (version 2).
                const auto hy2 = stream["hy2Settings"].toObject();
                QJsonObject hysteria;
                hysteria["version"] = 2;
                if (!hy2["password"].toString().isEmpty())
                    hysteria["auth"] = hy2["password"];
                if (hy2.contains("congestion"))
                    hysteria["congestion"] = hy2["congestion"];
                stream.remove("hy2Settings");
                stream["network"] = "hysteria";
                stream["hysteriaSettings"] = hysteria;
                LOG("Migrating Hysteria2 transport to Xray hysteria transport.");
            }
            else if (network == "httpupgrade" || network == "xhttp" || network == "splithttp" || network == "hysteria" ||
                     network == "masque" || network == "xdrive")
            {
                // Already an Xray-native transport.
            }
            else if (network == "hysteria2")
            {
                stream["network"] = "hysteria";
            }

            // Xray parses the RAW settings as "rawSettings" and also keeps
            // "tcpSettings" as an alias.  Use rawSettings so the name matches
            // the current documentation.
            if (stream.contains("tcpSettings") && !stream.contains("rawSettings"))
                stream["rawSettings"] = stream["tcpSettings"];
            if (stream.contains("gunSettings"))
            {
                if (!stream.contains("grpcSettings"))
                    stream["grpcSettings"] = stream["gunSettings"];
                stream.remove("gunSettings");
            }
            if (stream.contains("splithttpSettings"))
            {
                if (!stream.contains("xhttpSettings"))
                    stream["xhttpSettings"] = stream["splithttpSettings"];
                stream.remove("splithttpSettings");
            }

            auto grpc = stream["grpcSettings"].toObject();
            if (!grpc.isEmpty())
            {
                if (grpc.contains("idleTimeout") && !grpc.contains("idle_timeout"))
                    grpc["idle_timeout"] = grpc["idleTimeout"];
                if (grpc.contains("healthCheckTimeout") && !grpc.contains("health_check_timeout"))
                    grpc["health_check_timeout"] = grpc["healthCheckTimeout"];
                if (grpc.contains("permitWithoutStream") && !grpc.contains("permit_without_stream"))
                    grpc["permit_without_stream"] = grpc["permitWithoutStream"];
                if (grpc.contains("initialWindowsSize") && !grpc.contains("initial_windows_size"))
                    grpc["initial_windows_size"] = grpc["initialWindowsSize"];
                if (grpc.contains("userAgent") && !grpc.contains("user_agent"))
                    grpc["user_agent"] = grpc["userAgent"];
                for (const auto &key : { "idleTimeout", "healthCheckTimeout", "permitWithoutStream", "initialWindowsSize", "userAgent" })
                    grpc.remove(key);
                stream["grpcSettings"] = grpc;
            }

            auto kcp = stream["kcpSettings"].toObject();
            if (!kcp.isEmpty())
            {
                // These options only exist in v2ray-core.
                for (const auto &key : { "congestion", "readBufferSize", "writeBufferSize" })
                    kcp.remove(key);
                stream["kcpSettings"] = kcp;
            }

            auto ws = stream["wsSettings"].toObject();
            if (!ws.isEmpty())
            {
                auto headers = ws["headers"].toObject();
                const auto host = ws["host"].toString(FirstHostHeader(headers));
                RemoveHostHeaders(headers);
                ws["headers"] = headers;
                if (!host.isEmpty())
                    ws["host"] = host;
                stream["wsSettings"] = ws;
            }

            auto masque = stream["masqueSettings"].toObject();
            if (!masque.isEmpty())
            {
                auto headers = masque["headers"].toObject();
                for (const auto &key : headers.keys())
                {
                    if (key.compare("host", Qt::CaseInsensitive) == 0 || key.compare("capsule-protocol", Qt::CaseInsensitive) == 0)
                        headers.remove(key);
                    if (key.compare("authorization", Qt::CaseInsensitive) == 0 &&
                        (!masque["user"].toString().isEmpty() || !masque["pass"].toString().isEmpty()))
                        headers.remove(key);
                }
                masque["headers"] = headers;
                stream["masqueSettings"] = masque;
            }

            auto security = stream["security"].toString().toLower();
            if (security == "tls")
            {
                auto tls = stream["tlsSettings"].toObject();
                if (tls["allowInsecure"].toBool(false))
                    LOG("Removing allowInsecure for Xray; use pinnedPeerCertSha256/verifyPeerCertByName instead.");
                tls.remove("allowInsecure");
                // v2ray-core calls Xray's ECHConfigList "echConfig".
                if (!tls["echConfig"].toString().isEmpty() && tls["echConfigList"].toString().isEmpty())
                    tls["echConfigList"] = tls["echConfig"];
                // v2ray-core-only TLS fields.
                for (const auto &key : { "pinnedPeerCertificateChainSha256", "verifyClientCertificate", "echConfig", "echDohServer" })
                    tls.remove(key);
                stream["tlsSettings"] = tls;
            }
            else if (security == "reality")
            {
                auto reality = stream["realitySettings"].toObject();
                if (reality.contains("dest") && !reality.contains("target"))
                    reality["target"] = reality["dest"];
                reality.remove("dest");

                const auto realityNetwork = stream["network"].toString().toLower();
                if (realityNetwork != "tcp" && realityNetwork != "raw" && realityNetwork != "xhttp" && realityNetwork != "splithttp" &&
                    realityNetwork != "grpc")
                {
                    // Current Xray-core only allows REALITY on RAW, XHTTP and
                    // gRPC.  Downgrade imported REALITY-over-WS/HTTP configs
                    // to ordinary TLS so they remain usable.
                    LOG("REALITY is only supported with RAW/XHTTP/gRPC; falling back to TLS.");
                    auto tls = stream["tlsSettings"].toObject();
                    if (tls["serverName"].toString().isEmpty())
                        tls["serverName"] = reality["serverName"].toString();
                    if (tls["fingerprint"].toString().isEmpty())
                        tls["fingerprint"] = reality["fingerprint"].toString();
                    stream["security"] = "tls";
                    stream.remove("realitySettings");
                    stream["tlsSettings"] = tls;
                }
                else
                {
                    stream["realitySettings"] = reality;
                }
            }
            else if (security == "xtls")
            {
                stream["security"] = "tls";
            }

            auto sockopt = stream["sockopt"].toObject();
            if (!sockopt.isEmpty())
            {
                // v2ray-core socket options which Xray does not understand.
                for (const auto &key : { "tcpFastOpenQueueLength", "bindToDevice", "rxBufSize", "txBufSize", "forceBufSize" })
                    sockopt.remove(key);
                if (sockopt["mptcp"].toBool(false) && !sockopt["tcpMptcp"].toBool(false))
                    sockopt["tcpMptcp"] = true;
                sockopt.remove("mptcp");
                stream["sockopt"] = sockopt;
            }

            stream.remove("method");
            entry["streamSettings"] = stream;
        }

        void ApplyV2rayStreamCompatibility(QJsonObject &entry)
        {
            auto stream = entry["streamSettings"].toObject();
            if (stream.isEmpty())
                return;

            auto network = stream["network"].toString().toLower();
            if (network == "xhttp" || network == "splithttp")
            {
                // v2ray-core has no XHTTP.  Use the closest supported
                // transport (HTTP/2) so old imported configurations remain
                // usable.  Users should migrate to a v2ray-core transport for
                // full functionality.
                const auto xhttp = stream["xhttpSettings"].toObject();
                QJsonObject http;
                if (!xhttp["host"].toString().isEmpty())
                    http["host"] = QJsonArray{ xhttp["host"].toString() };
                if (!xhttp["path"].toString().isEmpty())
                    http["path"] = xhttp["path"];
                http["method"] = "PUT";
                stream.remove("xhttpSettings");
                stream.remove("splithttpSettings");
                stream["network"] = "http";
                stream["httpSettings"] = http;
                LOG("v2ray-core does not support XHTTP; falling back to the HTTP transport.");
            }
            else if (network == "httpupgrade")
            {
                const auto hu = stream["httpupgradeSettings"].toObject();
                QJsonObject ws;
                auto headers = hu["headers"].toObject();
                if (!hu["host"].toString().isEmpty())
                    headers["Host"] = hu["host"].toString();
                if (!headers.isEmpty())
                    ws["headers"] = headers;
                if (!hu["path"].toString().isEmpty())
                    ws["path"] = hu["path"];
                stream.remove("httpupgradeSettings");
                stream["network"] = "ws";
                stream["wsSettings"] = ws;
                LOG("v2ray-core does not support HTTPUpgrade; falling back to WebSocket.");
            }
            else if (network == "hysteria")
            {
                // Xray's hysteria transport is Hysteria2.  v2ray-core calls
                // the same transport hy2/hysteria2.
                const auto hysteria = stream["hysteriaSettings"].toObject();
                if (hysteria["version"].toInt() != 0 && hysteria["version"].toInt() != 2)
                    LOG("v2ray-core only supports Hysteria2; the configured Hysteria version may not work.");
                QJsonObject hy2;
                hy2["password"] = hysteria["auth"].toString();
                if (hysteria.contains("congestion"))
                    hy2["congestion"] = hysteria["congestion"];
                stream.remove("hysteriaSettings");
                stream["network"] = "hy2";
                stream["hy2Settings"] = hy2;
                LOG("Migrating Xray hysteria transport to v2ray Hysteria2 transport.");
            }
            else if (network == "raw")
            {
                stream["network"] = "tcp";
            }
            else if (network == "masque" || network == "xdrive")
            {
                LOG("v2ray-core does not support the " + network + " transport.");
            }

            // Transport setting names understood by v2ray-core.
            if (stream.contains("rawSettings") && !stream.contains("tcpSettings"))
                stream["tcpSettings"] = stream["rawSettings"];
            stream.remove("rawSettings");
            if (stream.contains("gunSettings"))
            {
                if (!stream.contains("grpcSettings"))
                    stream["grpcSettings"] = stream["gunSettings"];
                stream.remove("gunSettings");
            }

            auto grpc = stream["grpcSettings"].toObject();
            if (!grpc.isEmpty())
            {
                // v2ray-core understands the snake_case names and additionally
                // supports parseXForwardedFor.  Xray-only fields are ignored
                // by v2ray-core anyway, but remove them to keep configs tidy.
                for (const auto &key : { "authority", "user_agent" })
                    grpc.remove(key);
                stream["grpcSettings"] = grpc;
            }

            auto kcp = stream["kcpSettings"].toObject();
            if (!kcp.isEmpty())
            {
                // These options only exist in Xray-core.
                for (const auto &key : { "cwndMultiplier", "maxSendingWindow" })
                    kcp.remove(key);
                stream["kcpSettings"] = kcp;
            }

            auto ws = stream["wsSettings"].toObject();
            if (!ws.isEmpty())
            {
                auto headers = ws["headers"].toObject();
                if (ws["host"].toString().isEmpty() && !FirstHostHeader(headers).isEmpty())
                    ws["host"] = FirstHostHeader(headers);
                if (!ws["host"].toString().isEmpty())
                    headers["Host"] = ws["host"].toString();
                ws.remove("host");
                ws["headers"] = headers;
                stream["wsSettings"] = ws;
            }

            auto tls = stream["tlsSettings"].toObject();
            if (!tls.isEmpty())
            {
                // Xray's echConfigList is v2ray's echConfig.
                if (!tls["echConfigList"].toString().isEmpty() && tls["echConfig"].toString().isEmpty())
                    tls["echConfig"] = tls["echConfigList"];
                // Xray-only TLS options.
                for (const auto &key : { "minVersion", "maxVersion", "cipherSuites", "fingerprint", "rejectUnknownSni",
                                         "curvePreferences", "masterKeyLog", "pinnedPeerCertSha256", "verifyPeerCertByName",
                                         "echServerKeys", "echConfigList", "echSockopt", "useSystemCA" })
                    tls.remove(key);
                stream["tlsSettings"] = tls;
            }

            auto sockopt = stream["sockopt"].toObject();
            if (!sockopt.isEmpty())
            {
                // Xray's tcpMptcp is v2ray-core's mptcp.
                if (sockopt["tcpMptcp"].toBool(false) && !sockopt["mptcp"].toBool(false))
                    sockopt["mptcp"] = true;
                // Xray-only socket options.
                for (const auto &key : { "domainStrategy", "dialerProxy", "tcpCongestion", "tcpWindowClamp", "tcpMaxSeg", "penetrate",
                                         "tcpUserTimeout", "v6only", "interface", "tcpMptcp", "customSockopt", "addressPortStrategy",
                                         "happyEyeballs", "trustedXForwardedFor" })
                    sockopt.remove(key);
                stream["sockopt"] = sockopt;
            }

            // v2ray-core supports TLS but not REALITY.  Fall back to TLS
            // using the REALITY server name so that a forced v2ray-core run
            // does not silently send plaintext traffic.
            if (stream["security"].toString().compare("reality", Qt::CaseInsensitive) == 0)
            {
                LOG("v2ray-core does not support REALITY. Falling back to TLS; use Xray-core for REALITY connections.");
                auto reality = stream["realitySettings"].toObject();
                auto tls = stream["tlsSettings"].toObject();
                if (tls["serverName"].toString().isEmpty())
                    tls["serverName"] = reality["serverName"].toString();
                stream["security"] = tls["serverName"].toString().isEmpty() ? "none" : "tls";
                stream["tlsSettings"] = tls;
                stream.remove("realitySettings");
            }

            stream.remove("method");
            stream.remove("finalmask");
            entry["streamSettings"] = stream;
        }

        bool RuleHasEffectiveFields(const QJsonObject &rule)
        {
            static const QStringList fields{ "domain", "domains", "ip", "port", "network", "source", "sourceIP", "sourcePort",
                                             "inboundTag", "protocol", "user", "attrs", "localIP", "localPort", "process",
                                             "localOS", "vlessRoute", "webhook" };
            for (const auto &field : fields)
            {
                const auto value = rule.value(field);
                if (value.isArray() && !value.toArray().isEmpty())
                    return true;
                if (value.isObject() && !value.toObject().isEmpty())
                    return true;
                if (value.isString() && !value.toString().isEmpty())
                    return true;
                if (value.isBool() || value.isDouble())
                    return true;
            }
            return false;
        }

        void ApplyXrayRuleCompatibility(QJsonObject &rule)
        {
            const auto attrs = rule["attrs"];
            if (attrs.isString() && !attrs.toString().trimmed().isEmpty())
            {
                const auto doc = QJsonDocument::fromJson(attrs.toString().trimmed().toUtf8());
                if (doc.isObject())
                    rule["attrs"] = doc.object();
                else
                {
                    LOG("Dropping v2ray-core string attrs for Xray: " + attrs.toString());
                    rule.remove("attrs");
                }
            }
            else if (attrs.isObject())
            {
                const auto object = attrs.toObject();
                if (object.isEmpty())
                {
                    rule.remove("attrs");
                }
                else
                {
                    // Xray expects map<string,string>.  Normalize scalar
                    // values imported from other tools.
                    QJsonObject normalized;
                    for (const auto &key : object.keys())
                    {
                        const auto value = object.value(key);
                        normalized[key] = value.toVariant().toString();
                    }
                    rule["attrs"] = normalized;
                }
            }
        }

        void ApplyV2rayRuleCompatibility(QJsonObject &rule)
        {
            // These conditions are Xray-only.
            for (const auto &key : { "ruleTag", "localIP", "localPort", "process", "localOS", "vlessRoute", "webhook" })
                rule.remove(key);
            const auto attrs = rule["attrs"];
            if (attrs.isObject())
            {
                // v2ray-core's attrs is a string expression, not a map.
                LOG("Dropping Xray attrs map for v2ray-core.");
                rule.remove("attrs");
            }
        }

        void ApplyXrayDNSCompatibility(CONFIGROOT &root)
        {
            auto dns = root["dns"].toObject();
            if (dns.isEmpty())
                return;
            // Xray-core has no top-level domain matcher switch.
            dns.remove("domainMatcher");
            auto servers = dns["servers"].toArray();
            for (auto i = 0; i < servers.count(); i++)
            {
                auto server = servers[i].toObject();
                if (server.isEmpty())
                    continue;
                for (const auto &key : { "cacheStrategy", "fallbackStrategy" })
                    server.remove(key);
                servers[i] = server;
            }
            dns["servers"] = servers;
            root["dns"] = dns;
        }

        void ApplyV2rayDNSCompatibility(CONFIGROOT &root)
        {
            auto dns = root["dns"].toObject();
            if (dns.isEmpty())
                return;
            // v2ray-core uses "expectIps" (lower-case p) and does not know
            // Xray's per-server extensions.
            auto servers = dns["servers"].toArray();
            for (auto i = 0; i < servers.count(); i++)
            {
                auto server = servers[i].toObject();
                if (server.isEmpty())
                    continue;
                if (server.contains("expectIPs"))
                {
                    server["expectIps"] = server["expectIPs"];
                    server.remove("expectIPs");
                }
                for (const auto &key : { "id", "unexpectedIPs", "finalQuery", "timeoutMs", "serveStale", "serveExpiredTTL", "disableCache" })
                    server.remove(key);
                servers[i] = server;
            }
            dns["servers"] = servers;
            for (const auto &key : { "script", "enableParallelQuery", "useSystemHosts", "serveStale", "serveExpiredTTL" })
                dns.remove(key);
            root["dns"] = dns;
        }

        void ApplyVlessCompatibility(QJsonObject &entry, const bool forXray, const bool isInbound)
        {
            Q_UNUSED(forXray)
            if (entry["protocol"].toString().toLower() != "vless")
                return;
            auto settings = entry["settings"].toObject();
            if (isInbound)
            {
                // Xray rejects "encryption" in inbound users; v2ray-core also
                // expects "decryption": "none".
                auto users = settings["users"].toArray();
                auto clients = settings["clients"].toArray();
                const auto cleanUsers = [](QJsonArray list) {
                    for (auto i = 0; i < list.count(); i++)
                    {
                        auto user = list[i].toObject();
                        user.remove("encryption");
                        auto flow = user["flow"].toString();
                        if (flow.startsWith("xtls-rprx-") && flow != "xtls-rprx-vision" && flow != "xtls-rprx-vision-udp443")
                            user["flow"] = flow.endsWith("-udp443") ? "xtls-rprx-vision-udp443" : "xtls-rprx-vision";
                        list[i] = user;
                    }
                    return list;
                };
                if (!users.isEmpty())
                    settings["users"] = cleanUsers(users);
                if (!clients.isEmpty())
                    settings["clients"] = cleanUsers(clients);
                if (settings["decryption"].toString().isEmpty())
                    settings["decryption"] = "none";
            }
            else
            {
                // Both cores require an explicit encryption field for VLESS
                // outbound users.
                auto vnext = settings["vnext"].toArray();
                for (auto i = 0; i < vnext.count(); i++)
                {
                    auto server = vnext[i].toObject();
                    auto users = server["users"].toArray();
                    for (auto j = 0; j < users.count(); j++)
                    {
                        auto user = users[j].toObject();
                        if (user["encryption"].toString().isEmpty())
                            user["encryption"] = "none";
                        auto flow = user["flow"].toString();
                        if (flow.startsWith("xtls-rprx-") && flow != "xtls-rprx-vision" && flow != "xtls-rprx-vision-udp443")
                            user["flow"] = flow.endsWith("-udp443") ? "xtls-rprx-vision-udp443" : "xtls-rprx-vision";
                        users[j] = user;
                    }
                    server["users"] = users;
                    vnext[i] = server;
                }
                settings["vnext"] = vnext;
            }
            entry["settings"] = settings;
        }

        void ApplyOutboundSettingsCompatibility(QJsonObject &entry, const bool forXray)
        {
            const auto protocol = entry["protocol"].toString().toLower();
            auto settings = entry["settings"].toObject();
            if (settings.isEmpty())
                return;

            if (protocol == "freedom" && forXray)
            {
                auto fragment = settings["fragment"].toObject();
                if (!fragment.isEmpty())
                {
                    for (const auto &key : { "length", "interval", "maxSplit" })
                        NormalizeRangeField(fragment, key);
                    settings["fragment"] = fragment;
                }
                auto noises = settings["noises"].toArray();
                for (auto i = 0; i < noises.count(); i++)
                {
                    auto noise = noises[i].toObject();
                    NormalizeRangeField(noise, "delay");
                    noises[i] = noise;
                }
                if (!noises.isEmpty())
                    settings["noises"] = noises;
                auto noise = settings["noise"].toObject();
                if (!noise.isEmpty())
                {
                    NormalizeRangeField(noise, "delay");
                    settings["noise"] = noise;
                }
                auto finalRules = settings["finalRules"].toArray();
                for (auto i = 0; i < finalRules.count(); i++)
                {
                    auto rule = finalRules[i].toObject();
                    NormalizeRangeField(rule, "blockDelay");
                    finalRules[i] = rule;
                }
                if (!finalRules.isEmpty())
                    settings["finalRules"] = finalRules;
            }
            else if (protocol == "freedom" && !forXray)
            {
                for (const auto &key : { "fragment", "noise", "noises", "targetStrategy", "proxyProtocol", "ipsBlocked", "finalRules" })
                    settings.remove(key);
            }
            else if (protocol == "blackhole" && !forXray)
            {
                auto response = settings["response"].toObject();
                if (response["type"].toString().compare("custom", Qt::CaseInsensitive) == 0)
                {
                    LOG("v2ray-core does not support custom blackhole responses; using HTTP.");
                    response["type"] = "http";
                    response.remove("customResponseData");
                    settings["response"] = response;
                }
            }
            else if (protocol == "dns" && !forXray)
            {
                // v2ray-core's DNS outbound uses the same settings shape.
            }
            entry["settings"] = settings;
        }

        void EnsureObservatory(CONFIGROOT &root)
        {
            const auto routing = root["routing"].toObject();
            const auto balancers = routing["balancers"].toArray();
            if (balancers.isEmpty())
                return;

            QSet<QString> subjects;
            for (const auto &balancerVal : balancers)
            {
                const auto balancer = balancerVal.toObject();
                for (const auto &selector : balancer["selector"].toArray())
                {
                    const auto text = selector.toString();
                    if (!text.isEmpty())
                        subjects.insert(text);
                }
            }
            if (subjects.isEmpty())
            {
                for (const auto &outbound : root["outbounds"].toArray())
                {
                    const auto tag = outbound.toObject()["tag"].toString();
                    if (!tag.isEmpty())
                        subjects.insert(tag);
                }
            }

            QJsonArray subjectList;
            for (const auto &subject : subjects)
                subjectList.append(subject);

            QJsonObject observatory;
            observatory["subjectSelector"] = subjectList;
            observatory["probeURL"] = "https://www.google.com/generate_204";
            observatory["probeInterval"] = "10m";
            observatory["enableConcurrency"] = true;

            // Keep a user supplied observatory, but fill in the selector when
            // it was omitted.
            auto existing = root["observatory"].toObject();
            if (existing.isEmpty())
                root["observatory"] = observatory;
            else
            {
                if (existing["subjectSelector"].toArray().isEmpty())
                    existing["subjectSelector"] = subjectList;
                root["observatory"] = existing;
            }
        }
    } // namespace

    void NormalizeLegacyStreamSettings(CONFIGROOT &root)
    {
        for (const auto &key : { "inbounds", "outbounds" })
        {
            auto entries = root[key].toArray();
            for (auto i = 0; i < entries.count(); i++)
            {
                auto entry = entries[i].toObject();
                NormalizeStreamObject(entry);
                entries[i] = entry;
            }
            if (!entries.isEmpty())
                root[key] = entries;
        }

        auto routing = root["routing"].toObject();
        auto rules = routing["rules"].toArray();
        for (auto i = 0; i < rules.count(); i++)
        {
            auto rule = rules[i].toObject();
            StripInternalRuleFields(rule);
            rules[i] = rule;
        }
        if (!rules.isEmpty())
        {
            routing["rules"] = rules;
            root["routing"] = routing;
        }
    }

    void ApplyCoreCompatibilityFilter(CONFIGROOT &root, const Qv2rayCoreType coreType)
    {
        const bool forXray = coreType == CORE_XRAY;

        for (const auto &key : { "inbounds", "outbounds" })
        {
            auto entries = root[key].toArray();
            for (auto i = 0; i < entries.count(); i++)
            {
                auto entry = entries[i].toObject();
                if (forXray)
                    ApplyXrayStreamCompatibility(entry);
                else
                    ApplyV2rayStreamCompatibility(entry);

                ApplyVlessCompatibility(entry, forXray, key == QStringLiteral("inbounds"));
                ApplyOutboundSettingsCompatibility(entry, forXray);

                if (forXray)
                {
                    if (entry.contains("proxySettings"))
                    {
                        const auto proxySettings = entry["proxySettings"].toObject();
                        const auto proxyTag = proxySettings["tag"].toString();
                        if (!proxyTag.isEmpty())
                        {
                            auto stream = entry["streamSettings"].toObject();
                            auto sockopt = stream["sockopt"].toObject();
                            sockopt["dialerProxy"] = proxyTag;
                            stream["sockopt"] = sockopt;
                            entry["streamSettings"] = stream;
                        }
                        entry.remove("proxySettings");
                    }
                }
                entries[i] = entry;
            }
            if (!entries.isEmpty())
                root[key] = entries;
        }

        auto routing = root["routing"].toObject();
        auto rules = routing["rules"].toArray();
        QJsonArray effectiveRules;
        for (auto i = 0; i < rules.count(); i++)
        {
            auto rule = rules[i].toObject();
            StripInternalRuleFields(rule);
            if (forXray)
                ApplyXrayRuleCompatibility(rule);
            else
                ApplyV2rayRuleCompatibility(rule);
            // After removing fields unsupported by the selected core a rule
            // may have no conditions left.  Both cores reject such rules.
            if (RuleHasEffectiveFields(rule))
                effectiveRules.append(rule);
            else
                LOG("Dropping a routing rule with no conditions supported by the selected core.");
        }
        if (!routing.isEmpty() || !effectiveRules.isEmpty())
        {
            routing["rules"] = effectiveRules;
            root["routing"] = routing;
        }

        if (!forXray)
        {
            // roundrobin is an Xray-only balancer strategy.  v2ray-core has
            // random/leastPing/leastLoad.
            auto balancers = routing["balancers"].toArray();
            for (auto i = 0; i < balancers.count(); i++)
            {
                auto balancer = balancers[i].toObject();
                auto strategy = balancer["strategy"].toObject();
                if (strategy["type"].toString().compare("roundrobin", Qt::CaseInsensitive) == 0)
                {
                    strategy["type"] = "random";
                    balancer["strategy"] = strategy;
                    balancers[i] = balancer;
                }
            }
            if (!balancers.isEmpty())
            {
                routing["balancers"] = balancers;
                root["routing"] = routing;
            }
        }

        if (forXray)
            ApplyXrayDNSCompatibility(root);
        else
            ApplyV2rayDNSCompatibility(root);

        if (forXray)
        {
            // v2ray-core-only features.
            root.remove("browserForwarder");
        }
        else
        {
            // Xray-core-only features.
            root.remove("finalmask");
        }

        // Both cores require an observatory app when a balancer is used.
        EnsureObservatory(root);
    }

    void XrayCompatibilityFilter(CONFIGROOT &root)
    {
        ApplyCoreCompatibilityFilter(root, CORE_XRAY);
    }

} // namespace Qv2ray::core::connection::generation::filters
