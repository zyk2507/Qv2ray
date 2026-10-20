#include "core/CoreUtils.hpp"
#include "core/connection/Generation.hpp"
#include "core/connection/Serialization.hpp"
#include "utils/QvHelpers.hpp"

#include <QJsonDocument>
#include <QUrl>
#include <QUrlQuery>

#define QV_MODULE_NAME "VLESSImporter"

namespace Qv2ray::core::connection
{
    namespace serialization::vless
    {
        namespace
        {
            QString getQueryValue(const QUrlQuery &query, const QString &key, const QString &defaultValue = "")
            {
                return query.hasQueryItem(key) ? query.queryItemValue(key, QUrl::FullyDecoded) : defaultValue;
            }

            void setHostForWs(QJsonObject &stream, const QString &host)
            {
                if (host.isEmpty())
                    return;
                // Xray uses the independent "host" field, while v2ray-core
                // reads the Host header.  Emit both for compatibility.
                QJsonIO::SetValue(stream, host, "wsSettings", "host");
                QJsonIO::SetValue(stream, host, "wsSettings", "headers", "Host");
            }
        } // namespace

        CONFIGROOT Deserialize(const QString &str, QString *alias, QString *errMessage)
        {
            // must start with vless://
            if (!str.startsWith("vless://", Qt::CaseInsensitive))
            {
                *errMessage = QObject::tr("VLESS link should start with vless://");
                return CONFIGROOT();
            }

            // parse url
            QUrl url(str);
            if (!url.isValid())
            {
                *errMessage = QObject::tr("link parse failed: %1").arg(url.errorString());
                return CONFIGROOT();
            }

            // fetch host
            const auto hostRaw = url.host();
            if (hostRaw.isEmpty())
            {
                *errMessage = QObject::tr("empty host");
                return CONFIGROOT();
            }
            const auto host = (hostRaw.startsWith('[') && hostRaw.endsWith(']')) ? hostRaw.mid(1, hostRaw.length() - 2) : hostRaw;

            // fetch port
            const auto port = url.port();
            if (port == -1)
            {
                *errMessage = QObject::tr("missing port");
                return CONFIGROOT();
            }

            // fetch remarks
            const auto remarks = url.fragment(QUrl::FullyDecoded);
            if (!remarks.isEmpty())
            {
                *alias = remarks;
            }

            // fetch uuid
            const auto uuid = url.userName(QUrl::FullyDecoded);
            if (uuid.isEmpty())
            {
                *errMessage = QObject::tr("missing uuid");
                return CONFIGROOT();
            }

            // initialize QJsonObject with basic info
            QJsonObject outbound;
            QJsonObject stream;

            QJsonIO::SetValue(outbound, "vless", "protocol");
            QJsonIO::SetValue(outbound, host, { "settings", "vnext", 0, "address" });
            QJsonIO::SetValue(outbound, port, { "settings", "vnext", 0, "port" });
            QJsonIO::SetValue(outbound, uuid, { "settings", "vnext", 0, "users", 0, "id" });

            // parse query
            const QUrlQuery query(url.query());

            // handle type / network
            auto type = getQueryValue(query, "type", getQueryValue(query, "network", "tcp"));
            if (type == "raw")
                type = "tcp";
            if (type == "websocket")
                type = "ws";
            if (type == "mkcp")
                type = "kcp";
            if (type == "gun")
                type = "grpc";
            if (type != "tcp")
                QJsonIO::SetValue(stream, type, "network");

            // handle encryption (Xray VLESS Encryption is carried here)
            const auto encryption = getQueryValue(query, "encryption", "none");
            QJsonIO::SetValue(outbound, encryption, { "settings", "vnext", 0, "users", 0, "encryption" });

            // flow (xtls-rprx-vision) is independent from the transport
            // security in modern cores.
            auto flow = getQueryValue(query, "flow");
            if (!flow.isEmpty())
                QJsonIO::SetValue(outbound, flow, { "settings", "vnext", 0, "users", 0, "flow" });

            // transport-wise settings
            if (type == "kcp")
            {
                const auto seed = getQueryValue(query, "seed");
                if (!seed.isEmpty())
                    QJsonIO::SetValue(stream, seed, { "kcpSettings", "seed" });

                const auto headerType = getQueryValue(query, "headerType", "none");
                if (headerType != "none")
                    QJsonIO::SetValue(stream, headerType, { "kcpSettings", "header", "type" });
            }
            else if (type == "http" || type == "h2")
            {
                const auto path = getQueryValue(query, "path", "/");
                if (path != "/")
                    QJsonIO::SetValue(stream, path, { "httpSettings", "path" });

                const auto hostValue = getQueryValue(query, "host");
                if (!hostValue.isEmpty())
                {
                    const auto hosts = QJsonArray::fromStringList(hostValue.split(","));
                    QJsonIO::SetValue(stream, hosts, { "httpSettings", "host" });
                }
            }
            else if (type == "ws")
            {
                const auto path = getQueryValue(query, "path", "/");
                if (path != "/")
                    QJsonIO::SetValue(stream, path, { "wsSettings", "path" });
                setHostForWs(stream, getQueryValue(query, "host"));
            }
            else if (type == "httpupgrade")
            {
                const auto path = getQueryValue(query, "path", "/");
                if (path != "/")
                    QJsonIO::SetValue(stream, path, { "httpupgradeSettings", "path" });
                const auto hostValue = getQueryValue(query, "host");
                if (!hostValue.isEmpty())
                    QJsonIO::SetValue(stream, hostValue, { "httpupgradeSettings", "host" });
            }
            else if (type == "xhttp" || type == "splithttp")
            {
                const auto settingsKey = type == "xhttp" ? "xhttpSettings" : "splithttpSettings";
                const auto path = getQueryValue(query, "path", "/");
                if (path != "/")
                    QJsonIO::SetValue(stream, path, { settingsKey, "path" });
                const auto hostValue = getQueryValue(query, "host");
                if (!hostValue.isEmpty())
                    QJsonIO::SetValue(stream, hostValue, { settingsKey, "host" });
                const auto mode = getQueryValue(query, "mode");
                if (!mode.isEmpty())
                    QJsonIO::SetValue(stream, mode, { settingsKey, "mode" });
                const auto extra = getQueryValue(query, "extra");
                if (!extra.isEmpty())
                {
                    const auto extraJson = JsonFromString(extra);
                    if (!extraJson.isEmpty())
                        QJsonIO::SetValue(stream, extraJson, { settingsKey, "extra" });
                }
            }
            else if (type == "quic")
            {
                const auto quicSecurity = getQueryValue(query, "quicSecurity");
                if (!quicSecurity.isEmpty())
                {
                    QJsonIO::SetValue(stream, quicSecurity, { "quicSettings", "security" });
                    if (quicSecurity != "none")
                        QJsonIO::SetValue(stream, getQueryValue(query, "key"), { "quicSettings", "key" });
                }
                const auto headerType = getQueryValue(query, "headerType", "none");
                if (headerType != "none")
                    QJsonIO::SetValue(stream, headerType, { "quicSettings", "header", "type" });
            }
            else if (type == "grpc")
            {
                const auto serviceName = getQueryValue(query, "serviceName");
                if (!serviceName.isEmpty())
                    QJsonIO::SetValue(stream, serviceName, { "grpcSettings", "serviceName" });

                if (getQueryValue(query, "mode") == "multi")
                    QJsonIO::SetValue(stream, true, { "grpcSettings", "multiMode" });

                const auto authority = getQueryValue(query, "authority");
                if (!authority.isEmpty())
                    QJsonIO::SetValue(stream, authority, { "grpcSettings", "authority" });
            }

            // security-wise settings
            auto security = getQueryValue(query, "security", "none").toLower();
            const auto sni = getQueryValue(query, "sni");
            const auto alpnRaw = getQueryValue(query, "alpn");
            const auto fingerprint = getQueryValue(query, "fp", getQueryValue(query, "fingerprint"));
            const auto allowInsecure = getQueryValue(query, "allowInsecure");

            if (security == "xtls")
            {
                // Legacy link: XTLS is now TLS + vision flow.
                security = "tls";
                if (flow.isEmpty())
                    flow = "xtls-rprx-vision";
                QJsonIO::SetValue(outbound, flow, { "settings", "vnext", 0, "users", 0, "flow" });
            }

            if (security != "none")
                QJsonIO::SetValue(stream, security, "security");

            if (security == "reality")
            {
                const auto publicKey = getQueryValue(query, "pbk", getQueryValue(query, "publicKey", getQueryValue(query, "password")));
                const auto shortId = getQueryValue(query, "sid", getQueryValue(query, "shortId"));
                const auto spiderX = getQueryValue(query, "spx", getQueryValue(query, "spiderX"));
                if (!sni.isEmpty())
                    QJsonIO::SetValue(stream, sni, { "realitySettings", "serverName" });
                if (!fingerprint.isEmpty())
                    QJsonIO::SetValue(stream, fingerprint, { "realitySettings", "fingerprint" });
                if (!publicKey.isEmpty())
                {
                    QJsonIO::SetValue(stream, publicKey, { "realitySettings", "publicKey" });
                    QJsonIO::SetValue(stream, publicKey, { "realitySettings", "password" });
                }
                if (!shortId.isEmpty())
                    QJsonIO::SetValue(stream, shortId, { "realitySettings", "shortId" });
                if (!spiderX.isEmpty())
                    QJsonIO::SetValue(stream, spiderX, { "realitySettings", "spiderX" });
                const auto mldsa65Verify = getQueryValue(query, "mldsa65Verify");
                if (!mldsa65Verify.isEmpty())
                    QJsonIO::SetValue(stream, mldsa65Verify, { "realitySettings", "mldsa65Verify" });
            }
            else if (security == "tls")
            {
                if (!sni.isEmpty())
                    QJsonIO::SetValue(stream, sni, { "tlsSettings", "serverName" });
                if (!fingerprint.isEmpty())
                    QJsonIO::SetValue(stream, fingerprint, { "tlsSettings", "fingerprint" });
                if (!alpnRaw.isEmpty())
                {
                    const auto alpnArray = QJsonArray::fromStringList(alpnRaw.split(","));
                    QJsonIO::SetValue(stream, alpnArray, { "tlsSettings", "alpn" });
                }
                if (!allowInsecure.isEmpty())
                {
                    const auto value = allowInsecure == "1" || allowInsecure.toLower() == "true";
                    QJsonIO::SetValue(stream, value, { "tlsSettings", "allowInsecure" });
                }
                const auto pinned = getQueryValue(query, "pinnedPeerCertSha256", getQueryValue(query, "pcs"));
                if (!pinned.isEmpty())
                    QJsonIO::SetValue(stream, pinned, { "tlsSettings", "pinnedPeerCertSha256" });
            }

            // assembling config
            CONFIGROOT root;
            outbound["streamSettings"] = stream;
            root["outbounds"] = QJsonArray{ outbound };

            // return
            return root;
        }

        const QString Serialize(const StreamSettingsObject &stream, const VLESSServerObject &server, const QString &alias)
        {
            if (server.users.isEmpty())
                return {};

            QUrl url;
            url.setScheme("vless");
            url.setHost(server.address);
            url.setPort(server.port);
            url.setUserName(server.users.first().id);
            url.setFragment(alias, QUrl::StrictMode);

            QUrlQuery query;
            const auto &user = server.users.first();
            if (!user.encryption.isEmpty() && user.encryption != "none")
                query.addQueryItem("encryption", user.encryption);
            if (!user.flow.isEmpty())
                query.addQueryItem("flow", user.flow);

            auto network = stream.network;
            if (network == "raw")
                network = "tcp";
            if (network != "tcp")
                query.addQueryItem("type", network);

            auto security = stream.security;
            if (security == "xtls")
                security = "tls";
            if (!security.isEmpty() && security != "none")
                query.addQueryItem("security", security);

            if (network == "kcp")
            {
                if (!stream.kcpSettings.seed.isEmpty())
                    query.addQueryItem("seed", stream.kcpSettings.seed);
                if (!stream.kcpSettings.header.type.isEmpty() && stream.kcpSettings.header.type != "none")
                    query.addQueryItem("headerType", stream.kcpSettings.header.type);
            }
            else if (network == "http" || network == "h2")
            {
                if (!stream.httpSettings.host.isEmpty())
                    query.addQueryItem("host", stream.httpSettings.host.join(","));
                query.addQueryItem("path", stream.httpSettings.path.isEmpty() ? "/" : stream.httpSettings.path);
            }
            else if (network == "ws")
            {
                const auto host = !stream.wsSettings.host.isEmpty() ? stream.wsSettings.host :
                                                                     stream.wsSettings.headers.value("Host", stream.wsSettings.headers.value("host"));
                if (!host.isEmpty())
                    query.addQueryItem("host", host);
                if (!stream.wsSettings.path.isEmpty() && stream.wsSettings.path != "/")
                    query.addQueryItem("path", stream.wsSettings.path);
            }
            else if (network == "httpupgrade")
            {
                if (!stream.httpupgradeSettings.host.isEmpty())
                    query.addQueryItem("host", stream.httpupgradeSettings.host);
                if (!stream.httpupgradeSettings.path.isEmpty() && stream.httpupgradeSettings.path != "/")
                    query.addQueryItem("path", stream.httpupgradeSettings.path);
            }
            else if (network == "xhttp" || network == "splithttp")
            {
                const auto &xhttp = network == "xhttp" ? stream.xhttpSettings : stream.splithttpSettings;
                if (!xhttp.host.isEmpty())
                    query.addQueryItem("host", xhttp.host);
                if (!xhttp.path.isEmpty() && xhttp.path != "/")
                    query.addQueryItem("path", xhttp.path);
                if (!xhttp.mode.isEmpty())
                    query.addQueryItem("mode", xhttp.mode);
                if (!xhttp.extra.isEmpty())
                    query.addQueryItem("extra", QString::fromUtf8(QJsonDocument(xhttp.extra).toJson(QJsonDocument::Compact)));
            }
            else if (network == "quic")
            {
                if (!stream.quicSettings.security.isEmpty() && stream.quicSettings.security != "none")
                {
                    query.addQueryItem("quicSecurity", stream.quicSettings.security);
                    query.addQueryItem("key", stream.quicSettings.key);
                }
                if (!stream.quicSettings.header.type.isEmpty() && stream.quicSettings.header.type != "none")
                    query.addQueryItem("headerType", stream.quicSettings.header.type);
            }
            else if (network == "grpc")
            {
                if (!stream.grpcSettings.serviceName.isEmpty())
                    query.addQueryItem("serviceName", stream.grpcSettings.serviceName);
                if (stream.grpcSettings.multiMode)
                    query.addQueryItem("mode", "multi");
                if (!stream.grpcSettings.authority.isEmpty())
                    query.addQueryItem("authority", stream.grpcSettings.authority);
            }

            if (security == "reality")
            {
                if (!stream.realitySettings.serverName.isEmpty())
                    query.addQueryItem("sni", stream.realitySettings.serverName);
                if (!stream.realitySettings.fingerprint.isEmpty())
                    query.addQueryItem("fp", stream.realitySettings.fingerprint);
                const auto publicKey = !stream.realitySettings.publicKey.isEmpty() ? stream.realitySettings.publicKey :
                                                                                     stream.realitySettings.password;
                if (!publicKey.isEmpty())
                    query.addQueryItem("pbk", publicKey);
                if (!stream.realitySettings.shortId.isEmpty())
                    query.addQueryItem("sid", stream.realitySettings.shortId);
                if (!stream.realitySettings.spiderX.isEmpty() && stream.realitySettings.spiderX != "/")
                    query.addQueryItem("spx", stream.realitySettings.spiderX);
                if (!stream.realitySettings.mldsa65Verify.isEmpty())
                    query.addQueryItem("mldsa65Verify", stream.realitySettings.mldsa65Verify);
            }
            else if (security == "tls")
            {
                if (!stream.tlsSettings.serverName.isEmpty())
                    query.addQueryItem("sni", stream.tlsSettings.serverName);
                if (!stream.tlsSettings.fingerprint.isEmpty())
                    query.addQueryItem("fp", stream.tlsSettings.fingerprint);
                if (!stream.tlsSettings.alpn.isEmpty())
                    query.addQueryItem("alpn", stream.tlsSettings.alpn.join(","));
                if (!stream.tlsSettings.pinnedPeerCertSha256.isEmpty())
                    query.addQueryItem("pinnedPeerCertSha256", stream.tlsSettings.pinnedPeerCertSha256);
            }

            url.setQuery(query);
            return url.toString(QUrl::FullyEncoded);
        }
    } // namespace serialization::vless
} // namespace Qv2ray::core::connection
