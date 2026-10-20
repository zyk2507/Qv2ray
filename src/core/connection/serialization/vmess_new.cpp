#include "core/CoreUtils.hpp"
#include "core/connection/Generation.hpp"
#include "core/connection/Serialization.hpp"
#include "utils/QvHelpers.hpp"

#include <QJsonDocument>
#include <QUrl>
#include <QUrlQuery>

namespace Qv2ray::core::connection
{
    namespace serialization::vmess_new
    {
        const static QStringList NetworkType{ "tcp", "raw", "http", "ws", "kcp", "quic", "grpc", "xhttp", "splithttp", "httpupgrade" };
        const static QStringList QuicSecurityTypes{ "none", "aes-128-gcm", "chacha20-poly1305" };
        const static QStringList QuicKcpHeaderTypes{ "none", "srtp", "utp", "wechat-video", "dtls", "wireguard" };
        const static QStringList FalseTypes{ "false", "False", "No", "Off", "0" };

        CONFIGROOT Deserialize(const QString &vmessStr, QString *alias, QString *errMessage)
        {
            QUrl url{ vmessStr };
            QUrlQuery query{ url };
            //
#define default CONFIGROOT()
            if (!url.isValid())
            {
                *errMessage = QObject::tr("vmess:// url is invalid");
                return default;
            }

            // If previous alias is empty, just the PS is needed, else, append a "_"
            const auto name = url.fragment(QUrl::FullyDecoded).trimmed();
            *alias = alias->isEmpty() ? name : (*alias + "_" + name);

            VMessServerObject server;
            server.users << VMessServerObject::UserObject{};

            StreamSettingsObject stream;
            QString net;
            bool tls = false;
            // Check streamSettings
            {
                for (const auto &_protocol : url.userName().split("+"))
                {
                    if (_protocol == "tls")
                        tls = true;
                    else
                        net = _protocol;
                }
                if (net == "raw")
                    net = "tcp";
                if (!NetworkType.contains(net))
                {
                    *errMessage = QObject::tr("Invalid streamSettings protocol: ") + net;
                    return default;
                }
                stream.network = net;
                stream.security = tls ? "tls" : "";
            }
            // Host Port UUID AlterID
            {
                const auto host = url.host();
                int port = url.port();
                QString uuid;
                int aid;
                {
                    const auto pswd = url.password();
                    const auto index = pswd.lastIndexOf("-");
                    uuid = pswd.mid(0, index);
                    aid = pswd.right(pswd.length() - index - 1).toInt();
                }
                server.address = host;
                server.port = port;
                server.users.first().id = uuid;
                server.users.first().alterId = aid;
                server.users.first().security = "auto";
            }

            const static auto getQueryValue = [&query](const QString &key, const QString &defaultValue) {
                if (query.hasQueryItem(key))
                    return query.queryItemValue(key, QUrl::FullyDecoded);
                else
                    return defaultValue;
            };

            //
            // Begin transport settings parser
            {
                if (net == "tcp")
                {
                    stream.tcpSettings.header.type = getQueryValue("type", "none");
                }
                else if (net == "http")
                {
                    stream.httpSettings.host.append(getQueryValue("host", ""));
                    stream.httpSettings.path = getQueryValue("path", "/");
                }
                else if (net == "ws")
                {
                    const auto host = getQueryValue("host", "");
                    stream.wsSettings.host = host;
                    if (!host.isEmpty())
                        stream.wsSettings.headers["Host"] = host;
                    stream.wsSettings.path = getQueryValue("path", "/");
                }
                else if (net == "kcp")
                {
                    stream.kcpSettings.seed = getQueryValue("seed", "");
                    stream.kcpSettings.header.type = getQueryValue("type", "none");
                }
                else if (net == "quic")
                {
                    stream.quicSettings.security = getQueryValue("security", "none");
                    stream.quicSettings.key = getQueryValue("key", "");
                    stream.quicSettings.header.type = getQueryValue("type", "none");
                }
                else if (net == "grpc")
                {
                    stream.grpcSettings.serviceName = getQueryValue("serviceName", "");
                    stream.grpcSettings.authority = getQueryValue("authority", "");
                    stream.grpcSettings.multiMode = getQueryValue("mode", "") == "multi";
                }
                else if (net == "xhttp" || net == "splithttp")
                {
                    auto &xhttp = net == "xhttp" ? stream.xhttpSettings : stream.splithttpSettings;
                    xhttp.host = getQueryValue("host", "");
                    xhttp.path = getQueryValue("path", "/");
                    xhttp.mode = getQueryValue("mode", "auto");
                    const auto extra = getQueryValue("extra", "");
                    if (!extra.isEmpty())
                        xhttp.extra = JsonFromString(extra);
                }
                else if (net == "httpupgrade")
                {
                    stream.httpupgradeSettings.host = getQueryValue("host", "");
                    stream.httpupgradeSettings.path = getQueryValue("path", "/");
                }
                else
                {
                    *errMessage = QObject::tr("Unknown transport method: ") + net;
                    return default;
                }
            }
#undef default
            const auto security = getQueryValue("security", tls ? "tls" : "none").toLower();
            if (security == "reality")
            {
                stream.security = "reality";
                stream.realitySettings.serverName = getQueryValue("sni", getQueryValue("tlsServerName", ""));
                stream.realitySettings.fingerprint = getQueryValue("fp", "");
                stream.realitySettings.publicKey = getQueryValue("pbk", getQueryValue("publicKey", ""));
                stream.realitySettings.password = stream.realitySettings.publicKey;
                stream.realitySettings.shortId = getQueryValue("sid", getQueryValue("shortId", ""));
                stream.realitySettings.spiderX = getQueryValue("spx", getQueryValue("spiderX", "/"));
                stream.realitySettings.mldsa65Verify = getQueryValue("mldsa65Verify", "");
            }
            else if (security == "xtls")
            {
                // Legacy VMess XTLS links are migrated to TLS.
                stream.security = "tls";
                stream.tlsSettings.serverName = getQueryValue("sni", getQueryValue("tlsServerName", ""));
                stream.tlsSettings.allowInsecure = !FalseTypes.contains(getQueryValue("allowInsecure", "false"));
            }
            else if (tls)
            {
                stream.security = "tls";
                stream.tlsSettings.allowInsecure = !FalseTypes.contains(getQueryValue("allowInsecure", "false"));
                stream.tlsSettings.serverName = getQueryValue("sni", getQueryValue("tlsServerName", ""));
                stream.tlsSettings.fingerprint = getQueryValue("fp", "");
                const auto alpn = getQueryValue("alpn", "");
                if (!alpn.isEmpty())
                    stream.tlsSettings.alpn = alpn.split(",");
                stream.tlsSettings.pinnedPeerCertSha256 = getQueryValue("pinnedPeerCertSha256", "");
            }
            CONFIGROOT root;
            OUTBOUNDSETTING vConf;
            QJsonArray vnextArray;
            vnextArray.append(server.toJson());
            vConf["vnext"] = vnextArray;
            auto outbound = GenerateOutboundEntry(OUTBOUND_TAG_PROXY, "vmess", vConf, stream.toJson());
            //
            root["outbounds"] = QJsonArray{ outbound };
            return root;
        }

        const QString Serialize(const StreamSettingsObject &stream, const VMessServerObject &server, const QString &alias)
        {
            if (server.users.empty())
                return QObject::tr("(Empty Users)");
            QUrl url;
            QUrlQuery query;
            url.setFragment(alias, QUrl::StrictMode);

            if (stream.network == "tcp")
            {
                if (!stream.tcpSettings.header.type.isEmpty() && stream.tcpSettings.header.type != "none")
                    query.addQueryItem("type", stream.tcpSettings.header.type);
            }
            else if (stream.network == "http")
            {
                if (!stream.httpSettings.host.isEmpty())
                    query.addQueryItem("host", stream.httpSettings.host.first());
                query.addQueryItem("path", stream.httpSettings.path.isEmpty() ? "/" : stream.httpSettings.path);
            }
            else if (stream.network == "ws")
            {
                const auto host = !stream.wsSettings.host.isEmpty() ? stream.wsSettings.host :
                                                                     stream.wsSettings.headers.value("Host", stream.wsSettings.headers.value("host"));
                if (!host.isEmpty())
                    query.addQueryItem("host", host);
                if (!stream.wsSettings.path.isEmpty() && stream.wsSettings.path != "/")
                    query.addQueryItem("path", stream.wsSettings.path);
            }
            else if (stream.network == "httpupgrade")
            {
                if (!stream.httpupgradeSettings.host.isEmpty())
                    query.addQueryItem("host", stream.httpupgradeSettings.host);
                if (!stream.httpupgradeSettings.path.isEmpty() && stream.httpupgradeSettings.path != "/")
                    query.addQueryItem("path", stream.httpupgradeSettings.path);
            }
            else if (stream.network == "xhttp" || stream.network == "splithttp")
            {
                const auto &xhttp = stream.network == "xhttp" ? stream.xhttpSettings : stream.splithttpSettings;
                if (!xhttp.host.isEmpty())
                    query.addQueryItem("host", xhttp.host);
                if (!xhttp.path.isEmpty() && xhttp.path != "/")
                    query.addQueryItem("path", xhttp.path);
                if (!xhttp.mode.isEmpty())
                    query.addQueryItem("mode", xhttp.mode);
                if (!xhttp.extra.isEmpty())
                    query.addQueryItem("extra", QString::fromUtf8(QJsonDocument(xhttp.extra).toJson(QJsonDocument::Compact)));
            }
            else if (stream.network == "kcp")
            {
                if (!stream.kcpSettings.seed.isEmpty() && stream.kcpSettings.seed != "")
                    query.addQueryItem("seed", stream.kcpSettings.seed);
                if (!stream.kcpSettings.header.type.isEmpty() && stream.kcpSettings.header.type != "none")
                    query.addQueryItem("type", stream.kcpSettings.header.type);
            }
            else if (stream.network == "quic")
            {
                if (!stream.quicSettings.security.isEmpty() && stream.quicSettings.security != "none")
                    query.addQueryItem("security", stream.quicSettings.security);
                if (!stream.quicSettings.key.isEmpty())
                    query.addQueryItem("key", stream.quicSettings.key);
                if (!stream.quicSettings.header.type.isEmpty() && stream.quicSettings.header.type != "none")
                    query.addQueryItem("headers", stream.quicSettings.header.type);
            }
            else if (stream.network == "grpc")
            {
                if (!stream.grpcSettings.serviceName.isEmpty())
                    query.addQueryItem("serviceName", stream.grpcSettings.serviceName);
                if (!stream.grpcSettings.authority.isEmpty())
                    query.addQueryItem("authority", stream.grpcSettings.authority);
                if (stream.grpcSettings.multiMode)
                    query.addQueryItem("mode", "multi");
            }
            else
            {
                return {};
            }
            const bool hasTLS = stream.security == "tls" || stream.security == "xtls" || stream.security == "reality";
            auto protocol = stream.network == "raw" ? "tcp" : stream.network;
            if (hasTLS)
                protocol += "+tls";
            if (stream.security == "tls")
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
            else if (stream.security == "reality")
            {
                query.addQueryItem("security", "reality");
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
            else if (stream.security == "xtls")
            {
                if (!stream.xtlsSettings.serverName.isEmpty())
                    query.addQueryItem("sni", stream.xtlsSettings.serverName);
            }
            url.setPath("/");
            url.setScheme("vmess");
            url.setPassword(server.users.first().id + "-" + QSTRN(server.users.first().alterId));
            url.setHost(server.address);
            url.setPort(server.port);
            url.setUserName(protocol);
            url.setQuery(query);
            return url.toString();
        }
    } // namespace serialization::vmess_new
} // namespace Qv2ray::core::connection
