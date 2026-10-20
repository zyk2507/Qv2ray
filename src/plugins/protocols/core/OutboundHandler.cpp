#include "OutboundHandler.hpp"

#include "3rdparty/QJsonStruct/QJsonIO.hpp"

#include <QJsonDocument>
#include <QUrl>
#include <QUrlQuery>

using namespace Qv2rayPlugin;

const Qv2rayPlugin::OutboundInfoObject BuiltinSerializer::GetOutboundInfo(const QString &protocol, const QJsonObject &outbound) const
{
    OutboundInfoObject obj;
    obj[INFO_PROTOCOL] = protocol;
    if (protocol == "http")
    {
        const auto http = HttpServerObject::fromJson(outbound["servers"].toArray().first());
        obj[INFO_SERVER] = http.address;
        obj[INFO_PORT] = http.port;
    }
    else if (protocol == "socks")
    {
        const auto socks = SocksServerObject::fromJson(outbound["servers"].toArray().first());
        obj[INFO_SERVER] = socks.address;
        obj[INFO_PORT] = socks.port;
    }
    else if (protocol == "vmess")
    {
        const auto vmess = VMessServerObject::fromJson(outbound["vnext"].toArray().first());
        obj[INFO_SERVER] = vmess.address;
        obj[INFO_PORT] = vmess.port;
    }
    else if (protocol == "vless")
    {
        const auto vless = VLESSServerObject::fromJson(outbound["vnext"].toArray().first());
        obj[INFO_SERVER] = vless.address;
        obj[INFO_PORT] = vless.port;
    }
    else if (protocol == "shadowsocks")
    {
        const auto ss = ShadowSocksServerObject::fromJson(outbound["servers"].toArray().first());
        obj[INFO_SERVER] = ss.address;
        obj[INFO_PORT] = ss.port;
    }
    return obj;
}

const void BuiltinSerializer::SetOutboundInfo(const QString &protocol, const Qv2rayPlugin::OutboundInfoObject &info, QJsonObject &outbound) const
{
    if ((QStringList{ "http", "socks", "shadowsocks" }).contains(protocol))
    {
        QJsonIO::SetValue(outbound, info[INFO_SERVER].toString(), "servers", 0, "address");
        QJsonIO::SetValue(outbound, info[INFO_PORT].toInt(), "servers", 0, "port");
    }
    else if ((QStringList{ "vless", "vmess" }).contains(protocol))
    {
        QJsonIO::SetValue(outbound, info[INFO_SERVER].toString(), "vnext", 0, "address");
        QJsonIO::SetValue(outbound, info[INFO_PORT].toInt(), "vnext", 0, "port");
    }
}

const QString BuiltinSerializer::SerializeOutbound(const QString &protocol, const QString &alias, const QString &, const QJsonObject &obj,
                                                   const QJsonObject &objStream) const
{
    if (protocol == "http" || protocol == "socks")
    {
        QUrl url;
        url.setScheme(protocol);
        url.setHost(QJsonIO::GetValue(obj, { "servers", 0, "address" }).toString());
        url.setPort(QJsonIO::GetValue(obj, { "servers", 0, "port" }).toInt());
        if (QJsonIO::GetValue(obj, { "servers", 0 }).toObject().contains("users"))
        {
            url.setUserName(QJsonIO::GetValue(obj, { "servers", 0, "users", 0, "user" }).toString());
            url.setPassword(QJsonIO::GetValue(obj, { "servers", 0, "users", 0, "pass" }).toString());
        }
        return url.toString();
    }
    if (protocol == "vless")
    {
        QUrl url;
        url.setFragment(QUrl::toPercentEncoding(alias));
        url.setScheme(protocol);
        url.setHost(QJsonIO::GetValue(obj, { "vnext", 0, "address" }).toString());
        url.setPort(QJsonIO::GetValue(obj, { "vnext", 0, "port" }).toInt());
        url.setUserName(QJsonIO::GetValue(obj, { "vnext", 0, "users", 0, "id" }).toString());

        // -------- COMMON INFORMATION --------
        QUrlQuery query;
        const auto encryption = QJsonIO::GetValue(obj, { "vnext", 0, "users", 0, "encryption" }).toString("none");
        if (encryption != "none")
            query.addQueryItem("encryption", encryption);
        const auto flow = QJsonIO::GetValue(obj, { "vnext", 0, "users", 0, "flow" }).toString();
        if (!flow.isEmpty())
            query.addQueryItem("flow", flow);

        auto network = QJsonIO::GetValue(objStream, "network").toString("tcp");
        if (network == "raw")
            network = "tcp";
        if (network == "splithttp")
            network = "xhttp";
        if (network != "tcp")
            query.addQueryItem("type", network);

        auto security = QJsonIO::GetValue(objStream, "security").toString("none");
        if (security == "xtls")
            security = "tls";
        if (security != "none")
            query.addQueryItem("security", security);

        // -------- TRANSPORT RELATED --------
        if (network == "kcp")
        {
            const auto seed = QJsonIO::GetValue(objStream, { "kcpSettings", "seed" }).toString();
            if (!seed.isEmpty())
                query.addQueryItem("seed", QUrl::toPercentEncoding(seed));

            const auto headerType = QJsonIO::GetValue(objStream, { "kcpSettings", "header", "type" }).toString("none");
            if (headerType != "none")
                query.addQueryItem("headerType", headerType);
        }
        else if (network == "http")
        {
            const auto path = QJsonIO::GetValue(objStream, { "httpSettings", "path" }).toString("/");
            query.addQueryItem("path", QUrl::toPercentEncoding(path));

            const auto hosts = QJsonIO::GetValue(objStream, { "httpSettings", "host" }).toArray();
            QStringList hostList;
            for (const auto item : hosts)
            {
                const auto host = item.toString();
                if (!host.isEmpty())
                    hostList << host;
            }
            query.addQueryItem("host", QUrl::toPercentEncoding(hostList.join(",")));
        }
        else if (network == "ws")
        {
            const auto path = QJsonIO::GetValue(objStream, { "wsSettings", "path" }).toString("/");
            query.addQueryItem("path", QUrl::toPercentEncoding(path));

            const auto host = QJsonIO::GetValue(objStream, { "wsSettings", "host" })
                                  .toString(QJsonIO::GetValue(objStream, { "wsSettings", "headers", "Host" }).toString());
            if (!host.isEmpty())
                query.addQueryItem("host", host);
        }
        else if (network == "httpupgrade")
        {
            const auto path = QJsonIO::GetValue(objStream, { "httpupgradeSettings", "path" }).toString("/");
            query.addQueryItem("path", QUrl::toPercentEncoding(path));
            const auto host = QJsonIO::GetValue(objStream, { "httpupgradeSettings", "host" }).toString();
            if (!host.isEmpty())
                query.addQueryItem("host", host);
        }
        else if (network == "xhttp")
        {
            const auto &key = "xhttpSettings";
            const auto path = QJsonIO::GetValue(objStream, { key, "path" }).toString("/");
            query.addQueryItem("path", QUrl::toPercentEncoding(path));
            const auto host = QJsonIO::GetValue(objStream, { key, "host" }).toString();
            if (!host.isEmpty())
                query.addQueryItem("host", host);
            const auto mode = QJsonIO::GetValue(objStream, { key, "mode" }).toString();
            if (!mode.isEmpty())
                query.addQueryItem("mode", mode);
            const auto extra = QJsonIO::GetValue(objStream, { key, "extra" }).toObject();
            if (!extra.isEmpty())
                query.addQueryItem("extra", QUrl::toPercentEncoding(QString::fromUtf8(QJsonDocument(extra).toJson(QJsonDocument::Compact))));
        }
        else if (network == "quic")
        {
            const auto quicSecurity = QJsonIO::GetValue(objStream, { "quicSettings", "security" }).toString("none");
            if (quicSecurity != "none")
            {
                query.addQueryItem("quicSecurity", quicSecurity);

                const auto key = QJsonIO::GetValue(objStream, { "quicSettings", "key" }).toString();
                query.addQueryItem("key", QUrl::toPercentEncoding(key));

                const auto headerType = QJsonIO::GetValue(objStream, { "quicSettings", "header", "type" }).toString("none");
                if (headerType != "none")
                    query.addQueryItem("headerType", headerType);
            }
        }
        else if (network == "grpc")
        {
            const auto serviceName = QJsonIO::GetValue(objStream, { "grpcSettings", "serviceName" }).toString("GunService");
            if (serviceName != "GunService")
                query.addQueryItem("serviceName", QUrl::toPercentEncoding(serviceName));

            const auto multiMode = QJsonIO::GetValue(objStream, { "grpcSettings", "multiMode" }).toBool(false);
            if (multiMode)
                query.addQueryItem("mode", "multi");
            const auto authority = QJsonIO::GetValue(objStream, { "grpcSettings", "authority" }).toString();
            if (!authority.isEmpty())
                query.addQueryItem("authority", authority);
        }
        // -------- TLS / REALITY RELATED --------
        if (security == "reality")
        {
            const auto &key = "realitySettings";
            const auto sni = QJsonIO::GetValue(objStream, { key, "serverName" }).toString();
            if (!sni.isEmpty())
                query.addQueryItem("sni", sni);
            const auto fp = QJsonIO::GetValue(objStream, { key, "fingerprint" }).toString();
            if (!fp.isEmpty())
                query.addQueryItem("fp", fp);
            auto publicKey = QJsonIO::GetValue(objStream, { key, "publicKey" }).toString();
            if (publicKey.isEmpty())
                publicKey = QJsonIO::GetValue(objStream, { key, "password" }).toString();
            if (!publicKey.isEmpty())
                query.addQueryItem("pbk", publicKey);
            const auto shortId = QJsonIO::GetValue(objStream, { key, "shortId" }).toString();
            if (!shortId.isEmpty())
                query.addQueryItem("sid", shortId);
            const auto spiderX = QJsonIO::GetValue(objStream, { key, "spiderX" }).toString();
            if (!spiderX.isEmpty() && spiderX != "/")
                query.addQueryItem("spx", spiderX);
            const auto mldsa65Verify = QJsonIO::GetValue(objStream, { key, "mldsa65Verify" }).toString();
            if (!mldsa65Verify.isEmpty())
                query.addQueryItem("mldsa65Verify", mldsa65Verify);
        }
        else if (security == "tls")
        {
            const auto sni = QJsonIO::GetValue(objStream, { "tlsSettings", "serverName" }).toString();
            if (!sni.isEmpty())
                query.addQueryItem("sni", sni);
            const auto fp = QJsonIO::GetValue(objStream, { "tlsSettings", "fingerprint" }).toString();
            if (!fp.isEmpty())
                query.addQueryItem("fp", fp);
            const auto pinned = QJsonIO::GetValue(objStream, { "tlsSettings", "pinnedPeerCertSha256" }).toString();
            if (!pinned.isEmpty())
                query.addQueryItem("pinnedPeerCertSha256", pinned);
            const auto alpnArray = QJsonIO::GetValue(objStream, { "tlsSettings", "alpn" }).toArray();
            QStringList alpnList;
            for (const auto v : alpnArray)
            {
                const auto alpn = v.toString();
                if (!alpn.isEmpty())
                    alpnList << alpn;
            }
            if (!alpnList.isEmpty())
                query.addQueryItem("alpn", QUrl::toPercentEncoding(alpnList.join(",")));
        }

        // ======== END OF QUERY ========
        url.setQuery(query);
        return url.toString(QUrl::FullyEncoded);
    }
    return "(Unsupported)";
}

const QPair<QString, QJsonObject> BuiltinSerializer::DeserializeOutbound(const QString &link, QString *alias, QString *errorMessage) const
{
    if (link.startsWith("http://") || link.startsWith("socks://"))
    {
        const QUrl url = link;
        QJsonObject root;
        QJsonIO::SetValue(root, url.host(), "servers", 0, "address");
        QJsonIO::SetValue(root, url.port(), "servers", 0, "port");
        if (!url.userName().isEmpty())
        {
            QJsonIO::SetValue(root, url.userName(), "servers", 0, "users", 0, "user");
        }
        if (!url.password().isEmpty())
        {
            QJsonIO::SetValue(root, url.password(), "servers", 0, "users", 0, "pass");
        }
        return { url.scheme(), root };
    }
    return {};
}

const QList<QString> BuiltinSerializer::SupportedLinkPrefixes() const
{
    return { "http", "socks" };
}
