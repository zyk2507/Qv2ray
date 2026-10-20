#pragma once
#include "3rdparty/QJsonStruct/QJsonIO.hpp"
#include "3rdparty/QJsonStruct/QJsonStruct.hpp"

#include <QList>
#include <QMap>
#include <QRegularExpression>
#include <QString>

namespace Qv2ray::base::objects
{
    /**
     * A small wrapper that keeps a JSON value untouched.
     *
     * Several core options are intentionally polymorphic in JSON (for example
     * "attrs", "fakedns" and REALITY's "target").  QJsonStruct cannot store a
     * bare QJsonValue directly, so this wrapper is used for those fields.
     */
    struct QvJsonValueObject
    {
        QJsonValue value;
        QvJsonValueObject() = default;
        QvJsonValueObject(const QJsonValue &_value) : value(_value){};
        QvJsonValueObject &operator=(const QJsonValue &_value)
        {
            value = _value;
            return *this;
        }
        friend bool operator==(const QvJsonValueObject &left, const QvJsonValueObject &right)
        {
            return left.value == right.value;
        }
        friend bool operator!=(const QvJsonValueObject &left, const QvJsonValueObject &right)
        {
            return !(left == right);
        }
        void loadJson(const QJsonValue &d)
        {
            value = d;
        }
        [[nodiscard]] QJsonValue toJson() const
        {
            return value;
        }
    };

    /**
     * Xray accepts both an integer and an object with "from"/"to" for range
     * options.  Keep both representations round-trippable.
     */
    struct Int32RangeObject
    {
        int from = 0;
        int to = 0;
        Int32RangeObject() = default;
        Int32RangeObject(int _from, int _to) : from(_from), to(_to){};
        friend bool operator==(const Int32RangeObject &left, const Int32RangeObject &right)
        {
            return left.from == right.from && left.to == right.to;
        }
        friend bool operator!=(const Int32RangeObject &left, const Int32RangeObject &right)
        {
            return !(left == right);
        }
        void loadJson(const QJsonValue &d)
        {
            // Xray accepts a plain integer, the "from-to" string form and
            // (in older versions) an object with "from"/"to" members.
            if (d.isObject())
            {
                const auto obj = d.toObject();
                from = obj["from"].toInt(obj["left"].toInt());
                to = obj["to"].toInt(obj["right"].toInt(from));
                return;
            }
            if (d.isString())
            {
                const auto text = d.toString().trimmed();
                if (text.isEmpty())
                {
                    from = to = 0;
                    return;
                }
                bool singleOk = false;
                const auto single = text.toInt(&singleOk);
                if (singleOk)
                {
                    from = to = single;
                    return;
                }
                // Split on the dash which separates the two numbers, taking
                // negative numbers into account ("-114-514").
                static const QRegularExpression rangePattern(QStringLiteral("^(-?\\d+)-(-?\\d+)$"));
                const auto match = rangePattern.match(text);
                if (match.hasMatch())
                {
                    from = match.captured(1).toInt();
                    to = match.captured(2).toInt();
                    return;
                }
                from = to = 0;
                return;
            }
            from = to = d.toInt();
        }
        [[nodiscard]] QJsonValue toJson() const
        {
            // Current Xray-core only accepts an integer or the "from-to"
            // string form, not the object form used by some earlier builds.
            if (from == to)
                return from;
            return QStringLiteral("%1-%2").arg(from).arg(to);
        }
    };

    struct DNSObject
    {
        struct DNSServerObject
        {
            bool QV2RAY_DNS_IS_COMPLEX_DNS;
            QString address;
            int port;
            QList<QString> domains;
            QList<QString> expectIPs;
            // Modern v2ray-core and Xray-core DNS server fields.
            QString id;
            QString clientIp;
            QString tag;
            bool skipFallback = false;
            QString queryStrategy;
            QString cacheStrategy;
            QString fallbackStrategy;
            int timeoutMs = 0;
            bool disableCache = false;
            bool serveStale = false;
            int serveExpiredTTL = 0;
            bool finalQuery = false;
            QList<QString> unexpectedIPs;
            QvJsonValueObject fakedns;
            DNSServerObject() : QV2RAY_DNS_IS_COMPLEX_DNS(false), port(53){};
            DNSServerObject(const QString &_address) : DNSServerObject()
            {
                address = _address;
            };

            friend bool operator==(const DNSServerObject &left, const DNSServerObject &right)
            {
                return left.QV2RAY_DNS_IS_COMPLEX_DNS == right.QV2RAY_DNS_IS_COMPLEX_DNS && //
                       left.address == right.address &&                                     //
                       left.port == right.port &&                                           //
                       left.domains == right.domains &&                                     //
                       left.expectIPs == right.expectIPs &&                                 //
                       left.id == right.id &&                                               //
                       left.clientIp == right.clientIp &&                                   //
                       left.tag == right.tag &&                                             //
                       left.skipFallback == right.skipFallback &&                           //
                       left.queryStrategy == right.queryStrategy &&                         //
                       left.cacheStrategy == right.cacheStrategy &&                         //
                       left.fallbackStrategy == right.fallbackStrategy &&                   //
                       left.timeoutMs == right.timeoutMs &&                                 //
                       left.disableCache == right.disableCache &&                           //
                       left.serveStale == right.serveStale &&                               //
                       left.serveExpiredTTL == right.serveExpiredTTL &&                     //
                       left.finalQuery == right.finalQuery &&                               //
                       left.unexpectedIPs == right.unexpectedIPs &&                         //
                       left.fakedns == right.fakedns;
            }
            friend bool operator!=(const DNSServerObject &left, const DNSServerObject &right)
            {
                return !(left == right);
            }
            void loadJson(const QJsonValue &___json_object_)
            {
                DNSServerObject ___qjsonstruct_default_check;
                // A string represents the compact, legacy DNS server syntax.
                if (___json_object_.isString())
                {
                    address = ___json_object_.toString();
                    QV2RAY_DNS_IS_COMPLEX_DNS = false;
                    return;
                }
                // Any object is the complex form.  Do not trust the old
                // QV2RAY_DNS_IS_COMPLEX_DNS marker since imported configs do
                // not contain it.
                QV2RAY_DNS_IS_COMPLEX_DNS = true;
                FOREACH_CALL_FUNC(___DESERIALIZE_FROM_JSON_EXTRACT_B_F,
                                  F(address, port, domains, expectIPs, id, clientIp, tag, skipFallback, queryStrategy, cacheStrategy,
                                    fallbackStrategy, timeoutMs, disableCache, serveStale, serveExpiredTTL, finalQuery),
                                  F(unexpectedIPs, fakedns));
            }
            [[nodiscard]] static auto fromJson(const QJsonValue &___json_object_)
            {
                DNSServerObject _t;
                _t.loadJson(___json_object_);
                return _t;
            }
            [[nodiscard]] const QJsonObject toJson() const
            {
                QJsonObject ___json_object_;
                DNSServerObject ___qjsonstruct_default_check;
                FOREACH_CALL_FUNC(___SERIALIZE_TO_JSON_EXTRACT_B_F,
                                  F(address, port, domains, expectIPs, id, clientIp, tag, skipFallback, queryStrategy, cacheStrategy,
                                    fallbackStrategy, timeoutMs, disableCache, serveStale, serveExpiredTTL, finalQuery),
                                  F(unexpectedIPs, fakedns));
                return ___json_object_;
            }
        };

        // Xray/v2ray both allow a host to map to one address or an array of
        // addresses (and to a proxied domain).  Keep the original JSON value.
        QMap<QString, QvJsonValueObject> hosts;
        QList<DNSServerObject> servers;
        QString clientIp;
        QString tag;
        QString domainMatcher;
        bool disableCache = false;
        bool disableFallback = false;
        bool disableFallbackIfMatch = false;
        bool enableParallelQuery = false;
        bool useSystemHosts = false;
        bool serveStale = false;
        int serveExpiredTTL = 0;
        QString queryStrategy = "UseIP";
        QString cacheStrategy;
        QString fallbackStrategy;
        QString script;
        friend bool operator==(const DNSObject &left, const DNSObject &right)
        {
            return left.hosts == right.hosts &&                                     //
                   left.servers == right.servers &&                                 //
                   left.clientIp == right.clientIp &&                               //
                   left.tag == right.tag &&                                         //
                   left.domainMatcher == right.domainMatcher &&                     //
                   left.disableCache == right.disableCache &&                       //
                   left.disableFallback == right.disableFallback &&                 //
                   left.disableFallbackIfMatch == right.disableFallbackIfMatch &&   //
                   left.enableParallelQuery == right.enableParallelQuery &&         //
                   left.useSystemHosts == right.useSystemHosts &&                   //
                   left.serveStale == right.serveStale &&                           //
                   left.serveExpiredTTL == right.serveExpiredTTL &&                 //
                   left.queryStrategy == right.queryStrategy &&                     //
                   left.cacheStrategy == right.cacheStrategy &&                     //
                   left.fallbackStrategy == right.fallbackStrategy &&               //
                   left.script == right.script;
        }
        friend bool operator!=(const DNSObject &left, const DNSObject &right)
        {
            return !(left == right);
        }
        JSONSTRUCT_REGISTER(DNSObject, F(hosts, servers, clientIp, tag, domainMatcher, disableCache, disableFallback, disableFallbackIfMatch,
                                         enableParallelQuery, useSystemHosts, serveStale, serveExpiredTTL, queryStrategy, cacheStrategy,
                                         fallbackStrategy, script))
    };
    //
    // Used in config generation
    struct AccountObject
    {
        QString user;
        QString pass;
        JSONSTRUCT_COMPARE(AccountObject, user, pass)
        JSONSTRUCT_REGISTER(AccountObject, F(user, pass))
    };
    //
    //
    struct RuleObject
    {
        bool QV2RAY_RULE_ENABLED = true;
        QString QV2RAY_RULE_TAG = "New Rule";
        //
        QString type = "field";
        QString ruleTag;
        QList<QString> inboundTag;
        QString outboundTag;
        QString balancerTag;
        // Addresses
        QList<QString> source;
        QList<QString> domain;
        QList<QString> ip;
        // Ports
        QString sourcePort;
        QString port;
        //
        QString network;
        QList<QString> protocol;
        QList<QString> user;
        QList<QString> localIP;
        QString localPort;
        QList<QString> process;
        QList<QString> localOS;
        QString vlessRoute;
        QString domainMatcher;
        QvJsonValueObject attrs;
        QvJsonValueObject webhook;
        friend bool operator==(const RuleObject &left, const RuleObject &right)
        {
            return left.type == right.type && left.ruleTag == right.ruleTag && left.outboundTag == right.outboundTag &&
                   left.balancerTag == right.balancerTag && left.QV2RAY_RULE_ENABLED == right.QV2RAY_RULE_ENABLED &&
                   left.QV2RAY_RULE_TAG == right.QV2RAY_RULE_TAG && left.domain == right.domain && left.ip == right.ip &&
                   left.port == right.port && left.sourcePort == right.sourcePort && left.network == right.network &&
                   left.source == right.source && left.inboundTag == right.inboundTag && left.protocol == right.protocol &&
                   left.user == right.user && left.localIP == right.localIP && left.localPort == right.localPort &&
                   left.process == right.process && left.localOS == right.localOS && left.vlessRoute == right.vlessRoute &&
                   left.domainMatcher == right.domainMatcher && left.attrs == right.attrs && left.webhook == right.webhook;
        }
        JSONSTRUCT_REGISTER(RuleObject,                                                     //
                            A(type, outboundTag, balancerTag),                              //
                            A(QV2RAY_RULE_ENABLED, QV2RAY_RULE_TAG),                        //
                            F(ruleTag, domain, ip, port, sourcePort, network, source,       //
                              inboundTag, protocol, user, localIP, localPort, process),     //
                            F(localOS, vlessRoute, domainMatcher, attrs, webhook))
    };
    //
    //

    struct StrategyObject
    {
        QString type;
        QJsonObject settings;
        JSONSTRUCT_COMPARE(StrategyObject, type, settings)
        JSONSTRUCT_REGISTER(StrategyObject, F(type, settings))
    };

    struct BalancerObject
    {
        QString tag;
        QList<QString> selector;
        StrategyObject strategy;
        QString fallbackTag;
        JSONSTRUCT_COMPARE(BalancerObject, tag, selector, strategy, fallbackTag)
        JSONSTRUCT_REGISTER(BalancerObject, F(tag, selector, strategy, fallbackTag))
    };
    //
    //
    namespace transfer
    {
        struct HTTPRequestObject
        {
            QString version = "1.1";
            QString method = "GET";
            QList<QString> path = { "/" };
            QMap<QString, QList<QString>> headers;
            HTTPRequestObject()
            {
                headers = {
                    { "Host", { "www.baidu.com", "www.bing.com" } },
                    { "User-Agent",
                      { "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.143 Safari/537.36",
                        "Mozilla/5.0 (iPhone; CPU iPhone OS 10_0_2 like Mac OS X) AppleWebKit/601.1 (KHTML, like Gecko) CriOS/53.0.2785.109 Mobile/14A456 Safari/601.1.46" } },
                    { "Accept-Encoding", { "gzip, deflate" } },
                    { "Connection", { "keep-alive" } },
                    { "Pragma", { "no-cache" } }
                };
            }
            JSONSTRUCT_COMPARE(HTTPRequestObject, version, method, path, headers)
            JSONSTRUCT_REGISTER(HTTPRequestObject, F(version, method, path, headers))
        };
        //
        //
        struct HTTPResponseObject
        {
            QString version = "1.1";
            QString status = "200";
            QString reason = "OK";
            QMap<QString, QList<QString>> headers;
            HTTPResponseObject()
            {
                headers = { { "Content-Type", { "application/octet-stream", "video/mpeg" } }, //
                            { "Transfer-Encoding", { "chunked" } },                           //
                            { "Connection", { "keep-alive" } },                               //
                            { "Pragma", { "no-cache" } } };
            }
            JSONSTRUCT_COMPARE(HTTPResponseObject, version, status, reason, headers)
            JSONSTRUCT_REGISTER(HTTPResponseObject, F(version, status, reason, headers))
        };
        //
        //
        struct TCPHeader_Internal
        {
            QString type = "none";
            HTTPRequestObject request;
            HTTPResponseObject response;
            JSONSTRUCT_COMPARE(TCPHeader_Internal, type, request, response)
            JSONSTRUCT_REGISTER(TCPHeader_Internal, A(type), F(request, response))
        };
        //
        //
        struct ObfsHeaderObject
        {
            QString type = "none";
            JSONSTRUCT_COMPARE(ObfsHeaderObject, type)
            JSONSTRUCT_REGISTER(ObfsHeaderObject, F(type))
        };
        //
        //
        struct TCPObject
        {
            TCPHeader_Internal header;
            bool acceptProxyProtocol = false;
            JSONSTRUCT_COMPARE(TCPObject, header, acceptProxyProtocol)
            JSONSTRUCT_REGISTER(TCPObject, F(header, acceptProxyProtocol))
        };
        //
        //
        struct KCPObject
        {
            int mtu = 1350;
            int tti = 50;
            int uplinkCapacity = 5;
            int downlinkCapacity = 20;
            bool congestion = false;
            int readBufferSize = 2;
            int writeBufferSize = 2;
            // Xray-core mKCP additions.
            int cwndMultiplier = 0;
            int maxSendingWindow = 0;
            QString seed;
            ObfsHeaderObject header;
            KCPObject(){};
            JSONSTRUCT_COMPARE(KCPObject, mtu, tti, uplinkCapacity, downlinkCapacity, congestion, readBufferSize, writeBufferSize,
                               cwndMultiplier, maxSendingWindow, seed, header)
            JSONSTRUCT_REGISTER(KCPObject, F(mtu, tti, uplinkCapacity, downlinkCapacity, congestion, readBufferSize, writeBufferSize,
                                             cwndMultiplier, maxSendingWindow, header, seed))
        };
        //
        //
        struct WebSocketObject
        {
            QString host;
            QString path = "/";
            QMap<QString, QString> headers;
            bool acceptProxyProtocol = false;
            // v2ray-core early-data extensions.
            int maxEarlyData = 0;
            bool useBrowserForwarding = false;
            QString earlyDataHeaderName;
            bool parseXForwardedFor = false;
            // Xray-core WebSocket extension.
            int heartbeatPeriod = 0;
            JSONSTRUCT_COMPARE(WebSocketObject, host, path, headers, acceptProxyProtocol, maxEarlyData, useBrowserForwarding,
                               earlyDataHeaderName, parseXForwardedFor, heartbeatPeriod)
            JSONSTRUCT_REGISTER(WebSocketObject, F(host, path, headers, acceptProxyProtocol, maxEarlyData, useBrowserForwarding,
                                                   earlyDataHeaderName, parseXForwardedFor, heartbeatPeriod))
        };
        //
        //
        struct HttpObject
        {
            QList<QString> host;
            QString path = "/";
            QString method = "PUT";
            QMap<QString, QList<QString>> headers;
            bool parseXForwardedFor = false;
            JSONSTRUCT_COMPARE(HttpObject, host, path, method, headers, parseXForwardedFor)
            JSONSTRUCT_REGISTER(HttpObject, F(host, path, method, headers, parseXForwardedFor))
        };
        //
        //
        struct DomainSocketObject
        {
            QString path = "/";
            bool abstract = false;
            bool padding = false;
            JSONSTRUCT_COMPARE(DomainSocketObject, path, abstract, padding)
            JSONSTRUCT_REGISTER(DomainSocketObject, F(path, abstract, padding))
        };
        //
        //
        struct QuicObject
        {
            QString security = "none";
            QString key;
            ObfsHeaderObject header;
            JSONSTRUCT_COMPARE(QuicObject, security, key, header)
            JSONSTRUCT_REGISTER(QuicObject, F(security, key, header))
        };
        //
        //
        struct gRPCObject
        {
            QString authority;
            QString serviceName;
            bool multiMode = false;
            // Both cores use the same snake_case JSON names for these tuning
            // options; v2ray-core additionally supports parseXForwardedFor.
            int idleTimeout = 0;
            int healthCheckTimeout = 0;
            bool permitWithoutStream = false;
            int initialWindowsSize = 0;
            QString userAgent;
            bool parseXForwardedFor = false;
            friend bool operator==(const gRPCObject &left, const gRPCObject &right)
            {
                return left.authority == right.authority && left.serviceName == right.serviceName && left.multiMode == right.multiMode &&
                       left.idleTimeout == right.idleTimeout && left.healthCheckTimeout == right.healthCheckTimeout &&
                       left.permitWithoutStream == right.permitWithoutStream && left.initialWindowsSize == right.initialWindowsSize &&
                       left.userAgent == right.userAgent && left.parseXForwardedFor == right.parseXForwardedFor;
            }
            void loadJson(const QJsonValue &d)
            {
                const auto obj = d.toObject();
                authority = obj["authority"].toString();
                serviceName = obj["serviceName"].toString();
                multiMode = obj["multiMode"].toBool();
                // Accept the camelCase spelling emitted by older Qv2ray
                // builds as well as the canonical snake_case spelling.
                idleTimeout = obj["idle_timeout"].toInt(obj["idleTimeout"].toInt());
                healthCheckTimeout = obj["health_check_timeout"].toInt(obj["healthCheckTimeout"].toInt());
                permitWithoutStream = obj["permit_without_stream"].toBool(obj["permitWithoutStream"].toBool());
                initialWindowsSize = obj["initial_windows_size"].toInt(obj["initialWindowsSize"].toInt());
                userAgent = obj["user_agent"].toString(obj["userAgent"].toString());
                parseXForwardedFor = obj["parseXForwardedFor"].toBool();
            }
            [[nodiscard]] static gRPCObject fromJson(const QJsonValue &d)
            {
                gRPCObject o;
                o.loadJson(d);
                return o;
            }
            [[nodiscard]] QJsonObject toJson() const
            {
                const gRPCObject def;
                QJsonObject obj;
                if (!authority.isEmpty())
                    obj["authority"] = authority;
                if (!serviceName.isEmpty())
                    obj["serviceName"] = serviceName;
                if (multiMode != def.multiMode)
                    obj["multiMode"] = multiMode;
                if (idleTimeout != def.idleTimeout)
                    obj["idle_timeout"] = idleTimeout;
                if (healthCheckTimeout != def.healthCheckTimeout)
                    obj["health_check_timeout"] = healthCheckTimeout;
                if (permitWithoutStream != def.permitWithoutStream)
                    obj["permit_without_stream"] = permitWithoutStream;
                if (initialWindowsSize != def.initialWindowsSize)
                    obj["initial_windows_size"] = initialWindowsSize;
                if (!userAgent.isEmpty())
                    obj["user_agent"] = userAgent;
                if (parseXForwardedFor != def.parseXForwardedFor)
                    obj["parseXForwardedFor"] = parseXForwardedFor;
                return obj;
            }
        };

        //
        //
        struct CustomSockoptObject
        {
            QString system;
            QString network;
            QString level;
            QString opt;
            QString value;
            QString type;
            JSONSTRUCT_COMPARE(CustomSockoptObject, system, network, level, opt, value, type)
            JSONSTRUCT_REGISTER(CustomSockoptObject, F(system, network, level, opt, value, type))
        };

        struct HappyEyeballsObject
        {
            bool prioritizeIPv6 = false;
            qint64 tryDelayMs = 0;
            int interleave = 0;
            int maxConcurrentTry = 0;
            JSONSTRUCT_COMPARE(HappyEyeballsObject, prioritizeIPv6, tryDelayMs, interleave, maxConcurrentTry)
            JSONSTRUCT_REGISTER(HappyEyeballsObject, F(prioritizeIPv6, tryDelayMs, interleave, maxConcurrentTry))
        };

        struct SockoptObject
        {
            int mark = 0;
            bool tcpFastOpen = false;
            QString tproxy = "off";
            // v2ray-core socket options.
            bool acceptProxyProtocol = false;
            int tcpKeepAliveInterval = 0;
            int tcpKeepAliveIdle = 0;
            int tcpFastOpenQueueLength = 0;
            QString bindToDevice;
            qint64 rxBufSize = 0;
            qint64 txBufSize = 0;
            bool forceBufSize = false;
            bool mptcp = false;
            // Xray-core socket options.
            QString domainStrategy;
            QString dialerProxy;
            QString tcpCongestion;
            int tcpWindowClamp = 0;
            int tcpMaxSeg = 0;
            bool penetrate = false;
            int tcpUserTimeout = 0;
            bool v6only = false;
            QString interface;
            bool tcpMptcp = false;
            QList<CustomSockoptObject> customSockopt;
            QString addressPortStrategy;
            HappyEyeballsObject happyEyeballs;
            QList<QString> trustedXForwardedFor;
            friend bool operator==(const SockoptObject &left, const SockoptObject &right)
            {
                return left.mark == right.mark && left.tcpFastOpen == right.tcpFastOpen && left.tproxy == right.tproxy &&
                       left.acceptProxyProtocol == right.acceptProxyProtocol && left.tcpKeepAliveInterval == right.tcpKeepAliveInterval &&
                       left.tcpKeepAliveIdle == right.tcpKeepAliveIdle && left.tcpFastOpenQueueLength == right.tcpFastOpenQueueLength &&
                       left.bindToDevice == right.bindToDevice && left.rxBufSize == right.rxBufSize && left.txBufSize == right.txBufSize &&
                       left.forceBufSize == right.forceBufSize && left.mptcp == right.mptcp && left.domainStrategy == right.domainStrategy &&
                       left.dialerProxy == right.dialerProxy && left.tcpCongestion == right.tcpCongestion &&
                       left.tcpWindowClamp == right.tcpWindowClamp && left.tcpMaxSeg == right.tcpMaxSeg &&
                       left.penetrate == right.penetrate && left.tcpUserTimeout == right.tcpUserTimeout && left.v6only == right.v6only &&
                       left.interface == right.interface && left.tcpMptcp == right.tcpMptcp && left.customSockopt == right.customSockopt &&
                       left.addressPortStrategy == right.addressPortStrategy && left.happyEyeballs == right.happyEyeballs &&
                       left.trustedXForwardedFor == right.trustedXForwardedFor;
            }
            JSONSTRUCT_REGISTER(SockoptObject, F(mark, tcpFastOpen, tproxy, acceptProxyProtocol, tcpKeepAliveInterval, tcpKeepAliveIdle,
                                                 tcpFastOpenQueueLength, bindToDevice, rxBufSize, txBufSize, forceBufSize, mptcp),
                                                 F(domainStrategy, dialerProxy, tcpCongestion, tcpWindowClamp, tcpMaxSeg, penetrate,
                                                 tcpUserTimeout, v6only, interface, tcpMptcp),
                                                 F(customSockopt, addressPortStrategy, happyEyeballs, trustedXForwardedFor))
        };
        //
        //
        struct CertificateObject
        {
            QString usage = "encipherment";
            QString certificateFile;
            QString keyFile;
            QList<QString> certificate;
            QList<QString> key;
            // Xray-core certificate loading options.
            qint64 ocspStapling = 0;
            bool oneTimeLoading = false;
            bool buildChain = false;
            JSONSTRUCT_COMPARE(CertificateObject, usage, certificateFile, keyFile, certificate, key, ocspStapling, oneTimeLoading, buildChain)
            JSONSTRUCT_REGISTER(CertificateObject, F(usage, certificateFile, keyFile, certificate, key, ocspStapling, oneTimeLoading, buildChain))
        };
        //
        //
        struct TLSObject
        {
            QString serverName;
            // v2ray-core keeps allowInsecure; Xray removed it.  It is emitted
            // only when explicitly enabled so that normal configs stay valid
            // for both cores.
            bool allowInsecure = false;
            bool enableSessionResumption = false;
            bool disableSystemRoot = false;
            QList<QString> alpn;
            QList<QString> pinnedPeerCertificateChainSha256;
            QList<CertificateObject> certificates;
            // v2ray-core TLS additions.
            bool verifyClientCertificate = false;
            QString echConfig;
            QString echDohServer;
            // Xray-core TLS additions.
            QString minVersion;
            QString maxVersion;
            QString cipherSuites;
            QString fingerprint;
            bool rejectUnknownSni = false;
            QList<QString> curvePreferences;
            QString masterKeyLog;
            QString pinnedPeerCertSha256;
            QString verifyPeerCertByName;
            QString echServerKeys;
            QString echConfigList;
            SockoptObject echSockopt;
            bool useSystemCA = false;
            friend bool operator==(const TLSObject &left, const TLSObject &right)
            {
                return left.serverName == right.serverName && left.allowInsecure == right.allowInsecure &&
                       left.enableSessionResumption == right.enableSessionResumption && left.disableSystemRoot == right.disableSystemRoot &&
                       left.alpn == right.alpn && left.pinnedPeerCertificateChainSha256 == right.pinnedPeerCertificateChainSha256 &&
                       left.certificates == right.certificates && left.verifyClientCertificate == right.verifyClientCertificate &&
                       left.echConfig == right.echConfig && left.echDohServer == right.echDohServer && left.minVersion == right.minVersion &&
                       left.maxVersion == right.maxVersion && left.cipherSuites == right.cipherSuites && left.fingerprint == right.fingerprint &&
                       left.rejectUnknownSni == right.rejectUnknownSni && left.curvePreferences == right.curvePreferences &&
                       left.masterKeyLog == right.masterKeyLog && left.pinnedPeerCertSha256 == right.pinnedPeerCertSha256 &&
                       left.verifyPeerCertByName == right.verifyPeerCertByName && left.echServerKeys == right.echServerKeys &&
                       left.echConfigList == right.echConfigList && left.echSockopt == right.echSockopt && left.useSystemCA == right.useSystemCA;
            }
            JSONSTRUCT_REGISTER(TLSObject, F(serverName, allowInsecure, enableSessionResumption, disableSystemRoot, alpn,
                                             pinnedPeerCertificateChainSha256, certificates, verifyClientCertificate, echConfig,
                                             echDohServer, minVersion, maxVersion, cipherSuites, fingerprint, rejectUnknownSni),
                                             F(curvePreferences, masterKeyLog, pinnedPeerCertSha256, verifyPeerCertByName, echServerKeys,
                                             echConfigList, echSockopt, useSystemCA))
        };
        //
        //
        struct XTLSObject
        {
            QString serverName;
            bool allowInsecure = false;
            bool enableSessionResumption = false;
            bool disableSystemRoot = false;
            QList<QString> alpn;
            QList<QString> pinnedPeerCertificateChainSha256;
            QList<CertificateObject> certificates;
            JSONSTRUCT_COMPARE(XTLSObject, serverName, allowInsecure, enableSessionResumption, disableSystemRoot, alpn,
                               pinnedPeerCertificateChainSha256, certificates)
            JSONSTRUCT_REGISTER(XTLSObject, F(serverName, allowInsecure, enableSessionResumption, disableSystemRoot, alpn,
                                             pinnedPeerCertificateChainSha256, certificates))
        };

        struct RealityLimitFallbackObject
        {
            qint64 afterBytes = 0;
            qint64 bytesPerSec = 0;
            qint64 burstBytesPerSec = 0;
            JSONSTRUCT_COMPARE(RealityLimitFallbackObject, afterBytes, bytesPerSec, burstBytesPerSec)
            JSONSTRUCT_REGISTER(RealityLimitFallbackObject, F(afterBytes, bytesPerSec, burstBytesPerSec))
        };

        // Xray-core REALITY security settings.  The same object is used for
        // server and client configurations (server-only and client-only fields
        // are simply empty on the other side).
        struct RealityObject
        {
            QString masterKeyLog;
            bool show = false;
            QvJsonValueObject target;
            QvJsonValueObject dest;
            QString type;
            int xver = 0;
            QList<QString> serverNames;
            QString privateKey;
            QString minClientVer;
            QString maxClientVer;
            qint64 maxTimeDiff = 0;
            QList<QString> shortIds;
            QString mldsa65Seed;
            RealityLimitFallbackObject limitFallbackUpload;
            RealityLimitFallbackObject limitFallbackDownload;
            //
            QString fingerprint;
            QString serverName;
            QString password;
            QString publicKey;
            QString shortId;
            QString mldsa65Verify;
            QString spiderX = "/";
            friend bool operator==(const RealityObject &left, const RealityObject &right)
            {
                return left.masterKeyLog == right.masterKeyLog && left.show == right.show && left.target == right.target &&
                       left.dest == right.dest && left.type == right.type && left.xver == right.xver && left.serverNames == right.serverNames &&
                       left.privateKey == right.privateKey && left.minClientVer == right.minClientVer &&
                       left.maxClientVer == right.maxClientVer && left.maxTimeDiff == right.maxTimeDiff && left.shortIds == right.shortIds &&
                       left.mldsa65Seed == right.mldsa65Seed && left.limitFallbackUpload == right.limitFallbackUpload &&
                       left.limitFallbackDownload == right.limitFallbackDownload && left.fingerprint == right.fingerprint &&
                       left.serverName == right.serverName && left.password == right.password && left.publicKey == right.publicKey &&
                       left.shortId == right.shortId && left.mldsa65Verify == right.mldsa65Verify && left.spiderX == right.spiderX;
            }
            JSONSTRUCT_REGISTER(RealityObject, F(masterKeyLog, show, target, dest, type, xver, serverNames, privateKey, minClientVer,
                                                 maxClientVer, maxTimeDiff, shortIds, mldsa65Seed),
                                                 F(limitFallbackUpload, limitFallbackDownload, fingerprint, serverName, password, publicKey,
                                                 shortId, mldsa65Verify, spiderX))
        };

        struct XmuxObject
        {
            Int32RangeObject maxConcurrency;
            Int32RangeObject maxConnections;
            Int32RangeObject cMaxReuseTimes;
            Int32RangeObject hMaxRequestTimes;
            Int32RangeObject hMaxReusableSecs;
            qint64 hKeepAlivePeriod = 0;
            JSONSTRUCT_COMPARE(XmuxObject, maxConcurrency, maxConnections, cMaxReuseTimes, hMaxRequestTimes, hMaxReusableSecs, hKeepAlivePeriod)
            JSONSTRUCT_REGISTER(XmuxObject, F(maxConcurrency, maxConnections, cMaxReuseTimes, hMaxRequestTimes, hMaxReusableSecs, hKeepAlivePeriod))
        };

        // Xray-core XHTTP / SplitHTTP transport.
        struct XHTTPObject
        {
            QString host;
            QString path = "/";
            QString mode = "auto";
            QMap<QString, QString> headers;
            Int32RangeObject xPaddingBytes;
            bool xPaddingObfsMode = false;
            QString xPaddingKey = "x_padding";
            QString xPaddingHeader = "X-Padding";
            QString xPaddingPlacement = "queryInHeader";
            QString xPaddingMethod = "repeat-x";
            QString uplinkHTTPMethod = "POST";
            QString sessionIDPlacement = "path";
            QString sessionIDKey;
            QString sessionIDTable;
            Int32RangeObject sessionIDLength;
            QString seqPlacement = "path";
            QString seqKey;
            QString uplinkDataPlacement;
            QString uplinkDataKey;
            Int32RangeObject uplinkChunkSize;
            bool noGRPCHeader = false;
            bool noSSEHeader = false;
            Int32RangeObject scMaxEachPostBytes;
            Int32RangeObject scMinPostsIntervalMs;
            qint64 scMaxBufferedPosts = 0;
            Int32RangeObject scStreamUpServerSecs;
            int serverMaxHeaderBytes = 0;
            XmuxObject xmux;
            QJsonObject downloadSettings;
            QJsonObject extra;
            friend bool operator==(const XHTTPObject &left, const XHTTPObject &right)
            {
                return left.host == right.host && left.path == right.path && left.mode == right.mode && left.headers == right.headers &&
                       left.xPaddingBytes == right.xPaddingBytes && left.xPaddingObfsMode == right.xPaddingObfsMode &&
                       left.xPaddingKey == right.xPaddingKey && left.xPaddingHeader == right.xPaddingHeader &&
                       left.xPaddingPlacement == right.xPaddingPlacement && left.xPaddingMethod == right.xPaddingMethod &&
                       left.uplinkHTTPMethod == right.uplinkHTTPMethod && left.sessionIDPlacement == right.sessionIDPlacement &&
                       left.sessionIDKey == right.sessionIDKey && left.sessionIDTable == right.sessionIDTable &&
                       left.sessionIDLength == right.sessionIDLength && left.seqPlacement == right.seqPlacement &&
                       left.seqKey == right.seqKey && left.uplinkDataPlacement == right.uplinkDataPlacement &&
                       left.uplinkDataKey == right.uplinkDataKey && left.uplinkChunkSize == right.uplinkChunkSize &&
                       left.noGRPCHeader == right.noGRPCHeader && left.noSSEHeader == right.noSSEHeader &&
                       left.scMaxEachPostBytes == right.scMaxEachPostBytes && left.scMinPostsIntervalMs == right.scMinPostsIntervalMs &&
                       left.scMaxBufferedPosts == right.scMaxBufferedPosts && left.scStreamUpServerSecs == right.scStreamUpServerSecs &&
                       left.serverMaxHeaderBytes == right.serverMaxHeaderBytes && left.xmux == right.xmux &&
                       left.downloadSettings == right.downloadSettings && left.extra == right.extra;
            }
            JSONSTRUCT_REGISTER(XHTTPObject, F(host, path, mode, headers, xPaddingBytes, xPaddingObfsMode, xPaddingKey, xPaddingHeader,
                                               xPaddingPlacement, xPaddingMethod, uplinkHTTPMethod, sessionIDPlacement, sessionIDKey,
                                               sessionIDTable, sessionIDLength),
                                               F(seqPlacement, seqKey, uplinkDataPlacement, uplinkDataKey, uplinkChunkSize,
                                               noGRPCHeader, noSSEHeader, scMaxEachPostBytes, scMinPostsIntervalMs, scMaxBufferedPosts,
                                               scStreamUpServerSecs, serverMaxHeaderBytes, xmux, downloadSettings, extra))
        };

        struct HTTPUpgradeObject
        {
            QString host;
            QString path = "/";
            QMap<QString, QString> headers;
            bool acceptProxyProtocol = false;
            JSONSTRUCT_COMPARE(HTTPUpgradeObject, host, path, headers, acceptProxyProtocol)
            JSONSTRUCT_REGISTER(HTTPUpgradeObject, F(host, path, headers, acceptProxyProtocol))
        };

        struct Hysteria2CongestionObject
        {
            QString type;
            qint64 up_mbps = 0;
            qint64 down_mbps = 0;
            JSONSTRUCT_COMPARE(Hysteria2CongestionObject, type, up_mbps, down_mbps)
            JSONSTRUCT_REGISTER(Hysteria2CongestionObject, F(type, up_mbps, down_mbps))
        };

        // v2ray-core Hysteria2 transport.
        struct Hysteria2Object
        {
            QString password;
            Hysteria2CongestionObject congestion;
            bool use_udp_extension = false;
            bool ignore_client_bandwidth = false;
            JSONSTRUCT_COMPARE(Hysteria2Object, password, congestion, use_udp_extension, ignore_client_bandwidth)
            JSONSTRUCT_REGISTER(Hysteria2Object, F(password, congestion, use_udp_extension, ignore_client_bandwidth))
        };

        struct MasqueradeObject
        {
            QString type;
            QString dir;
            QString url;
            bool rewriteHost = false;
            bool xForwarded = false;
            bool insecure = false;
            QString content;
            QMap<QString, QString> headers;
            int statusCode = 0;
            JSONSTRUCT_COMPARE(MasqueradeObject, type, dir, url, rewriteHost, xForwarded, insecure, content, headers, statusCode)
            JSONSTRUCT_REGISTER(MasqueradeObject, F(type, dir, url, rewriteHost, xForwarded, insecure, content, headers, statusCode))
        };

        // Xray-core Hysteria transport.
        struct HysteriaObject
        {
            int version = 0;
            QString auth;
            qint64 udpIdleTimeout = 0;
            MasqueradeObject masquerade;
            JSONSTRUCT_COMPARE(HysteriaObject, version, auth, udpIdleTimeout, masquerade)
            JSONSTRUCT_REGISTER(HysteriaObject, F(version, auth, udpIdleTimeout, masquerade))
        };

        struct MasqueWarpObject
        {
            QString privateKey;
            QString publicKey;
            QList<QString> address;
            JSONSTRUCT_COMPARE(MasqueWarpObject, privateKey, publicKey, address)
            JSONSTRUCT_REGISTER(MasqueWarpObject, F(privateKey, publicKey, address))
        };

        struct MasqueObject
        {
            QString host;
            QString path;
            QString user;
            QString pass;
            QMap<QString, QString> headers;
            MasqueWarpObject warp;
            XmuxObject xmux;
            JSONSTRUCT_COMPARE(MasqueObject, host, path, user, pass, headers, warp, xmux)
            JSONSTRUCT_REGISTER(MasqueObject, F(host, path, user, pass, headers, warp, xmux))
        };

        struct XDriveObject
        {
            QString remoteFolder;
            QString service;
            QList<QString> secrets;
            int segmentBytes = 0;
            int flushIntervalMs = 0;
            int pollIntervalMs = 0;
            int maxPollIntervalMs = 0;
            int sessionTtlSeconds = 0;
            int concurrency = 0;
            int eagerWindowMs = 0;
            int holeTimeoutMs = 0;
            // JSON key is "template"; "template" is a C++ keyword.
            QJsonObject templateConfig;
            friend bool operator==(const XDriveObject &left, const XDriveObject &right)
            {
                return left.remoteFolder == right.remoteFolder && left.service == right.service && left.secrets == right.secrets &&
                       left.segmentBytes == right.segmentBytes && left.flushIntervalMs == right.flushIntervalMs &&
                       left.pollIntervalMs == right.pollIntervalMs && left.maxPollIntervalMs == right.maxPollIntervalMs &&
                       left.sessionTtlSeconds == right.sessionTtlSeconds && left.concurrency == right.concurrency &&
                       left.eagerWindowMs == right.eagerWindowMs && left.holeTimeoutMs == right.holeTimeoutMs &&
                       left.templateConfig == right.templateConfig;
            }
            friend bool operator!=(const XDriveObject &left, const XDriveObject &right)
            {
                return !(left == right);
            }
            void loadJson(const QJsonValue &d)
            {
                XDriveObject def;
                const auto obj = d.toObject();
                remoteFolder = obj["remoteFolder"].toString();
                service = obj["service"].toString();
                JsonStructHelper::Deserialize(secrets, obj["secrets"]);
                segmentBytes = obj["segmentBytes"].toInt();
                flushIntervalMs = obj["flushIntervalMs"].toInt();
                pollIntervalMs = obj["pollIntervalMs"].toInt();
                maxPollIntervalMs = obj["maxPollIntervalMs"].toInt();
                sessionTtlSeconds = obj["sessionTtlSeconds"].toInt();
                concurrency = obj["concurrency"].toInt();
                eagerWindowMs = obj["eagerWindowMs"].toInt();
                holeTimeoutMs = obj["holeTimeoutMs"].toInt();
                templateConfig = obj["template"].toObject();
            }
            [[nodiscard]] static XDriveObject fromJson(const QJsonValue &d)
            {
                XDriveObject o;
                o.loadJson(d);
                return o;
            }
            [[nodiscard]] QJsonObject toJson() const
            {
                XDriveObject def;
                QJsonObject obj;
                if (!remoteFolder.isEmpty())
                    obj["remoteFolder"] = remoteFolder;
                if (!service.isEmpty())
                    obj["service"] = service;
                if (!secrets.isEmpty())
                    obj["secrets"] = JsonStructHelper::Serialize(secrets);
                if (segmentBytes != def.segmentBytes)
                    obj["segmentBytes"] = segmentBytes;
                if (flushIntervalMs != def.flushIntervalMs)
                    obj["flushIntervalMs"] = flushIntervalMs;
                if (pollIntervalMs != def.pollIntervalMs)
                    obj["pollIntervalMs"] = pollIntervalMs;
                if (maxPollIntervalMs != def.maxPollIntervalMs)
                    obj["maxPollIntervalMs"] = maxPollIntervalMs;
                if (sessionTtlSeconds != def.sessionTtlSeconds)
                    obj["sessionTtlSeconds"] = sessionTtlSeconds;
                if (concurrency != def.concurrency)
                    obj["concurrency"] = concurrency;
                if (eagerWindowMs != def.eagerWindowMs)
                    obj["eagerWindowMs"] = eagerWindowMs;
                if (holeTimeoutMs != def.holeTimeoutMs)
                    obj["holeTimeoutMs"] = holeTimeoutMs;
                if (!templateConfig.isEmpty())
                    obj["template"] = templateConfig;
                return obj;
            }
        };
    } // namespace transfer
    //
    //
    struct StreamSettingsObject
    {
        // Xray-core also allows overriding the destination address/port in
        // the stream settings (used by reverse/dynamic transports).
        QString address;
        int port = 0;
        // "method" is the legacy alias of "network" in Xray-core.
        QString method;
        QString network = "tcp";
        QString security = "none";
        transfer::SockoptObject sockopt;
        transfer::TLSObject tlsSettings;
        // Kept for loading/previewing legacy configs.  Generation migrates
        // XTLS to TLS + xtls-rprx-vision flow.
        transfer::XTLSObject xtlsSettings;
        transfer::RealityObject realitySettings;
        transfer::TCPObject tcpSettings;
        transfer::TCPObject rawSettings;
        transfer::KCPObject kcpSettings;
        transfer::WebSocketObject wsSettings;
        transfer::HttpObject httpSettings;
        transfer::DomainSocketObject dsSettings;
        transfer::QuicObject quicSettings;
        transfer::gRPCObject grpcSettings;
        transfer::gRPCObject gunSettings;
        transfer::XHTTPObject xhttpSettings;
        transfer::XHTTPObject splithttpSettings;
        transfer::HTTPUpgradeObject httpupgradeSettings;
        transfer::Hysteria2Object hy2Settings;
        transfer::HysteriaObject hysteriaSettings;
        transfer::MasqueObject masqueSettings;
        transfer::XDriveObject xdriveSettings;
        QJsonObject finalmask;
        friend bool operator==(const StreamSettingsObject &left, const StreamSettingsObject &right)
        {
            return left.address == right.address && left.port == right.port && left.method == right.method &&
                   left.network == right.network && left.security == right.security && left.sockopt == right.sockopt &&
                   left.tcpSettings == right.tcpSettings && left.rawSettings == right.rawSettings && left.tlsSettings == right.tlsSettings &&
                   left.xtlsSettings == right.xtlsSettings && left.realitySettings == right.realitySettings &&
                   left.kcpSettings == right.kcpSettings && left.wsSettings == right.wsSettings && left.httpSettings == right.httpSettings &&
                   left.dsSettings == right.dsSettings && left.quicSettings == right.quicSettings && left.grpcSettings == right.grpcSettings &&
                   left.gunSettings == right.gunSettings && left.xhttpSettings == right.xhttpSettings &&
                   left.splithttpSettings == right.splithttpSettings && left.httpupgradeSettings == right.httpupgradeSettings &&
                   left.hy2Settings == right.hy2Settings && left.hysteriaSettings == right.hysteriaSettings &&
                   left.masqueSettings == right.masqueSettings && left.xdriveSettings == right.xdriveSettings && left.finalmask == right.finalmask;
        }
        JSONSTRUCT_REGISTER(StreamSettingsObject, F(address, port, method, network, security, sockopt),
                            F(tcpSettings, rawSettings, tlsSettings, xtlsSettings, realitySettings, kcpSettings, wsSettings,
                              httpSettings, dsSettings, quicSettings, grpcSettings, gunSettings, xhttpSettings, splithttpSettings),
                            F(httpupgradeSettings, hy2Settings, hysteriaSettings, masqueSettings, xdriveSettings, finalmask))
    };

    struct FakeDNSObject
    {
        QString ipPool = "198.18.0.0/15";
        int poolSize = 65535;
        JSONSTRUCT_REGISTER(FakeDNSObject, A(ipPool, poolSize))
        JSONSTRUCT_COMPARE(FakeDNSObject, ipPool, poolSize)
    };

    //
    // Some protocols from: https://v2ray.com/chapter_02/02_protocols.html
    namespace protocol
    {
        //
        // VMess Server
        constexpr auto VMESS_USER_ALTERID_DEFAULT = 0;
        struct VMessServerObject
        {
            struct UserObject
            {
                QString id;
                int alterId = VMESS_USER_ALTERID_DEFAULT;
                QString security = "auto";
                QString experiments;
                int level = 0;
                JSONSTRUCT_COMPARE(UserObject, id, alterId, security, experiments, level)
                JSONSTRUCT_REGISTER(UserObject, F(id, alterId, security, experiments, level))
            };

            QString address;
            int port;
            QList<UserObject> users;
            JSONSTRUCT_COMPARE(VMessServerObject, address, port, users)
            JSONSTRUCT_REGISTER(VMessServerObject, F(address, port, users))
        };
        //
        // VLESS Server
        struct VLESSServerObject
        {
            struct UserObject
            {
                QString id;
                QString flow;
                QString encryption = "none";
                // Xray-core VLESS Encryption fields.
                int xorMode = 0;
                qint64 seconds = 0;
                QString padding;
                int testpre = 0;
                QList<int> testseed;
                QJsonObject reverse;
                JSONSTRUCT_COMPARE(UserObject, id, flow, encryption, xorMode, seconds, padding, testpre, testseed, reverse)
                // v2ray-core requires an explicit "encryption": "none" for
                // every VLESS outbound user, so always emit it.
                JSONSTRUCT_REGISTER(UserObject, A(id, encryption), F(flow, xorMode, seconds, padding, testpre, testseed, reverse))
            };
            QString address;
            int port = 0;
            QList<UserObject> users;
            JSONSTRUCT_COMPARE(VLESSServerObject, address, port, users)
            JSONSTRUCT_REGISTER(VLESSServerObject, F(address, port, users))
        };
        //
        // ShadowSocks Server
        struct ShadowSocksServerObject
        {
            QString address;
            QString method;
            QString password;
            int port;
            JSONSTRUCT_COMPARE(ShadowSocksServerObject, address, method, password)
            JSONSTRUCT_REGISTER(ShadowSocksServerObject, F(address, port, method, password))
        };
    } // namespace protocol
} // namespace Qv2ray::base::objects
