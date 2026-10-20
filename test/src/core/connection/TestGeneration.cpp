#define CATCH_CONFIG_MAIN
#include "catch.hpp"

#include "core/CoreUtils.hpp"
#include "core/connection/Generation.hpp"
#include "core/connection/Serialization.hpp"

namespace
{
    StreamSettingsObject MakeRealityXHTTPStream()
    {
        StreamSettingsObject stream;
        stream.network = "xhttp";
        stream.security = "reality";
        stream.realitySettings.serverName = "example.com";
        stream.realitySettings.fingerprint = "chrome";
        stream.realitySettings.publicKey = "public-key";
        stream.realitySettings.password = "public-key";
        stream.realitySettings.shortId = "0123456789abcdef";
        stream.realitySettings.spiderX = "/";
        stream.xhttpSettings.host = "example.com";
        stream.xhttpSettings.path = "/xhttp";
        stream.xhttpSettings.mode = "auto";
        stream.xhttpSettings.xPaddingBytes = { 100, 1000 };
        stream.xhttpSettings.scMaxEachPostBytes = { 1000000, 1000000 };
        stream.xhttpSettings.xmux.maxConcurrency = { 16, 32 };
        stream.sockopt.mark = 255;
        stream.sockopt.tcpFastOpen = true;
        stream.sockopt.tcpMptcp = true;
        stream.sockopt.domainStrategy = "UseIP";
        return stream;
    }

    CONFIGROOT MakeConfig(const QString &protocol, const QJsonObject &stream)
    {
        CONFIGROOT root;
        QJsonObject outbound;
        outbound["tag"] = "PROXY";
        outbound["protocol"] = protocol;
        outbound["settings"] = QJsonObject{
            { "vnext", QJsonArray{ QJsonObject{ { "address", "example.com" },
                                                { "port", 443 },
                                                { "users", QJsonArray{ QJsonObject{ { "id", "11111111-1111-4111-8111-111111111111" },
                                                                                    { "encryption", "none" } } } } } } }
        };
        outbound["streamSettings"] = stream;
        root["outbounds"] = QJsonArray{ outbound };
        return root;
    }
} // namespace

TEST_CASE("Xray-only stream options are emitted in a form Xray accepts")
{
    const auto stream = MakeRealityXHTTPStream();
    const auto json = stream.toJson();

    REQUIRE(json["network"].toString() == "xhttp");
    REQUIRE(json["security"].toString() == "reality");
    REQUIRE(json["realitySettings"].toObject()["publicKey"].toString() == "public-key");

    const auto xhttp = json["xhttpSettings"].toObject();
    // Current Xray-core only accepts an integer or a "from-to" string for
    // range options.
    REQUIRE(xhttp["xPaddingBytes"].toString() == "100-1000");
    REQUIRE(xhttp["scMaxEachPostBytes"].toInt() == 1000000);
    REQUIRE(xhttp["xmux"].toObject()["maxConcurrency"].toString() == "16-32");

    REQUIRE(json["sockopt"].toObject()["tcpMptcp"].toBool());
    REQUIRE(json["sockopt"].toObject()["domainStrategy"].toString() == "UseIP");
}

TEST_CASE("Range options parse legacy object and string forms")
{
    Int32RangeObject range;
    range.loadJson(QJsonObject{ { "from", 10 }, { "to", 20 } });
    REQUIRE(range.from == 10);
    REQUIRE(range.to == 20);
    REQUIRE(range.toJson().toString() == "10-20");

    range.loadJson("30-40");
    REQUIRE(range.from == 30);
    REQUIRE(range.to == 40);

    range.loadJson("-114-514");
    REQUIRE(range.from == -114);
    REQUIRE(range.to == 514);

    range.loadJson(53);
    REQUIRE(range.from == 53);
    REQUIRE(range.to == 53);
}

TEST_CASE("VLESS outbound explicitly carries encryption:none")
{
    protocol::VLESSServerObject server;
    server.address = "example.com";
    server.port = 443;
    protocol::VLESSServerObject::UserObject user;
    user.id = "11111111-1111-4111-8111-111111111111";
    user.flow = "xtls-rprx-vision";
    server.users << user;

    const auto json = server.toJson();
    const auto users = json["users"].toArray();
    REQUIRE(users.count() == 1);
    REQUIRE(users.first().toObject()["encryption"].toString() == "none");
    REQUIRE(users.first().toObject()["flow"].toString() == "xtls-rprx-vision");
}

TEST_CASE("Core compatibility migration")
{
    SECTION("XTLS becomes TLS + vision and Xray rejects allowInsecure")
    {
        auto stream = MakeRealityXHTTPStream();
        auto streamJson = stream.toJson();
        streamJson["security"] = "tls";
        auto tls = streamJson["tlsSettings"].toObject();
        tls["allowInsecure"] = true;
        tls["pinnedPeerCertificateChainSha256"] = QJsonArray{ "aa" };
        streamJson["tlsSettings"] = tls;

        auto root = MakeConfig("vless", streamJson);
        QJsonObject rule{ { "type", "field" }, { "ruleTag", "r1" }, { "attrs", QJsonObject{ { "k", "v" } } }, { "outboundTag", "PROXY" } };
        root["routing"] = QJsonObject{ { "rules", QJsonArray{ rule } }, { "balancers", QJsonArray{} } };

        ApplyCoreCompatibilityFilter(root, CORE_XRAY);
        const auto out = root["outbounds"].toArray().first().toObject();
        const auto normalizedStream = out["streamSettings"].toObject();
        const auto normalizedTls = normalizedStream["tlsSettings"].toObject();
        REQUIRE_FALSE(normalizedTls.contains("allowInsecure"));
        REQUIRE_FALSE(normalizedTls.contains("pinnedPeerCertificateChainSha256"));
        // The VLESS user must keep the explicit encryption field.
        REQUIRE(out["settings"].toObject()["vnext"].toArray().first().toObject()["users"].toArray().first().toObject()["encryption"].toString() ==
                "none");
    }

    SECTION("v2ray-core receives expectIps and loses Xray-only rule fields")
    {
        CONFIGROOT root;
        root["dns"] = QJsonObject{
            { "servers", QJsonArray{ QJsonObject{ { "address", "8.8.8.8" }, { "expectIPs", QJsonArray{ "127.0.0.0/8" } },
                                                { "unexpectedIPs", QJsonArray{ "1.2.3.4" } } } } }
        };
        root["routing"] = QJsonObject{ { "rules", QJsonArray{ QJsonObject{ { "type", "field" }, { "ruleTag", "r1" },
                                                                          { "localIP", QJsonArray{ "127.0.0.1" } },
                                                                          { "attrs", QJsonObject{ { "k", "v" } } },
                                                                          { "outboundTag", "DIRECT" } } } } };
        root["outbounds"] = QJsonArray{ QJsonObject{ { "tag", "PROXY" }, { "protocol", "vmess" }, { "settings", QJsonObject{} } } };

        ApplyCoreCompatibilityFilter(root, CORE_V2RAY);
        const auto server = root["dns"].toObject()["servers"].toArray().first().toObject();
        REQUIRE(server.contains("expectIps"));
        REQUIRE_FALSE(server.contains("expectIPs"));
        REQUIRE_FALSE(server.contains("unexpectedIPs"));
        const auto rule = root["routing"].toObject()["rules"].toArray().first().toObject();
        REQUIRE_FALSE(rule.contains("ruleTag"));
        REQUIRE_FALSE(rule.contains("localIP"));
        REQUIRE_FALSE(rule.contains("attrs"));
    }

    SECTION("Balancers get an observatory in both cores")
    {
        CONFIGROOT root;
        root["outbounds"] = QJsonArray{ QJsonObject{ { "tag", "PROXY" }, { "protocol", "vmess" }, { "settings", QJsonObject{} } } };
        root["routing"] = QJsonObject{ { "rules", QJsonArray{} },
                                       { "balancers", QJsonArray{ QJsonObject{ { "tag", "bal" },
                                                                               { "selector", QJsonArray{ "PROXY" } },
                                                                               { "strategy", QJsonObject{ { "type", "random" } } } } } } };
        ApplyCoreCompatibilityFilter(root, CORE_V2RAY);
        REQUIRE(root.contains("observatory"));
        REQUIRE(root["observatory"].toObject()["subjectSelector"].toArray().contains("PROXY"));
    }
}

TEST_CASE("VLESS share links round-trip Xray options")
{
    auto stream = MakeRealityXHTTPStream();
    protocol::VLESSServerObject server;
    server.address = "example.com";
    server.port = 443;
    protocol::VLESSServerObject::UserObject user;
    user.id = "11111111-1111-4111-8111-111111111111";
    user.flow = "xtls-rprx-vision";
    server.users << user;

    const auto link = vless::Serialize(stream, server, "test");
    REQUIRE(link.startsWith("vless://"));
    REQUIRE(link.contains("security=reality"));
    REQUIRE(link.contains("type=xhttp"));
    REQUIRE(link.contains("pbk=public-key"));

    QString alias;
    QString error;
    const auto parsed = vless::Deserialize(link, &alias, &error);
    REQUIRE(error.isEmpty());
    const auto parsedStream = QJsonIO::GetValue(parsed, "outbounds", 0, "streamSettings").toObject();
    REQUIRE(parsedStream["security"].toString() == "reality");
    REQUIRE(parsedStream["realitySettings"].toObject()["publicKey"].toString() == "public-key");
    REQUIRE(parsedStream["xhttpSettings"].toObject()["path"].toString() == "/xhttp");
}

TEST_CASE("Transport migration between the two cores")
{
    SECTION("Xray HTTP is migrated to XHTTP")
    {
        auto root = MakeConfig("vless", QJsonObject{ { "network", "http" }, { "security", "tls" },
                                                      { "httpSettings", QJsonObject{ { "host", QJsonArray{ "example.com" } },
                                                                                     { "path", "/h2" } } } });
        ApplyCoreCompatibilityFilter(root, CORE_XRAY);
        const auto stream = root["outbounds"].toArray().first().toObject()["streamSettings"].toObject();
        REQUIRE(stream["network"].toString() == "xhttp");
        REQUIRE_FALSE(stream.contains("httpSettings"));
        REQUIRE(stream["xhttpSettings"].toObject()["host"].toString() == "example.com");
        REQUIRE(stream["xhttpSettings"].toObject()["path"].toString() == "/h2");
    }

    SECTION("v2ray XHTTP falls back to HTTP")
    {
        auto root = MakeConfig("vmess", QJsonObject{ { "network", "xhttp" }, { "security", "tls" },
                                                     { "xhttpSettings", QJsonObject{ { "host", "example.com" }, { "path", "/x" } } } });
        ApplyCoreCompatibilityFilter(root, CORE_V2RAY);
        const auto stream = root["outbounds"].toArray().first().toObject()["streamSettings"].toObject();
        REQUIRE(stream["network"].toString() == "http");
        REQUIRE_FALSE(stream.contains("xhttpSettings"));
        REQUIRE(stream["httpSettings"].toObject()["path"].toString() == "/x");
    }

    SECTION("Hysteria2 and Hysteria are translated")
    {
        auto xrayRoot = MakeConfig("vless", QJsonObject{ { "network", "hy2" }, { "security", "tls" },
                                                          { "hy2Settings", QJsonObject{ { "password", "secret" } } } });
        ApplyCoreCompatibilityFilter(xrayRoot, CORE_XRAY);
        auto stream = xrayRoot["outbounds"].toArray().first().toObject()["streamSettings"].toObject();
        REQUIRE(stream["network"].toString() == "hysteria");
        REQUIRE(stream["hysteriaSettings"].toObject()["version"].toInt() == 2);
        REQUIRE(stream["hysteriaSettings"].toObject()["auth"].toString() == "secret");

        auto v2rayRoot = MakeConfig("vmess", QJsonObject{ { "network", "hysteria" }, { "security", "tls" },
                                                           { "hysteriaSettings", QJsonObject{ { "version", 2 }, { "auth", "secret" } } } });
        ApplyCoreCompatibilityFilter(v2rayRoot, CORE_V2RAY);
        stream = v2rayRoot["outbounds"].toArray().first().toObject()["streamSettings"].toObject();
        REQUIRE(stream["network"].toString() == "hy2");
        REQUIRE(stream["hy2Settings"].toObject()["password"].toString() == "secret");
    }
}

TEST_CASE("Rules with no effective fields are removed")
{
    CONFIGROOT root;
    root["outbounds"] = QJsonArray{ QJsonObject{ { "tag", "PROXY" }, { "protocol", "vmess" }, { "settings", QJsonObject{} } } };
    root["routing"] = QJsonObject{ { "rules", QJsonArray{
        QJsonObject{ { "type", "field" }, { "ruleTag", "empty" }, { "attrs", QJsonObject{ { "a", "b" } } },
                     { "outboundTag", "PROXY" } },
        QJsonObject{ { "type", "field" }, { "domain", QJsonArray{ "full:example.org" } }, { "outboundTag", "PROXY" } } } } };
    ApplyCoreCompatibilityFilter(root, CORE_V2RAY);
    const auto rules = root["routing"].toObject()["rules"].toArray();
    REQUIRE(rules.count() == 1);
    REQUIRE(rules.first().toObject()["domain"].toArray().first().toString() == "full:example.org");
}

TEST_CASE("gRPC options use Xray/v2ray JSON names")
{
    transfer::gRPCObject grpc;
    grpc.authority = "example.com";
    grpc.serviceName = "svc";
    grpc.idleTimeout = 60;
    grpc.healthCheckTimeout = 20;
    grpc.permitWithoutStream = true;
    grpc.initialWindowsSize = 1024;
    grpc.userAgent = "qv2ray";
    grpc.parseXForwardedFor = true;

    const auto json = grpc.toJson();
    REQUIRE(json["idle_timeout"].toInt() == 60);
    REQUIRE(json["health_check_timeout"].toInt() == 20);
    REQUIRE(json["permit_without_stream"].toBool());
    REQUIRE(json["initial_windows_size"].toInt() == 1024);
    REQUIRE(json["user_agent"].toString() == "qv2ray");
    REQUIRE(json["parseXForwardedFor"].toBool());

    // Legacy camelCase input is still understood.
    const auto parsed = transfer::gRPCObject::fromJson(
        QJsonObject{ { "idleTimeout", 5 }, { "healthCheckTimeout", 6 }, { "permitWithoutStream", true } });
    REQUIRE(parsed.idleTimeout == 5);
    REQUIRE(parsed.healthCheckTimeout == 6);
    REQUIRE(parsed.permitWithoutStream);
}

TEST_CASE("Core selection follows the protocol")
{
    CONFIGROOT vless;
    vless["outbounds"] = QJsonArray{ QJsonObject{ { "protocol", "vless" }, { "settings", QJsonObject{} } } };
    REQUIRE(GetCoreTypeForConfig(vless) == CORE_XRAY);

    CONFIGROOT vmess;
    vmess["outbounds"] = QJsonArray{ QJsonObject{ { "protocol", "vmess" }, { "settings", QJsonObject{} } } };
    REQUIRE(GetCoreTypeForConfig(vmess) == CORE_V2RAY);

    // Xray-only transports need Xray even for VMess.
    CONFIGROOT vmessXhttp;
    vmessXhttp["outbounds"] = QJsonArray{ QJsonObject{
        { "protocol", "vmess" },
        { "settings", QJsonObject{} },
        { "streamSettings", QJsonObject{ { "network", "xhttp" }, { "security", "tls" } } } } };
    REQUIRE(GetCoreTypeForConfig(vmessXhttp) == CORE_XRAY);
}

TEST_CASE("Advanced Xray transports are serialized")
{
    SECTION("XHTTP complete parameters")
    {
        StreamSettingsObject stream;
        stream.network = "xhttp";
        stream.security = "tls";
        auto &xhttp = stream.xhttpSettings;
        xhttp.host = "example.com";
        xhttp.path = "/x";
        xhttp.mode = "packet-up";
        xhttp.headers["X-Test"] = "value";
        xhttp.xPaddingBytes = { 10, 20 };
        xhttp.xPaddingObfsMode = true;
        xhttp.xPaddingKey = "pad";
        xhttp.xPaddingHeader = "X-Pad";
        xhttp.xPaddingPlacement = "header";
        xhttp.xPaddingMethod = "tokenish";
        xhttp.uplinkHTTPMethod = "GET";
        xhttp.sessionIDPlacement = "query";
        xhttp.sessionIDKey = "sid";
        xhttp.sessionIDTable = "alphabet";
        xhttp.sessionIDLength = { 8, 16 };
        xhttp.seqPlacement = "header";
        xhttp.seqKey = "X-Seq";
        xhttp.uplinkDataPlacement = "header";
        xhttp.uplinkDataKey = "X-Data";
        xhttp.uplinkChunkSize = { 4096, 8192 };
        xhttp.noGRPCHeader = true;
        xhttp.noSSEHeader = true;
        xhttp.scMaxEachPostBytes = { 1000000, 1000000 };
        xhttp.scMinPostsIntervalMs = { 30, 30 };
        xhttp.scMaxBufferedPosts = 30;
        xhttp.scStreamUpServerSecs = { 20, 80 };
        xhttp.serverMaxHeaderBytes = 4096;
        xhttp.xmux.maxConcurrency = { 16, 32 };
        xhttp.xmux.maxConnections = { 2, 4 };
        xhttp.xmux.cMaxReuseTimes = { 64, 128 };
        xhttp.xmux.hMaxRequestTimes = { 800, 900 };
        xhttp.xmux.hMaxReusableSecs = { 1800, 3000 };
        xhttp.xmux.hKeepAlivePeriod = 120;
        xhttp.downloadSettings = QJsonObject{ { "network", "xhttp" }, { "security", "tls" } };
        xhttp.extra = QJsonObject{ { "scMaxEachPostBytes", 1000 } };

        const auto json = stream.toJson()["xhttpSettings"].toObject();
        REQUIRE(json["host"].toString() == "example.com");
        REQUIRE(json["path"].toString() == "/x");
        REQUIRE(json["mode"].toString() == "packet-up");
        REQUIRE(json["headers"].toObject()["X-Test"].toString() == "value");
        REQUIRE(json["xPaddingBytes"].toString() == "10-20");
        REQUIRE(json["xPaddingObfsMode"].toBool());
        REQUIRE(json["xPaddingPlacement"].toString() == "header");
        REQUIRE(json["xPaddingMethod"].toString() == "tokenish");
        REQUIRE(json["uplinkHTTPMethod"].toString() == "GET");
        REQUIRE(json["sessionIDPlacement"].toString() == "query");
        REQUIRE(json["sessionIDLength"].toString() == "8-16");
        REQUIRE(json["seqPlacement"].toString() == "header");
        REQUIRE(json["uplinkDataPlacement"].toString() == "header");
        REQUIRE(json["uplinkChunkSize"].toString() == "4096-8192");
        REQUIRE(json["scMaxEachPostBytes"].toInt() == 1000000);
        REQUIRE(json["scMinPostsIntervalMs"].toInt() == 30);
        REQUIRE(json["scStreamUpServerSecs"].toString() == "20-80");
        REQUIRE(json["xmux"].toObject()["maxConcurrency"].toString() == "16-32");
        REQUIRE(json["xmux"].toObject()["hKeepAlivePeriod"].toInt() == 120);
        REQUIRE(json["downloadSettings"].toObject()["network"].toString() == "xhttp");
        REQUIRE(json["extra"].toObject()["scMaxEachPostBytes"].toInt() == 1000);
    }

    SECTION("REALITY server parameters")
    {
        StreamSettingsObject stream;
        stream.network = "tcp";
        stream.security = "reality";
        auto &reality = stream.realitySettings;
        reality.masterKeyLog = "/tmp/reality.log";
        reality.show = true;
        reality.target = "example.com:443";
        reality.dest = "example.com:443";
        reality.type = "tcp";
        reality.xver = 2;
        reality.serverNames = { "example.com", "www.example.com" };
        reality.privateKey = "private";
        reality.minClientVer = "1.2.3";
        reality.maxClientVer = "9.9.9";
        reality.maxTimeDiff = 1000;
        reality.shortIds = { "0123456789abcdef", "fedcba9876543210" };
        reality.mldsa65Seed = "seed";
        reality.limitFallbackUpload = { 1, 2, 3 };
        reality.limitFallbackDownload = { 4, 5, 6 };

        const auto json = stream.toJson()["realitySettings"].toObject();
        REQUIRE(json["masterKeyLog"].toString() == "/tmp/reality.log");
        REQUIRE(json["show"].toBool());
        REQUIRE(json["target"].toString() == "example.com:443");
        REQUIRE(json["dest"].toString() == "example.com:443");
        REQUIRE(json["type"].toString() == "tcp");
        REQUIRE(json["xver"].toInt() == 2);
        REQUIRE(json["serverNames"].toArray().count() == 2);
        REQUIRE(json["privateKey"].toString() == "private");
        REQUIRE(json["minClientVer"].toString() == "1.2.3");
        REQUIRE(json["maxClientVer"].toString() == "9.9.9");
        REQUIRE(json["maxTimeDiff"].toInt() == 1000);
        REQUIRE(json["shortIds"].toArray().count() == 2);
        REQUIRE(json["mldsa65Seed"].toString() == "seed");
        REQUIRE(json["limitFallbackUpload"].toObject()["afterBytes"].toInt() == 1);
        REQUIRE(json["limitFallbackDownload"].toObject()["burstBytesPerSec"].toInt() == 6);
    }

    SECTION("MASQUE, Hysteria, Hysteria2 and XDRIVE")
    {
        StreamSettingsObject stream;
        stream.network = "masque";
        stream.masqueSettings.host = "example.com";
        stream.masqueSettings.path = "/masque";
        stream.masqueSettings.user = "user";
        stream.masqueSettings.pass = "pass";
        stream.masqueSettings.headers["X-Test"] = "value";
        stream.masqueSettings.warp.privateKey = "priv";
        stream.masqueSettings.warp.publicKey = "pub";
        stream.masqueSettings.warp.address = { "10.0.0.1/32" };
        stream.masqueSettings.xmux.maxConcurrency = { 1, 2 };
        auto masque = stream.toJson()["masqueSettings"].toObject();
        REQUIRE(masque["user"].toString() == "user");
        REQUIRE(masque["pass"].toString() == "pass");
        REQUIRE(masque["warp"].toObject()["privateKey"].toString() == "priv");
        REQUIRE(masque["warp"].toObject()["address"].toArray().first().toString() == "10.0.0.1/32");
        REQUIRE(masque["xmux"].toObject()["maxConcurrency"].toString() == "1-2");

        stream.network = "hysteria";
        stream.hysteriaSettings.version = 2;
        stream.hysteriaSettings.auth = "secret";
        stream.hysteriaSettings.udpIdleTimeout = 60;
        stream.hysteriaSettings.masquerade.type = "proxy";
        stream.hysteriaSettings.masquerade.url = "https://example.com";
        stream.hysteriaSettings.masquerade.rewriteHost = true;
        stream.hysteriaSettings.masquerade.statusCode = 200;
        auto hysteria = stream.toJson()["hysteriaSettings"].toObject();
        REQUIRE(hysteria["version"].toInt() == 2);
        REQUIRE(hysteria["auth"].toString() == "secret");
        REQUIRE(hysteria["udpIdleTimeout"].toInt() == 60);
        REQUIRE(hysteria["masquerade"].toObject()["type"].toString() == "proxy");
        REQUIRE(hysteria["masquerade"].toObject()["statusCode"].toInt() == 200);

        stream.network = "hysteria2";
        stream.hy2Settings.password = "pass";
        stream.hy2Settings.congestion.type = "bbr";
        stream.hy2Settings.congestion.up_mbps = 100;
        stream.hy2Settings.congestion.down_mbps = 200;
        stream.hy2Settings.use_udp_extension = true;
        stream.hy2Settings.ignore_client_bandwidth = true;
        auto hy2 = stream.toJson()["hy2Settings"].toObject();
        REQUIRE(hy2["password"].toString() == "pass");
        REQUIRE(hy2["congestion"].toObject()["up_mbps"].toInt() == 100);
        REQUIRE(hy2["use_udp_extension"].toBool());

        stream.network = "xdrive";
        stream.xdriveSettings.remoteFolder = "folder";
        stream.xdriveSettings.service = "google-drive";
        stream.xdriveSettings.secrets = { "a", "b", "c" };
        stream.xdriveSettings.segmentBytes = 1024;
        stream.xdriveSettings.concurrency = 4;
        stream.xdriveSettings.templateConfig = QJsonObject{ { "key", "value" } };
        auto xdrive = stream.toJson()["xdriveSettings"].toObject();
        REQUIRE(xdrive["remoteFolder"].toString() == "folder");
        REQUIRE(xdrive["service"].toString() == "google-drive");
        REQUIRE(xdrive["secrets"].toArray().count() == 3);
        REQUIRE(xdrive["segmentBytes"].toInt() == 1024);
        REQUIRE(xdrive["concurrency"].toInt() == 4);
        REQUIRE(xdrive["template"].toObject()["key"].toString() == "value");
    }
}
