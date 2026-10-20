#include "3rdparty/QJsonStruct/QJsonIO.hpp"
#include "Common.hpp"
#include "src/core/connection/Serialization.hpp"
#define CATCH_CONFIG_MAIN
#include "catch.hpp"

TEST_CASE("Test VLESS URL Parsing")
{
    QvTestApplication app;
    QString alias;
    QString errMessage;

    SECTION("VLESSTCPXTLSSplice")
    {
        const static auto url = "vless://b0dd64e4-0fbd-4038-9139-d1f32a68a0dc@qv2ray.net:3279?security=xtls&flow=rprx-xtls-splice#VLESSTCPXTLSSplice";

        const auto result = vless::Deserialize(url, &alias, &errMessage);

        INFO("Parsed: " << QJsonDocument(result).toJson().toStdString());
        REQUIRE(errMessage.isEmpty());
        REQUIRE(alias.toStdString() == "VLESSTCPXTLSSplice");
    }

    SECTION("ALPN Parse Test")
    {
        const static auto url = "vless://24a613c1-de83-4c63-ba73-a9d08c88fec3@qv2ray.net:13432?security=xtls&alpn=h2%2Chttp%2F1.1";

        const auto result = vless::Deserialize(url, &alias, &errMessage);

        INFO("Parsed: " << QJsonDocument(result).toJson().toStdString());
        REQUIRE(errMessage.isEmpty());

        const auto alpnField = QJsonIO::GetValue(result, "outbounds", 0, "streamSettings", "tlsSettings", "alpn");
        REQUIRE(alpnField.isArray());

        const auto alpnArray = alpnField.toArray();
        REQUIRE(!alpnArray.empty());
        REQUIRE(alpnArray.size() == 2);

        const auto firstALPN = alpnArray.first();
        REQUIRE(firstALPN.isString());

        const auto firstALPNString = firstALPN.toString();
        REQUIRE(firstALPNString.toStdString() == "h2");

        const auto lastALPN = alpnArray.last();
        REQUIRE(lastALPN.isString());

        const auto lastALPNString = lastALPN.toString();
        REQUIRE(lastALPNString.toStdString() == "http/1.1");
    }

    SECTION("gRPC Parse Test")
    {
        const static auto url = "vless://6d76fa31-8de2-40d4-8fee-6e61339c416f@qv2ray.net:123?type=grpc&security=tls&serviceName=FuckGFW&mode=multi";
        const auto result = vless::Deserialize(url, &alias, &errMessage);

        INFO("Parsed: " << QJsonDocument(result).toJson().toStdString());
        REQUIRE(errMessage.isEmpty());

        const auto grpcSettings = QJsonIO::GetValue(result, { "outbounds", 0, "streamSettings", "grpcSettings" });
        REQUIRE(grpcSettings.isObject());

        const auto grpcSettingsObj = grpcSettings.toObject();
        REQUIRE(grpcSettingsObj.contains("serviceName"));
        REQUIRE(grpcSettingsObj.contains("multiMode"));

        const auto serviceName = grpcSettingsObj["serviceName"];
        REQUIRE(serviceName.isString());

        const auto serviceNameString = serviceName.toString();
        REQUIRE(serviceNameString == "FuckGFW");

        const auto mode = grpcSettingsObj["multiMode"];
        REQUIRE(mode.isBool());

        const auto modeString = mode.toBool();
        REQUIRE(mode == true);
    }

    SECTION("REALITY Parse Test")
    {
        const static auto url = "vless://b0dd64e4-0fbd-4038-9139-d1f32a68a0dc@qv2ray.net:443?security=reality&flow=xtls-rprx-vision"
                                "&sni=www.example.com&fp=chrome&pbk=public-key&sid=0123456789abcdef&spx=%2F";
        const auto result = vless::Deserialize(url, &alias, &errMessage);

        INFO("Parsed: " << QJsonDocument(result).toJson().toStdString());
        REQUIRE(errMessage.isEmpty());

        const auto stream = QJsonIO::GetValue(result, "outbounds", 0, "streamSettings").toObject();
        REQUIRE(stream["security"].toString().toStdString() == "reality");
        REQUIRE(stream["realitySettings"].toObject()["publicKey"].toString().toStdString() == "public-key");
        REQUIRE(stream["realitySettings"].toObject()["shortId"].toString().toStdString() == "0123456789abcdef");
        REQUIRE(stream["realitySettings"].toObject()["fingerprint"].toString().toStdString() == "chrome");
        REQUIRE(QJsonIO::GetValue(result, "outbounds", 0, "settings", "vnext", 0, "users", 0, "flow").toString().toStdString() ==
                "xtls-rprx-vision");
    }

    SECTION("XHTTP and VLESS Encryption Parse Test")
    {
        const static auto url = "vless://b0dd64e4-0fbd-4038-9139-d1f32a68a0dc@qv2ray.net:443?type=xhttp&security=tls"
                                "&path=%2Ffoo&host=example.com&mode=stream-one&encryption=none";
        const auto result = vless::Deserialize(url, &alias, &errMessage);

        INFO("Parsed: " << QJsonDocument(result).toJson().toStdString());
        REQUIRE(errMessage.isEmpty());

        const auto stream = QJsonIO::GetValue(result, "outbounds", 0, "streamSettings").toObject();
        REQUIRE(stream["network"].toString().toStdString() == "xhttp");
        REQUIRE(stream["xhttpSettings"].toObject()["path"].toString().toStdString() == "/foo");
        REQUIRE(stream["xhttpSettings"].toObject()["host"].toString().toStdString() == "example.com");
        REQUIRE(stream["xhttpSettings"].toObject()["mode"].toString().toStdString() == "stream-one");
    }
}
