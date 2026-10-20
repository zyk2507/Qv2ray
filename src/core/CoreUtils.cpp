#include "CoreUtils.hpp"

#include "base/Qv2rayBase.hpp"
#include "core/connection/Serialization.hpp"
#include "core/handler/ConfigHandler.hpp"
#include "utils/QvHelpers.hpp"

#define QV_MODULE_NAME "CoreUtils"

namespace Qv2ray::core
{
    using namespace Qv2ray::base::config;

    namespace
    {
        Qv2rayCoreType detectedCoreType = CORE_AUTO;
    }

    void SetDetectedCoreType(Qv2rayCoreType type)
    {
        if (type != CORE_AUTO)
            detectedCoreType = type;
    }

    Qv2rayCoreType GetCoreType()
    {
        if (!QvCoreApplication)
            return detectedCoreType == CORE_AUTO ? CORE_V2RAY : detectedCoreType;
        if (GlobalConfig.kernelConfig.coreType != CORE_AUTO)
            return GlobalConfig.kernelConfig.coreType;
        if (detectedCoreType != CORE_AUTO)
            return detectedCoreType;
        return GlobalConfig.kernelConfig.EffectiveCoreType();
    }

    Qv2rayCoreType GetCoreTypeForConfig(const CONFIGROOT &root)
    {
        bool hasVLESS = false;
        bool hasVMess = false;
        bool needsXrayFeatures = false;
        const auto explicitType = QvCoreApplication ? GlobalConfig.kernelConfig.coreType : CORE_AUTO;

        const auto inspectEntry = [&](const QJsonObject &entry) {
            const auto protocol = entry["protocol"].toString().toLower();
            if (protocol == "vless")
                hasVLESS = true;
            else if (protocol == "vmess")
                hasVMess = true;

            const auto stream = entry["streamSettings"].toObject();
            const auto network = stream["network"].toString(stream["method"].toString()).toLower();
            const auto security = stream["security"].toString().toLower();
            if (network == "xhttp" || network == "splithttp" || network == "httpupgrade" || network == "hysteria" ||
                network == "masque" || network == "xdrive")
                needsXrayFeatures = true;
            if (security == "reality")
                needsXrayFeatures = true;
        };

        for (const auto &key : { "inbounds", "outbounds" })
        {
            for (const auto &entry : root[key].toArray())
                inspectEntry(entry.toObject());
        }

        // VLESS is a first-class Xray-core protocol.
        if (hasVLESS)
            return CORE_XRAY;

        if (hasVMess)
        {
            // Xray-only transports/security cannot run on v2ray-core.  The
            // requirement is to use v2ray-core for the VMess protocol, but a
            // configuration using REALITY/XHTTP has no v2ray-core equivalent.
            if (needsXrayFeatures || explicitType == CORE_XRAY)
            {
                LOG("VMess configuration uses Xray-only features, using Xray-core.");
                return CORE_XRAY;
            }
            // The user may explicitly force a core for advanced setups.
            if (explicitType == CORE_AUTO)
                return CORE_V2RAY;
        }

        if (explicitType != CORE_AUTO)
            return explicitType;

        if (detectedCoreType != CORE_AUTO)
            return detectedCoreType;

        return QvCoreApplication ? GlobalConfig.kernelConfig.EffectiveCoreType() : CORE_V2RAY;
    }

    bool IsComplexConfig(const ConnectionId &id)
    {
        return IsComplexConfig(ConnectionManager->GetConnectionRoot(id));
    }
    bool IsComplexConfig(const CONFIGROOT &root)
    {
        bool cRouting = root.contains("routing");
        bool cRule = cRouting && root["routing"].toObject().contains("rules");
        bool cRules = cRule && root["routing"].toObject()["rules"].toArray().count() > 0;
        //
        bool cInbounds = root.contains("inbounds");
        bool cInboundCount = cInbounds && root["inbounds"].toArray().count() > 0;
        //
        bool cOutbounds = root.contains("outbounds");
        bool cOutboundCount = cOutbounds && root["outbounds"].toArray().count() > 1;
        return cRules || cInboundCount || cOutboundCount;
    }

    bool GetOutboundInfo(const OUTBOUND &out, QString *host, int *port, QString *protocol)
    {
        *protocol = out["protocol"].toString(QObject::tr("N/A")).toLower();
        bool ok;
        const auto info = PluginHost->GetOutboundInfo(*protocol, out["settings"].toObject(), ok);
        if (ok)
        {
            *host = info[INFO_SERVER].toString();
            *port = info[INFO_PORT].toInt();
        }
        else
        {
            *host = QObject::tr("N/A");
            *port = 0;
        }
        return ok;
    }

    ///
    /// [Protocol, Host, Port]
    const ProtocolSettingsInfoObject GetConnectionInfo(const ConnectionId &id, bool *status)
    {
        if (status != nullptr)
            *status = false;
        const auto root = ConnectionManager->GetConnectionRoot(id);
        return GetConnectionInfo(root, status);
    }

    const ProtocolSettingsInfoObject GetConnectionInfo(const CONFIGROOT &out, bool *status)
    {
        if (status != nullptr)
            *status = false;
        //
        //
        for (const auto &item : out["outbounds"].toArray())
        {
            const auto outboundRoot = OUTBOUND(item.toObject());
            QString host;
            int port;
            QString outboundType = "";

            if (GetOutboundInfo(outboundRoot, &host, &port, &outboundType))
            {
                if (status != nullptr)
                    *status = true;
                // These lines will mess up the detection of protocols in subscription update.
                // if (IsComplexConfig(out))
                //{
                //    outboundType += " " + QObject::tr("(Guessed)");
                //    host += " " + QObject::tr("(Guessed)");
                //}
                return ProtocolSettingsInfoObject{ outboundType, host, port };
            }
            else
            {
                LOG("Unknown outbound type: " + outboundType + ", cannot deduce host and port.");
            }
        }
        return { QObject::tr("N/A"), QObject::tr("N/A"), 0 };
    }

    const std::tuple<quint64, quint64> GetConnectionUsageAmount(const ConnectionId &id)
    {
        auto connection = ConnectionManager->GetConnectionMetaObject(id);
        return { connection.stats[CurrentStatAPIType].upLinkData, connection.stats[CurrentStatAPIType].downLinkData };
    }

    uint64_t GetConnectionTotalData(const ConnectionId &id)
    {
        const auto &[a, b] = GetConnectionUsageAmount(id);
        return a + b;
    }

    int64_t GetConnectionLatency(const ConnectionId &id)
    {
        const auto connection = ConnectionManager->GetConnectionMetaObject(id);
        return std::max(connection.latency, {});
    }

    const QString GetConnectionProtocolString(const ConnectionId &id)
    {
        // Don't bother with the complex connection configs.
        if (IsComplexConfig(id))
        {
            return QV2RAY_SERIALIZATION_COMPLEX_CONFIG_PLACEHOLDER;
        }

        const auto root = ConnectionManager->GetConnectionRoot(id);
        const auto outbound = root["outbounds"].toArray().first().toObject();

        QStringList result;
        result << outbound["protocol"].toString();

        const auto streamSettings = outbound["streamSettings"].toObject();

        if (streamSettings.contains("network"))
            result << streamSettings["network"].toString();

        const auto security = streamSettings["security"].toString();
        if (!security.isEmpty() && security != "none")
            result << streamSettings["security"].toString();

        return result.join("+");
    }

    const QString GetDisplayName(const ConnectionId &id, int limit)
    {
        return TruncateString(ConnectionManager->GetConnectionMetaObject(id).displayName, limit);
    }

    const QString GetDisplayName(const GroupId &id, int limit)
    {
        return TruncateString(ConnectionManager->GetGroupMetaObject(id).displayName, limit);
    }

    bool GetInboundInfo(const INBOUND &in, QString *listen, int *port, QString *protocol)
    {
        *protocol = in["protocol"].toString();
        *listen = in["listen"].toString();
        *port = in["port"].toVariant().toInt();
        return true;
    }

    const QMap<QString, ProtocolSettingsInfoObject> GetInboundInfo(const CONFIGROOT &root)
    {
        QMap<QString, ProtocolSettingsInfoObject> inboundPorts;
        for (const auto &inboundVal : root["inbounds"].toArray())
        {
            INBOUND in{ inboundVal.toObject() };
            QString host, protocol;
            int port;
            if (GetInboundInfo(in, &host, &port, &protocol))
                inboundPorts[getTag(in)] = { protocol, host, port };
        }
        return inboundPorts;
    }

    const QMap<QString, ProtocolSettingsInfoObject> GetInboundInfo(const ConnectionId &id)
    {
        return GetInboundInfo(ConnectionManager->GetConnectionRoot(id));
    }
} // namespace Qv2ray::core
