#pragma once
#include "base/models/CoreObjectModels.hpp"
#include "base/models/QvConfigIdentifier.hpp"
#include "base/models/QvSafeType.hpp"

#define CurrentStatAPIType (GlobalConfig.uiConfig.graphConfig.useOutboundStats ? API_OUTBOUND_PROXY : API_INBOUND)

namespace Qv2ray::core
{
    const inline GroupId DefaultGroupId{ "000000000000" };
    using namespace Qv2ray::base;
    using namespace Qv2ray::base::safetype;
    using namespace Qv2ray::base::objects;
    inline const QString getTag(const INBOUND &in)
    {
        return in["tag"].toString();
    }

    inline const QString getTag(const OUTBOUND &in)
    {
        return in["tag"].toString();
    }

    inline const QString getTag(const RuleObject &in)
    {
        return in.QV2RAY_RULE_TAG;
    }
    //
    // Detect which core dialect is used.  Generation code uses this for the
    // few options whose JSON representation differs between v2ray-core and
    // Xray-core.
    void SetDetectedCoreType(Qv2ray::base::config::Qv2rayCoreType type);
    // The core selected in the settings or detected from the version output.
    Qv2ray::base::config::Qv2rayCoreType GetCoreType();
    // Select the core needed by the protocols/features used by this config.
    // VLESS is handled by Xray-core, VMess by v2ray-core.  Configs mixing
    // both protocols fall back to Xray-core, which can still parse VMess.
    Qv2ray::base::config::Qv2rayCoreType GetCoreTypeForConfig(const CONFIGROOT &root);
    inline bool IsXrayCore()
    {
        return GetCoreType() == Qv2ray::base::config::CORE_XRAY;
    }
    inline bool IsXrayCore(const CONFIGROOT &root)
    {
        return GetCoreTypeForConfig(root) == Qv2ray::base::config::CORE_XRAY;
    }
    //
    int64_t GetConnectionLatency(const ConnectionId &id);
    uint64_t GetConnectionTotalData(const ConnectionId &id);
    const std::tuple<quint64, quint64> GetConnectionUsageAmount(const ConnectionId &id);
    //
    bool GetOutboundInfo(const OUTBOUND &out, QString *host, int *port, QString *protocol);
    inline ProtocolSettingsInfoObject GetOutboundInfo(const OUTBOUND &out)
    {
        ProtocolSettingsInfoObject o;
        GetOutboundInfo(out, &o.address, &o.port, &o.protocol);
        return o;
    }
    const ProtocolSettingsInfoObject GetConnectionInfo(const ConnectionId &id, bool *status = nullptr);
    const ProtocolSettingsInfoObject GetConnectionInfo(const CONFIGROOT &out, bool *status = nullptr);
    //
    bool IsComplexConfig(const CONFIGROOT &root);
    bool IsComplexConfig(const ConnectionId &id);
    //
    const QString GetConnectionProtocolString(const ConnectionId &id);
    //
    const QString GetDisplayName(const ConnectionId &id, int limit = -1);
    const QString GetDisplayName(const GroupId &id, int limit = -1);
    //
    // const GroupId GetConnectionGroupId(const ConnectionId &id);
    //
    bool GetInboundInfo(const INBOUND &in, QString *listen, int *port, QString *protocol);
    inline ProtocolSettingsInfoObject GetInboundInfo(const INBOUND &in)
    {
        ProtocolSettingsInfoObject o;
        GetInboundInfo(in, &o.address, &o.port, &o.protocol);
        return o;
    }

    const QMap<QString, ProtocolSettingsInfoObject> GetInboundInfo(const CONFIGROOT &root);
    const QMap<QString, ProtocolSettingsInfoObject> GetInboundInfo(const ConnectionId &id);
} // namespace Qv2ray::core

using namespace Qv2ray::core;
