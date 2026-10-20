#pragma once
#include "base/models/QvConfigIdentifier.hpp"
#include "base/models/QvCoreSettings.hpp"
#include "base/models/QvSafeType.hpp"

#include <QFile>
#include <chrono>

constexpr int QV2RAY_CONFIG_VERSION = 14;

namespace Qv2ray::base::config
{
    struct QvGraphPenConfig
    {
        int R = 150, G = 150, B = 150;
        float width = 1.5f;
        Qt::PenStyle style = Qt::SolidLine;
        QvGraphPenConfig(){};
        QvGraphPenConfig(int R, int G, int B, float w, Qt::PenStyle s)
        {
            this->R = R;
            this->G = G;
            this->B = B;
            this->width = w;
            this->style = s;
        };
        friend bool operator==(const QvGraphPenConfig &one, const QvGraphPenConfig &another)
        {
            return one.R == another.R && one.G == another.G && one.B == another.B && one.width == another.width && one.style == another.style;
        }
        JSONSTRUCT_REGISTER(QvGraphPenConfig, F(R, G, B, width, style))
    };

    struct Qv2rayConfig_Graph
    {
        bool useOutboundStats = true;
        bool hasDirectStats = true;
        safetype::QvEnumMap<StatisticsType, safetype::QvPair<QvGraphPenConfig>> colorConfig;
        JSONSTRUCT_COMPARE(Qv2rayConfig_Graph, useOutboundStats, hasDirectStats, colorConfig)
        JSONSTRUCT_REGISTER(Qv2rayConfig_Graph, F(useOutboundStats, hasDirectStats, colorConfig))
        const static inline QvPair<QvGraphPenConfig> DefaultPen{ { 134, 196, 63, 1.5f, Qt::SolidLine }, { 50, 153, 255, 1.5f, Qt::SolidLine } };
        const static inline QvPair<QvGraphPenConfig> DirectPen{ { 0, 210, 240, 1.5f, Qt::DotLine }, { 235, 220, 42, 1.5f, Qt::DotLine } };
    };

    struct Qv2rayConfig_UI
    {
#ifdef Q_OS_WIN
        QString theme = "windowsvista";
#elif defined(Q_OS_MACOS)
        QString theme = "macintosh";
#else
        QString theme = "Fusion";
#endif
        QString language = "en_US";
        QList<ConnectionGroupPair> recentConnections;
        Qv2rayConfig_Graph graphConfig;
        bool quietMode = false;
        bool useDarkTheme = false;
        bool useGlyphTrayIcon = true;
        bool useDarkTrayIcon = false;
        int maximumLogLines = 500;
        int maxJumpListCount = 20;
        bool useOldShareLinkFormat = false;
        bool startMinimized = true;
        bool exitByCloseEvent = false;
        JSONSTRUCT_COMPARE(Qv2rayConfig_UI, theme, language, quietMode, graphConfig, useDarkTheme, useDarkTrayIcon, useGlyphTrayIcon, maximumLogLines,
                           maxJumpListCount, recentConnections, useOldShareLinkFormat, startMinimized, exitByCloseEvent)
        JSONSTRUCT_REGISTER(Qv2rayConfig_UI, F(theme, language, quietMode, graphConfig, useDarkTheme, useDarkTrayIcon, useGlyphTrayIcon,
                                               maximumLogLines, maxJumpListCount, recentConnections, useOldShareLinkFormat, startMinimized, exitByCloseEvent))
    };

    struct Qv2rayConfig_Plugin
    {
        QMap<QString, bool> pluginStates;
        bool v2rayIntegration = true;
        int portAllocationStart = 15000;
        JSONSTRUCT_COMPARE(Qv2rayConfig_Plugin, pluginStates, v2rayIntegration, portAllocationStart)
        JSONSTRUCT_REGISTER(Qv2rayConfig_Plugin, F(pluginStates, v2rayIntegration, portAllocationStart))
    };

    struct Qv2rayConfig_Kernel
    {
        Qv2rayCoreType coreType = CORE_AUTO;
        bool enableAPI = true;
        int statsPort = 15490;
        //
        // v2ray-core path (VMess, VMessAEAD, Shadowsocks, ...).
        QString v2CorePath_linux;
        QString v2AssetsPath_linux;
        QString v2CorePath_macx;
        QString v2AssetsPath_macx;
        QString v2CorePath_win;
        QString v2AssetsPath_win;
        // Xray-core path (VLESS, REALITY, XHTTP, ...).
        QString xrayCorePath_linux;
        QString xrayAssetsPath_linux;
        QString xrayCorePath_macx;
        QString xrayAssetsPath_macx;
        QString xrayCorePath_win;
        QString xrayAssetsPath_win;

#ifdef Q_OS_LINUX
#define _VARNAME_VCOREPATH_ v2CorePath_linux
#define _VARNAME_VASSETSPATH_ v2AssetsPath_linux
#define _VARNAME_XRAYCOREPATH_ xrayCorePath_linux
#define _VARNAME_XRAYASSETSPATH_ xrayAssetsPath_linux
#elif defined(Q_OS_MACOS)
#define _VARNAME_VCOREPATH_ v2CorePath_macx
#define _VARNAME_VASSETSPATH_ v2AssetsPath_macx
#define _VARNAME_XRAYCOREPATH_ xrayCorePath_macx
#define _VARNAME_XRAYASSETSPATH_ xrayAssetsPath_macx
#elif defined(Q_OS_WIN)
#define _VARNAME_VCOREPATH_ v2CorePath_win
#define _VARNAME_VASSETSPATH_ v2AssetsPath_win
#define _VARNAME_XRAYCOREPATH_ xrayCorePath_win
#define _VARNAME_XRAYASSETSPATH_ xrayAssetsPath_win
#endif

        // The original (v2ray-core) getters/setters.
        inline QString KernelPath() const
        {
            return _VARNAME_VCOREPATH_;
        }
        inline const QString KernelPath(const QString &path)
        {
            return _VARNAME_VCOREPATH_ = path;
        }
        inline QString AssetsPath() const
        {
            return _VARNAME_VASSETSPATH_;
        }
        inline const QString AssetsPath(const QString &path)
        {
            return _VARNAME_VASSETSPATH_ = path;
        }
        // Xray-core getters/setters.
        inline QString XrayKernelPath() const
        {
            return _VARNAME_XRAYCOREPATH_;
        }
        inline const QString XrayKernelPath(const QString &path)
        {
            return _VARNAME_XRAYCOREPATH_ = path;
        }
        inline QString XrayAssetsPath() const
        {
            return _VARNAME_XRAYASSETSPATH_;
        }
        inline const QString XrayAssetsPath(const QString &path)
        {
            return _VARNAME_XRAYASSETSPATH_ = path;
        }
        inline QString KernelPath(Qv2rayCoreType type) const
        {
            return KernelPathFor(type);
        }
        inline QString AssetsPath(Qv2rayCoreType type) const
        {
            return AssetsPathFor(type);
        }
        inline QString KernelPathFor(Qv2rayCoreType type) const
        {
            if (type == CORE_AUTO)
                type = EffectiveCoreType();
            auto path = type == CORE_XRAY ? _VARNAME_XRAYCOREPATH_ : _VARNAME_VCOREPATH_;
            // A user may have configured only one core executable.  This is
            // useful when the same binary (or a renamed binary) is used for
            // both roles, and keeps old Qv2ray configurations working.
            if (path.isEmpty())
                path = type == CORE_XRAY ? _VARNAME_VCOREPATH_ : _VARNAME_XRAYCOREPATH_;
            // Convenience: "v2ray" and "xray" binaries are usually installed
            // next to each other.  If the Xray path was not configured, use
            // the matching sibling when it exists.
            if (type == CORE_XRAY && _VARNAME_XRAYCOREPATH_.isEmpty())
            {
                auto candidate = path;
                candidate.replace("v2ray", "xray", Qt::CaseInsensitive);
                if (candidate != path && QFile::exists(candidate))
                    path = candidate;
            }
            return path;
        }
        inline QString AssetsPathFor(Qv2rayCoreType type) const
        {
            if (type == CORE_AUTO)
                type = EffectiveCoreType();
            auto path = type == CORE_XRAY ? _VARNAME_XRAYASSETSPATH_ : _VARNAME_VASSETSPATH_;
            if (path.isEmpty())
                path = type == CORE_XRAY ? _VARNAME_VASSETSPATH_ : _VARNAME_XRAYASSETSPATH_;
            return path;
        }

#undef _VARNAME_VCOREPATH_
#undef _VARNAME_VASSETSPATH_
#undef _VARNAME_XRAYCOREPATH_
#undef _VARNAME_XRAYASSETSPATH_

        inline Qv2rayCoreType EffectiveCoreType() const
        {
            if (coreType != CORE_AUTO)
                return coreType;
            const auto executable = KernelPath().toLower();
            if (executable.contains("xray"))
                return CORE_XRAY;
            const auto xrayExecutable = XrayKernelPath().toLower();
            if (executable.isEmpty() && (xrayExecutable.contains("xray") || !xrayExecutable.isEmpty()))
                return CORE_XRAY;
            return CORE_V2RAY;
        }

        JSONSTRUCT_COMPARE(Qv2rayConfig_Kernel, coreType, enableAPI, statsPort,                         //
                           v2CorePath_linux, v2AssetsPath_linux, xrayCorePath_linux, xrayAssetsPath_linux, //
                           v2CorePath_macx, v2AssetsPath_macx, xrayCorePath_macx, xrayAssetsPath_macx,    //
                           v2CorePath_win, v2AssetsPath_win, xrayCorePath_win, xrayAssetsPath_win)
        JSONSTRUCT_REGISTER(Qv2rayConfig_Kernel,                                                                       //
                            F(coreType, enableAPI, statsPort),                                                         //
                            F(v2CorePath_linux, v2AssetsPath_linux, xrayCorePath_linux, xrayAssetsPath_linux),         //
                            F(v2CorePath_macx, v2AssetsPath_macx, xrayCorePath_macx, xrayAssetsPath_macx),             //
                            F(v2CorePath_win, v2AssetsPath_win, xrayCorePath_win, xrayAssetsPath_win))
    };

    struct Qv2rayConfig_Update
    {
        enum UpdateChannel
        {
            CHANNEL_STABLE = 0,
            CHANNEL_TESTING = 1
        };
        UpdateChannel updateChannel = CHANNEL_STABLE;
        QString ignoredVersion;
        JSONSTRUCT_COMPARE(Qv2rayConfig_Update, updateChannel, ignoredVersion)
        JSONSTRUCT_REGISTER(Qv2rayConfig_Update, F(ignoredVersion, updateChannel))
    };

    struct Qv2rayConfig_Advanced
    {
        bool testLatencyPeriodically = false;
        bool disableSystemRoot = false;
        bool testLatencyOnConnected = false;
        JSONSTRUCT_COMPARE(Qv2rayConfig_Advanced, testLatencyPeriodically, disableSystemRoot, testLatencyOnConnected)
        JSONSTRUCT_REGISTER(Qv2rayConfig_Advanced, F(testLatencyPeriodically, disableSystemRoot, testLatencyOnConnected))
    };

    enum Qv2rayLatencyTestingMethod
    {
        TCPING = 0,
        ICMPING = 1,
        REALPING = 2
    };

    struct Qv2rayConfig_Network
    {
        enum Qv2rayProxyType
        {
            QVPROXY_NONE = 0,
            QVPROXY_SYSTEM = 1,
            QVPROXY_CUSTOM = 2
        };

        Qv2rayLatencyTestingMethod latencyTestingMethod = TCPING;
        QString latencyRealPingTestURL = "https://www.google.com";
        Qv2rayProxyType proxyType = QVPROXY_NONE;
        QString address = "127.0.0.1";
        QString type = "http";
        int port = 8000;
        QString userAgent = "Qv2ray/$VERSION WebRequestHelper";
        JSONSTRUCT_COMPARE(Qv2rayConfig_Network, latencyTestingMethod, latencyRealPingTestURL, proxyType, type, address, port, userAgent)
        JSONSTRUCT_REGISTER(Qv2rayConfig_Network, F(latencyTestingMethod, latencyRealPingTestURL, proxyType, type, address, port, userAgent))
    };

    enum Qv2rayAutoConnectionBehavior
    {
        AUTO_CONNECTION_NONE = 0,
        AUTO_CONNECTION_FIXED = 1,
        AUTO_CONNECTION_LAST_CONNECTED = 2
    };

    struct Qv2rayConfigObject
    {
        int config_version;
        int logLevel = 0;
        //
        ConnectionGroupPair autoStartId;
        ConnectionGroupPair lastConnectedId;
        Qv2rayAutoConnectionBehavior autoStartBehavior = AUTO_CONNECTION_NONE;
        //
        Qv2rayConfig_UI uiConfig;
        Qv2rayConfig_Plugin pluginConfig;
        Qv2rayConfig_Kernel kernelConfig;
        Qv2rayConfig_Update updateConfig;
        Qv2rayConfig_Network networkConfig;
        QvConfig_Inbounds inboundConfig;
        QvConfig_Outbounds outboundConfig;
        Qv2rayConfig_Advanced advancedConfig;
        GroupRoutingConfig defaultRouteConfig;

        explicit Qv2rayConfigObject()
        {
            config_version = QV2RAY_CONFIG_VERSION;
        }
#if QT_VERSION < QT_VERSION_CHECK(5, 13, 0)
        Q_DISABLE_COPY(Qv2rayConfigObject);
#else
        Q_DISABLE_COPY_MOVE(Qv2rayConfigObject);
#endif
        JSONSTRUCT_COMPARE(Qv2rayConfigObject, config_version, logLevel, autoStartId, lastConnectedId, autoStartBehavior, uiConfig, pluginConfig,
                           kernelConfig, updateConfig, networkConfig, inboundConfig, outboundConfig, advancedConfig, defaultRouteConfig)
        JSONSTRUCT_REGISTER_NOCOPYMOVE(Qv2rayConfigObject,                                                                   //
                                       A(config_version, autoStartId, lastConnectedId, autoStartBehavior, logLevel),         //
                                       A(uiConfig, advancedConfig, pluginConfig, updateConfig, kernelConfig, networkConfig), //
                                       A(inboundConfig, outboundConfig, defaultRouteConfig))
    };
} // namespace Qv2ray::base::config
