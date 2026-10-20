#pragma once

#include "base/Qv2rayBase.hpp"
#include "ui/common/QvMessageBus.hpp"
#include "ui_StreamSettingsWidget.h"

#include <QCheckBox>
#include <QComboBox>
#include <QLineEdit>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QSpinBox>
#include <QWidget>

class StreamSettingsWidget
    : public QWidget
    , private Ui::StreamSettingsWidget
{
    Q_OBJECT

  public:
    explicit StreamSettingsWidget(QWidget *parent = nullptr);
    void SetStreamObject(const StreamSettingsObject &sso);
    StreamSettingsObject GetStreamSettings() const;

  private slots:
    void on_transportCombo_currentIndexChanged(int arg1);

    // Domain Socket
    void on_dsPathTxt_textEdited(const QString &arg1);

    // HTTP
    void on_httpHostTxt_textChanged();
    void on_httpPathTxt_textEdited(const QString &arg1);
    void on_httpMethodCB_currentTextChanged(const QString &arg1);
    void on_httpHeadersEditBtn_clicked();
    void on_httpHeadersDefBtn_clicked();

    // KCP
    void on_kcpCongestionCB_stateChanged(int arg1);
    void on_kcpDownCapacitySB_valueChanged(int arg1);
    void on_kcpHeaderType_currentIndexChanged(int arg1);
    void on_kcpMTU_valueChanged(int arg1);
    void on_kcpReadBufferSB_valueChanged(int arg1);
    void on_kcpSeedTxt_textEdited(const QString &arg1);
    void on_kcpTTI_valueChanged(int arg1);
    void on_kcpUploadCapacSB_valueChanged(int arg1);
    void on_kcpWriteBufferSB_valueChanged(int arg1);

    // QUIC
    void on_quicHeaderTypeCB_currentIndexChanged(int arg1);
    void on_quicKeyTxt_textEdited(const QString &arg1);
    void on_quicSecurityCB_currentIndexChanged(int arg1);

    // TLS/XTLS
    void on_allowInsecureCB_stateChanged(int arg1);
    void on_alpnTxt_textEdited(const QString &arg1);
    void on_enableSessionResumptionCB_stateChanged(int arg1);
    void on_securityTypeCB_currentIndexChanged(int arg1);
    void on_serverNameTxt_textEdited(const QString &arg1);
    void on_disableSystemRoot_stateChanged(int arg1);
    void on_openCertEditorBtn_clicked();

    // TCP
    void on_tcpFastOpenCB_stateChanged(int arg1);
    void on_tcpHeaderTypeCB_currentIndexChanged(int arg1);
    void on_tcpRequestDefBtn_clicked();
    void on_tcpRequestEditBtn_clicked();
    void on_tcpRespDefBtn_clicked();
    void on_tcpResponseEditBtn_clicked();

    // SOCKOPT
    void on_tProxyCB_currentIndexChanged(int arg1);
    void on_soMarkSpinBox_valueChanged(int arg1);
    void on_tcpKeepAliveIntervalSpinBox_valueChanged(int arg1);

    // WebSocket
    void on_wsHeadersTxt_textChanged();
    void on_wsPathTxt_textEdited(const QString &arg1);
    void on_wsEarlyDataSB_valueChanged(int arg1);
    void on_wsBrowserForwardCB_stateChanged(int arg1);
    void on_wsEarlyDataHeaderNameCB_currentIndexChanged(int arg1);

    // gRPC
    void on_grpcServiceNameTxt_textEdited(const QString &arg1);
    void on_grpcModeCB_currentIndexChanged(int arg1);
    //
    void on_pinnedPeerCertificateChainSha256Btn_clicked();

  private:
    QvMessageBusSlotDecl;
    StreamSettingsObject stream;
    QPlainTextEdit *advancedStreamJsonEdit = nullptr;

    struct XmuxControls
    {
        QLineEdit *maxConcurrency = nullptr;
        QLineEdit *maxConnections = nullptr;
        QLineEdit *cMaxReuseTimes = nullptr;
        QLineEdit *hMaxRequestTimes = nullptr;
        QLineEdit *hMaxReusableSecs = nullptr;
        QSpinBox *hKeepAlivePeriod = nullptr;
    };

    // Xray-core XHTTP / SplitHTTP.
    QLineEdit *xhttpHostTxt = nullptr;
    QLineEdit *xhttpPathTxt = nullptr;
    QComboBox *xhttpModeCB = nullptr;
    QPlainTextEdit *xhttpHeadersTxt = nullptr;
    QLineEdit *xhttpXPaddingBytesTxt = nullptr;
    QCheckBox *xhttpXPaddingObfsModeCB = nullptr;
    QLineEdit *xhttpXPaddingKeyTxt = nullptr;
    QLineEdit *xhttpXPaddingHeaderTxt = nullptr;
    QComboBox *xhttpXPaddingPlacementCB = nullptr;
    QComboBox *xhttpXPaddingMethodCB = nullptr;
    QComboBox *xhttpUplinkHTTPMethodCB = nullptr;
    QComboBox *xhttpSessionIDPlacementCB = nullptr;
    QLineEdit *xhttpSessionIDKeyTxt = nullptr;
    QLineEdit *xhttpSessionIDTableTxt = nullptr;
    QLineEdit *xhttpSessionIDLengthTxt = nullptr;
    QComboBox *xhttpSeqPlacementCB = nullptr;
    QLineEdit *xhttpSeqKeyTxt = nullptr;
    QComboBox *xhttpUplinkDataPlacementCB = nullptr;
    QLineEdit *xhttpUplinkDataKeyTxt = nullptr;
    QLineEdit *xhttpUplinkChunkSizeTxt = nullptr;
    QCheckBox *xhttpNoGRPCHeaderCB = nullptr;
    QCheckBox *xhttpNoSSEHeaderCB = nullptr;
    QLineEdit *xhttpScMaxEachPostBytesTxt = nullptr;
    QLineEdit *xhttpScMinPostsIntervalMsTxt = nullptr;
    QLineEdit *xhttpScMaxBufferedPostsTxt = nullptr;
    QLineEdit *xhttpScStreamUpServerSecsTxt = nullptr;
    QSpinBox *xhttpServerMaxHeaderBytesSB = nullptr;
    XmuxControls xhttpXmux;
    QPlainTextEdit *xhttpDownloadSettingsTxt = nullptr;
    QPlainTextEdit *xhttpExtraTxt = nullptr;

    // HTTPUpgrade.
    QLineEdit *httpupgradeHostTxt = nullptr;
    QLineEdit *httpupgradePathTxt = nullptr;
    QPlainTextEdit *httpupgradeHeadersTxt = nullptr;
    QCheckBox *httpupgradeAcceptProxyProtocolCB = nullptr;

    // MASQUE.
    QLineEdit *masqueHostTxt = nullptr;
    QLineEdit *masquePathTxt = nullptr;
    QLineEdit *masqueUserTxt = nullptr;
    QLineEdit *masquePassTxt = nullptr;
    QPlainTextEdit *masqueHeadersTxt = nullptr;
    QLineEdit *masqueWarpPrivateKeyTxt = nullptr;
    QLineEdit *masqueWarpPublicKeyTxt = nullptr;
    QPlainTextEdit *masqueWarpAddressTxt = nullptr;
    XmuxControls masqueXmux;

    // Xray hysteria transport.
    QSpinBox *hysteriaVersionSB = nullptr;
    QLineEdit *hysteriaAuthTxt = nullptr;
    QSpinBox *hysteriaUdpIdleTimeoutSB = nullptr;
    QComboBox *hysteriaMasqTypeCB = nullptr;
    QLineEdit *hysteriaMasqDirTxt = nullptr;
    QLineEdit *hysteriaMasqUrlTxt = nullptr;
    QCheckBox *hysteriaMasqRewriteHostCB = nullptr;
    QCheckBox *hysteriaMasqXForwardedCB = nullptr;
    QCheckBox *hysteriaMasqInsecureCB = nullptr;
    QPlainTextEdit *hysteriaMasqContentTxt = nullptr;
    QPlainTextEdit *hysteriaMasqHeadersTxt = nullptr;
    QSpinBox *hysteriaMasqStatusCodeSB = nullptr;

    // v2ray Hysteria2 transport.
    QLineEdit *hy2PasswordTxt = nullptr;
    QComboBox *hy2CongestionTypeCB = nullptr;
    QSpinBox *hy2UpMbpsSB = nullptr;
    QSpinBox *hy2DownMbpsSB = nullptr;
    QCheckBox *hy2UseUdpExtensionCB = nullptr;
    QCheckBox *hy2IgnoreClientBandwidthCB = nullptr;

    // REALITY client fields.
    QLineEdit *realityPublicKeyTxt = nullptr;
    QLineEdit *realityShortIdTxt = nullptr;
    QLineEdit *realitySpiderXTxt = nullptr;
    QLineEdit *realityFingerprintTxt = nullptr;
    QLineEdit *realityPrivateKeyTxt = nullptr;
    QLineEdit *realityTargetTxt = nullptr;
    // REALITY server fields.
    QLineEdit *realityMasterKeyLogTxt = nullptr;
    QCheckBox *realityShowCB = nullptr;
    QLineEdit *realityDestTxt = nullptr;
    QLineEdit *realityTypeTxt = nullptr;
    QSpinBox *realityXverSB = nullptr;
    QPlainTextEdit *realityServerNamesTxt = nullptr;
    QLineEdit *realityMinClientVerTxt = nullptr;
    QLineEdit *realityMaxClientVerTxt = nullptr;
    QSpinBox *realityMaxTimeDiffSB = nullptr;
    QPlainTextEdit *realityShortIdsTxt = nullptr;
    QLineEdit *realityMldsa65SeedTxt = nullptr;
    QLineEdit *realityLimitUploadAfterTxt = nullptr;
    QLineEdit *realityLimitUploadBytesTxt = nullptr;
    QLineEdit *realityLimitUploadBurstTxt = nullptr;
    QLineEdit *realityLimitDownloadAfterTxt = nullptr;
    QLineEdit *realityLimitDownloadBytesTxt = nullptr;
    QLineEdit *realityLimitDownloadBurstTxt = nullptr;

    // XDRIVE transport.
    QLineEdit *xdriveRemoteFolderTxt = nullptr;
    QComboBox *xdriveServiceTxt = nullptr;
    QPlainTextEdit *xdriveSecretsTxt = nullptr;
    QSpinBox *xdriveSegmentBytesSB = nullptr;
    QSpinBox *xdriveFlushIntervalMsSB = nullptr;
    QSpinBox *xdrivePollIntervalMsSB = nullptr;
    QSpinBox *xdriveMaxPollIntervalMsSB = nullptr;
    QSpinBox *xdriveSessionTtlSecondsSB = nullptr;
    QSpinBox *xdriveConcurrencySB = nullptr;
    QSpinBox *xdriveEagerWindowMsSB = nullptr;
    QSpinBox *xdriveHoleTimeoutMsSB = nullptr;
    QPlainTextEdit *xdriveTemplateTxt = nullptr;

    QLineEdit *grpcAuthorityTxt = nullptr;
    QSpinBox *kcpCwndMultiplierSB = nullptr;
    QSpinBox *kcpMaxSendingWindowSB = nullptr;
    QCheckBox *sockoptTcpMptcpCB = nullptr;
    QCheckBox *sockoptV6OnlyCB = nullptr;
    QComboBox *sockoptDomainStrategyCB = nullptr;
    QLineEdit *sockoptDialerProxyTxt = nullptr;
    QLineEdit *sockoptTcpCongestionTxt = nullptr;
    QLineEdit *sockoptInterfaceTxt = nullptr;
    QSpinBox *sockoptTcpUserTimeoutSB = nullptr;
};
