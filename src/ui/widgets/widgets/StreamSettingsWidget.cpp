#include "StreamSettingsWidget.hpp"

#include "ui/widgets/common/WidgetUIBase.hpp"
#include "ui/widgets/editors/w_ChainSha256Editor.hpp"
#include "ui/widgets/editors/w_JsonEditor.hpp"
#include "utils/QvHelpers.hpp"

#include <QCheckBox>
#include <QComboBox>
#include <QDialogButtonBox>
#include <QFileDialog>
#include <QFont>
#include <QFormLayout>
#include <QGroupBox>
#include <QJsonDocument>
#include <QLabel>
#include <QLineEdit>
#include <QHBoxLayout>
#include <QListWidget>
#include <QMessageBox>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QSpinBox>
#include <QVBoxLayout>

#include <limits>
#include <optional>

#define QV_MODULE_NAME "StreamSettingsWidget"

namespace
{
    QString RangeToText(const Int32RangeObject &range)
    {
        return range.from == range.to ? QString::number(range.from) : QStringLiteral("%1-%2").arg(range.from).arg(range.to);
    }

    Int32RangeObject RangeFromText(const QString &text)
    {
        Int32RangeObject range;
        range.loadJson(text.trimmed());
        return range;
    }

    QString HeadersToText(const QMap<QString, QString> &headers)
    {
        QStringList lines;
        for (const auto &[key, value] : headers.toStdMap())
            lines << key % "|" % value;
        return lines.join(NEWLINE);
    }

    void LoadHeadersText(const QString &text, QMap<QString, QString> &headers)
    {
        headers.clear();
        for (const auto &line : SplitLines(text))
        {
            if (line.isEmpty())
                continue;
            const auto index = line.indexOf('|');
            if (index < 0)
                continue;
            headers[line.left(index).trimmed()] = line.mid(index + 1).trimmed();
        }
    }

    QString JsonObjectToText(const QJsonObject &object)
    {
        return object.isEmpty() ? QString() : QString::fromUtf8(QJsonDocument(object).toJson(QJsonDocument::Indented));
    }

    std::optional<QJsonObject> JsonObjectFromText(const QString &text)
    {
        const auto trimmed = text.trimmed();
        if (trimmed.isEmpty())
            return QJsonObject{};
        QJsonParseError error;
        const auto doc = QJsonDocument::fromJson(trimmed.toUtf8(), &error);
        if (error.error != QJsonParseError::NoError || !doc.isObject())
            return std::nullopt;
        return doc.object();
    }

    QFormLayout *AddFormTab(QTabWidget *tabs, const QString &title)
    {
        auto page = new QWidget(tabs);
        auto layout = new QFormLayout(page);
        tabs->addTab(page, title);
        return layout;
    }

    void BrowseFile(QWidget *parent, QLineEdit *edit, const QString &title)
    {
        const auto file = QFileDialog::getOpenFileName(parent, title, QDir::currentPath());
        if (!file.isEmpty())
            edit->setText(file);
    }

    bool EditCertificates(QWidget *parent, QList<transfer::CertificateObject> &certificates)
    {
        QDialog dialog(parent);
        dialog.setWindowTitle(QObject::tr("TLS Certificate Editor"));
        dialog.resize(760, 560);
        auto rootLayout = new QVBoxLayout(&dialog);
        auto contentLayout = new QHBoxLayout();

        auto list = new QListWidget(&dialog);
        list->setMinimumWidth(220);
        auto addButton = new QPushButton(QObject::tr("Add"), &dialog);
        auto removeButton = new QPushButton(QObject::tr("Remove"), &dialog);
        auto listLayout = new QVBoxLayout();
        listLayout->addWidget(list);
        auto listButtons = new QHBoxLayout();
        listButtons->addWidget(addButton);
        listButtons->addWidget(removeButton);
        listLayout->addLayout(listButtons);
        contentLayout->addLayout(listLayout);

        auto formPage = new QWidget(&dialog);
        auto form = new QFormLayout(formPage);
        auto usageCombo = new QComboBox(formPage);
        usageCombo->setEditable(true);
        usageCombo->addItems({ "encipherment", "verify", "issue" });
        auto certFileEdit = new QLineEdit(formPage);
        auto certFileButton = new QPushButton(QObject::tr("Browse"), formPage);
        auto certFileLayout = new QHBoxLayout();
        certFileLayout->addWidget(certFileEdit);
        certFileLayout->addWidget(certFileButton);
        auto keyFileEdit = new QLineEdit(formPage);
        auto keyFileButton = new QPushButton(QObject::tr("Browse"), formPage);
        auto keyFileLayout = new QHBoxLayout();
        keyFileLayout->addWidget(keyFileEdit);
        keyFileLayout->addWidget(keyFileButton);
        auto certificateEdit = new QPlainTextEdit(formPage);
        certificateEdit->setPlaceholderText(QObject::tr("PEM certificate contents (one certificate per line is also accepted)"));
        auto keyEdit = new QPlainTextEdit(formPage);
        keyEdit->setPlaceholderText(QObject::tr("PEM private key contents"));
        auto ocspStapling = new QSpinBox(formPage);
        ocspStapling->setRange(0, std::numeric_limits<int>::max());
        auto oneTimeLoading = new QCheckBox(QObject::tr("One time loading"), formPage);
        auto buildChain = new QCheckBox(QObject::tr("Build certificate chain"), formPage);

        form->addRow(QObject::tr("Usage"), usageCombo);
        form->addRow(QObject::tr("Certificate File"), certFileLayout);
        form->addRow(QObject::tr("Key File"), keyFileLayout);
        form->addRow(QObject::tr("Certificate PEM"), certificateEdit);
        form->addRow(QObject::tr("Key PEM"), keyEdit);
        form->addRow(QObject::tr("OCSP Stapling"), ocspStapling);
        form->addRow(oneTimeLoading);
        form->addRow(buildChain);
        contentLayout->addWidget(formPage, 1);
        rootLayout->addLayout(contentLayout);

        auto buttons = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, &dialog);
        rootLayout->addWidget(buttons);

        bool loading = false;
        int current = -1;

        const auto refreshList = [&]() {
            list->clear();
            for (const auto &cert : certificates)
            {
                auto label = cert.usage;
                if (!cert.certificateFile.isEmpty())
                    label += " | " + cert.certificateFile;
                else if (!cert.certificate.isEmpty())
                    label += " | " + QObject::tr("inline certificate");
                list->addItem(label);
            }
        };

        const auto saveCurrent = [&]() {
            if (loading || current < 0 || current >= certificates.size())
                return;
            auto &cert = certificates[current];
            cert.usage = usageCombo->currentText().trimmed().isEmpty() ? "encipherment" : usageCombo->currentText().trimmed();
            cert.certificateFile = certFileEdit->text().trimmed();
            cert.keyFile = keyFileEdit->text().trimmed();
            cert.certificate = SplitLines(certificateEdit->toPlainText());
            cert.key = SplitLines(keyEdit->toPlainText());
            cert.ocspStapling = ocspStapling->value();
            cert.oneTimeLoading = oneTimeLoading->isChecked();
            cert.buildChain = buildChain->isChecked();
            if (auto item = list->item(current); item)
            {
                auto label = cert.usage;
                if (!cert.certificateFile.isEmpty())
                    label += " | " + cert.certificateFile;
                else if (!cert.certificate.isEmpty())
                    label += " | " + QObject::tr("inline certificate");
                item->setText(label);
            }
        };

        const auto loadCurrent = [&](int row) {
            loading = true;
            current = row;
            const auto valid = row >= 0 && row < certificates.size();
            formPage->setEnabled(valid);
            if (valid)
            {
                const auto &cert = certificates[row];
                usageCombo->setCurrentText(cert.usage);
                certFileEdit->setText(cert.certificateFile);
                keyFileEdit->setText(cert.keyFile);
                certificateEdit->setPlainText(cert.certificate.join(NEWLINE));
                keyEdit->setPlainText(cert.key.join(NEWLINE));
                ocspStapling->setValue(static_cast<int>(std::min<qint64>(cert.ocspStapling, std::numeric_limits<int>::max())));
                oneTimeLoading->setChecked(cert.oneTimeLoading);
                buildChain->setChecked(cert.buildChain);
            }
            loading = false;
        };

        QObject::connect(list, &QListWidget::currentRowChanged, &dialog, [&](int row) {
            saveCurrent();
            loadCurrent(row);
        });
        QObject::connect(addButton, &QPushButton::clicked, &dialog, [&]() {
            saveCurrent();
            transfer::CertificateObject cert;
            certificates << cert;
            current = -1;
            refreshList();
            list->setCurrentRow(certificates.size() - 1);
        });
        QObject::connect(removeButton, &QPushButton::clicked, &dialog, [&]() {
            if (current < 0 || current >= certificates.size())
                return;
            const auto removed = current;
            certificates.removeAt(removed);
            current = -1;
            refreshList();
            if (certificates.isEmpty())
                loadCurrent(-1);
            else
                list->setCurrentRow(std::min(removed, certificates.size() - 1));
        });
        QObject::connect(certFileButton, &QPushButton::clicked, &dialog, [&]() { BrowseFile(&dialog, certFileEdit, QObject::tr("Open Certificate File")); });
        QObject::connect(keyFileButton, &QPushButton::clicked, &dialog, [&]() { BrowseFile(&dialog, keyFileEdit, QObject::tr("Open Private Key File")); });
        QObject::connect(usageCombo, &QComboBox::currentTextChanged, &dialog, [&](const QString &) { saveCurrent(); });
        QObject::connect(certFileEdit, &QLineEdit::textEdited, &dialog, [&](const QString &) { saveCurrent(); });
        QObject::connect(keyFileEdit, &QLineEdit::textEdited, &dialog, [&](const QString &) { saveCurrent(); });
        QObject::connect(certificateEdit, &QPlainTextEdit::textChanged, &dialog, [&]() { saveCurrent(); });
        QObject::connect(keyEdit, &QPlainTextEdit::textChanged, &dialog, [&]() { saveCurrent(); });
        QObject::connect(ocspStapling, QOverload<int>::of(&QSpinBox::valueChanged), &dialog, [&](int) { saveCurrent(); });
        QObject::connect(oneTimeLoading, &QCheckBox::stateChanged, &dialog, [&](int) { saveCurrent(); });
        QObject::connect(buildChain, &QCheckBox::stateChanged, &dialog, [&](int) { saveCurrent(); });
        QObject::connect(buttons, &QDialogButtonBox::accepted, &dialog, &QDialog::accept);
        QObject::connect(buttons, &QDialogButtonBox::rejected, &dialog, &QDialog::reject);

        refreshList();
        loadCurrent(list->count() > 0 ? 0 : -1);
        if (dialog.exec() != QDialog::Accepted)
            return false;
        saveCurrent();
        return true;
    }
} // namespace

StreamSettingsWidget::StreamSettingsWidget(QWidget *parent) : QWidget(parent)
{
    setupUi(this);
    QvMessageBusConnect(StreamSettingsWidget);

    // v2ray-core and Xray-core have gained several transports over the years.
    // Keep the combo and stack indexes in sync, even for transports that do
    // not have a dedicated editor page yet.
    const auto addFormPage = [this](const QString &name) {
        auto page = new QWidget(v2rayStackView);
        auto layout = new QFormLayout(page);
        v2rayStackView->addWidget(page);
        transportCombo->addItem(name);
        return layout;
    };

    // XHTTP / SplitHTTP (Xray-core).
    {
        auto page = new QWidget(v2rayStackView);
        auto pageLayout = new QVBoxLayout(page);
        auto tabs = new QTabWidget(page);
        pageLayout->addWidget(tabs);
        v2rayStackView->addWidget(page);
        transportCombo->addItem("xhttp");

        auto basic = AddFormTab(tabs, tr("Basic"));
        xhttpHostTxt = new QLineEdit();
        xhttpPathTxt = new QLineEdit();
        xhttpModeCB = new QComboBox();
        xhttpModeCB->addItems({ "auto", "packet-up", "stream-up", "stream-one" });
        xhttpHeadersTxt = new QPlainTextEdit();
        xhttpHeadersTxt->setPlaceholderText(tr("Header|Value, one per line"));
        basic->addRow(tr("Host"), xhttpHostTxt);
        basic->addRow(tr("Path"), xhttpPathTxt);
        basic->addRow(tr("Mode"), xhttpModeCB);
        basic->addRow(tr("Headers"), xhttpHeadersTxt);

        auto padding = AddFormTab(tabs, tr("Padding"));
        xhttpXPaddingBytesTxt = new QLineEdit();
        xhttpXPaddingBytesTxt->setPlaceholderText(tr("e.g. 100-1000"));
        xhttpXPaddingObfsModeCB = new QCheckBox(tr("Obfuscate padding"));
        xhttpXPaddingKeyTxt = new QLineEdit();
        xhttpXPaddingHeaderTxt = new QLineEdit();
        xhttpXPaddingPlacementCB = new QComboBox();
        xhttpXPaddingPlacementCB->addItems({ "queryInHeader", "cookie", "header", "query" });
        xhttpXPaddingMethodCB = new QComboBox();
        xhttpXPaddingMethodCB->addItems({ "repeat-x", "tokenish" });
        padding->addRow(tr("Padding Bytes"), xhttpXPaddingBytesTxt);
        padding->addRow(xhttpXPaddingObfsModeCB);
        padding->addRow(tr("Padding Key"), xhttpXPaddingKeyTxt);
        padding->addRow(tr("Padding Header"), xhttpXPaddingHeaderTxt);
        padding->addRow(tr("Padding Placement"), xhttpXPaddingPlacementCB);
        padding->addRow(tr("Padding Method"), xhttpXPaddingMethodCB);

        auto session = AddFormTab(tabs, tr("Session"));
        xhttpSessionIDPlacementCB = new QComboBox();
        xhttpSessionIDPlacementCB->addItems({ "path", "cookie", "header", "query" });
        xhttpSessionIDKeyTxt = new QLineEdit();
        xhttpSessionIDTableTxt = new QLineEdit();
        xhttpSessionIDLengthTxt = new QLineEdit();
        xhttpSessionIDLengthTxt->setPlaceholderText(tr("e.g. 8-16"));
        xhttpSeqPlacementCB = new QComboBox();
        xhttpSeqPlacementCB->addItems({ "path", "cookie", "header", "query" });
        xhttpSeqKeyTxt = new QLineEdit();
        xhttpUplinkDataPlacementCB = new QComboBox();
        xhttpUplinkDataPlacementCB->addItems({ "auto", "body", "cookie", "header" });
        xhttpUplinkDataKeyTxt = new QLineEdit();
        xhttpUplinkChunkSizeTxt = new QLineEdit();
        xhttpUplinkChunkSizeTxt->setPlaceholderText(tr("e.g. 4096-8192"));
        xhttpUplinkHTTPMethodCB = new QComboBox();
        xhttpUplinkHTTPMethodCB->setEditable(true);
        xhttpUplinkHTTPMethodCB->addItems({ "POST", "GET", "PUT" });
        session->addRow(tr("Session ID Placement"), xhttpSessionIDPlacementCB);
        session->addRow(tr("Session ID Key"), xhttpSessionIDKeyTxt);
        session->addRow(tr("Session ID Table"), xhttpSessionIDTableTxt);
        session->addRow(tr("Session ID Length"), xhttpSessionIDLengthTxt);
        session->addRow(tr("Sequence Placement"), xhttpSeqPlacementCB);
        session->addRow(tr("Sequence Key"), xhttpSeqKeyTxt);
        session->addRow(tr("Uplink Data Placement"), xhttpUplinkDataPlacementCB);
        session->addRow(tr("Uplink Data Key"), xhttpUplinkDataKeyTxt);
        session->addRow(tr("Uplink Chunk Size"), xhttpUplinkChunkSizeTxt);
        session->addRow(tr("Uplink HTTP Method"), xhttpUplinkHTTPMethodCB);

        auto sc = AddFormTab(tabs, tr("Server/Client"));
        xhttpNoGRPCHeaderCB = new QCheckBox(tr("No gRPC header"));
        xhttpNoSSEHeaderCB = new QCheckBox(tr("No SSE header"));
        xhttpScMaxEachPostBytesTxt = new QLineEdit();
        xhttpScMaxEachPostBytesTxt->setPlaceholderText(tr("e.g. 1000000"));
        xhttpScMinPostsIntervalMsTxt = new QLineEdit();
        xhttpScMinPostsIntervalMsTxt->setPlaceholderText(tr("e.g. 30-30"));
        xhttpScMaxBufferedPostsTxt = new QLineEdit();
        xhttpScStreamUpServerSecsTxt = new QLineEdit();
        xhttpScStreamUpServerSecsTxt->setPlaceholderText(tr("e.g. 20-80"));
        xhttpServerMaxHeaderBytesSB = new QSpinBox();
        xhttpServerMaxHeaderBytesSB->setRange(0, std::numeric_limits<int>::max());
        sc->addRow(xhttpNoGRPCHeaderCB);
        sc->addRow(xhttpNoSSEHeaderCB);
        sc->addRow(tr("Max Each Post Bytes"), xhttpScMaxEachPostBytesTxt);
        sc->addRow(tr("Min Posts Interval (ms)"), xhttpScMinPostsIntervalMsTxt);
        sc->addRow(tr("Max Buffered Posts"), xhttpScMaxBufferedPostsTxt);
        sc->addRow(tr("Stream Up Server Secs"), xhttpScStreamUpServerSecsTxt);
        sc->addRow(tr("Server Max Header Bytes"), xhttpServerMaxHeaderBytesSB);

        auto xmuxLayout = AddFormTab(tabs, tr("Xmux"));
        xhttpXmux.maxConcurrency = new QLineEdit();
        xhttpXmux.maxConnections = new QLineEdit();
        xhttpXmux.cMaxReuseTimes = new QLineEdit();
        xhttpXmux.hMaxRequestTimes = new QLineEdit();
        xhttpXmux.hMaxReusableSecs = new QLineEdit();
        xhttpXmux.hKeepAlivePeriod = new QSpinBox();
        xhttpXmux.hKeepAlivePeriod->setRange(0, std::numeric_limits<int>::max());
        xmuxLayout->addRow(tr("Max Concurrency"), xhttpXmux.maxConcurrency);
        xmuxLayout->addRow(tr("Max Connections"), xhttpXmux.maxConnections);
        xmuxLayout->addRow(tr("C Max Reuse Times"), xhttpXmux.cMaxReuseTimes);
        xmuxLayout->addRow(tr("H Max Request Times"), xhttpXmux.hMaxRequestTimes);
        xmuxLayout->addRow(tr("H Max Reusable Secs"), xhttpXmux.hMaxReusableSecs);
        xmuxLayout->addRow(tr("H Keep Alive Period"), xhttpXmux.hKeepAlivePeriod);

        auto advanced = AddFormTab(tabs, tr("Advanced"));
        xhttpDownloadSettingsTxt = new QPlainTextEdit();
        xhttpDownloadSettingsTxt->setPlaceholderText(tr("Full StreamSettings JSON for downloadSettings; not allowed in stream-one mode"));
        xhttpExtraTxt = new QPlainTextEdit();
        xhttpExtraTxt->setPlaceholderText(tr("Raw JSON object used as XHTTP \"extra\""));
        advanced->addRow(tr("downloadSettings"), xhttpDownloadSettingsTxt);
        advanced->addRow(tr("extra"), xhttpExtraTxt);

        connect(xhttpHostTxt, &QLineEdit::textEdited, this, [this](const QString &arg1) { stream.xhttpSettings.host = arg1; });
        connect(xhttpPathTxt, &QLineEdit::textEdited, this, [this](const QString &arg1) { stream.xhttpSettings.path = arg1; });
        connect(xhttpModeCB, &QComboBox::currentTextChanged, this, [this](const QString &arg1) { stream.xhttpSettings.mode = arg1; });
        connect(xhttpHeadersTxt, &QPlainTextEdit::textChanged, this,
                [this]() { LoadHeadersText(xhttpHeadersTxt->toPlainText(), stream.xhttpSettings.headers); });
        connect(xhttpXPaddingBytesTxt, &QLineEdit::textEdited, this,
                [this](const QString &arg1) { stream.xhttpSettings.xPaddingBytes = RangeFromText(arg1); });
        connect(xhttpXPaddingObfsModeCB, &QCheckBox::stateChanged, this,
                [this](int arg1) { stream.xhttpSettings.xPaddingObfsMode = arg1 == Qt::Checked; });
        connect(xhttpXPaddingKeyTxt, &QLineEdit::textEdited, this, [this](const QString &arg1) { stream.xhttpSettings.xPaddingKey = arg1; });
        connect(xhttpXPaddingHeaderTxt, &QLineEdit::textEdited, this,
                [this](const QString &arg1) { stream.xhttpSettings.xPaddingHeader = arg1; });
        connect(xhttpXPaddingPlacementCB, &QComboBox::currentTextChanged, this,
                [this](const QString &arg1) { stream.xhttpSettings.xPaddingPlacement = arg1; });
        connect(xhttpXPaddingMethodCB, &QComboBox::currentTextChanged, this,
                [this](const QString &arg1) { stream.xhttpSettings.xPaddingMethod = arg1; });
        connect(xhttpUplinkHTTPMethodCB, &QComboBox::currentTextChanged, this,
                [this](const QString &arg1) { stream.xhttpSettings.uplinkHTTPMethod = arg1; });
        connect(xhttpSessionIDPlacementCB, &QComboBox::currentTextChanged, this,
                [this](const QString &arg1) { stream.xhttpSettings.sessionIDPlacement = arg1; });
        connect(xhttpSessionIDKeyTxt, &QLineEdit::textEdited, this,
                [this](const QString &arg1) { stream.xhttpSettings.sessionIDKey = arg1; });
        connect(xhttpSessionIDTableTxt, &QLineEdit::textEdited, this,
                [this](const QString &arg1) { stream.xhttpSettings.sessionIDTable = arg1; });
        connect(xhttpSessionIDLengthTxt, &QLineEdit::textEdited, this,
                [this](const QString &arg1) { stream.xhttpSettings.sessionIDLength = RangeFromText(arg1); });
        connect(xhttpSeqPlacementCB, &QComboBox::currentTextChanged, this,
                [this](const QString &arg1) { stream.xhttpSettings.seqPlacement = arg1; });
        connect(xhttpSeqKeyTxt, &QLineEdit::textEdited, this, [this](const QString &arg1) { stream.xhttpSettings.seqKey = arg1; });
        connect(xhttpUplinkDataPlacementCB, &QComboBox::currentTextChanged, this,
                [this](const QString &arg1) { stream.xhttpSettings.uplinkDataPlacement = arg1; });
        connect(xhttpUplinkDataKeyTxt, &QLineEdit::textEdited, this,
                [this](const QString &arg1) { stream.xhttpSettings.uplinkDataKey = arg1; });
        connect(xhttpUplinkChunkSizeTxt, &QLineEdit::textEdited, this,
                [this](const QString &arg1) { stream.xhttpSettings.uplinkChunkSize = RangeFromText(arg1); });
        connect(xhttpNoGRPCHeaderCB, &QCheckBox::stateChanged, this,
                [this](int arg1) { stream.xhttpSettings.noGRPCHeader = arg1 == Qt::Checked; });
        connect(xhttpNoSSEHeaderCB, &QCheckBox::stateChanged, this,
                [this](int arg1) { stream.xhttpSettings.noSSEHeader = arg1 == Qt::Checked; });
        connect(xhttpScMaxEachPostBytesTxt, &QLineEdit::textEdited, this,
                [this](const QString &arg1) { stream.xhttpSettings.scMaxEachPostBytes = RangeFromText(arg1); });
        connect(xhttpScMinPostsIntervalMsTxt, &QLineEdit::textEdited, this,
                [this](const QString &arg1) { stream.xhttpSettings.scMinPostsIntervalMs = RangeFromText(arg1); });
        connect(xhttpScMaxBufferedPostsTxt, &QLineEdit::textEdited, this,
                [this](const QString &arg1) { stream.xhttpSettings.scMaxBufferedPosts = arg1.toLongLong(); });
        connect(xhttpScStreamUpServerSecsTxt, &QLineEdit::textEdited, this,
                [this](const QString &arg1) { stream.xhttpSettings.scStreamUpServerSecs = RangeFromText(arg1); });
        connect(xhttpServerMaxHeaderBytesSB, QOverload<int>::of(&QSpinBox::valueChanged), this,
                [this](int arg1) { stream.xhttpSettings.serverMaxHeaderBytes = arg1; });
        connect(xhttpXmux.maxConcurrency, &QLineEdit::textEdited, this,
                [this](const QString &arg1) { stream.xhttpSettings.xmux.maxConcurrency = RangeFromText(arg1); });
        connect(xhttpXmux.maxConnections, &QLineEdit::textEdited, this,
                [this](const QString &arg1) { stream.xhttpSettings.xmux.maxConnections = RangeFromText(arg1); });
        connect(xhttpXmux.cMaxReuseTimes, &QLineEdit::textEdited, this,
                [this](const QString &arg1) { stream.xhttpSettings.xmux.cMaxReuseTimes = RangeFromText(arg1); });
        connect(xhttpXmux.hMaxRequestTimes, &QLineEdit::textEdited, this,
                [this](const QString &arg1) { stream.xhttpSettings.xmux.hMaxRequestTimes = RangeFromText(arg1); });
        connect(xhttpXmux.hMaxReusableSecs, &QLineEdit::textEdited, this,
                [this](const QString &arg1) { stream.xhttpSettings.xmux.hMaxReusableSecs = RangeFromText(arg1); });
        connect(xhttpXmux.hKeepAlivePeriod, QOverload<int>::of(&QSpinBox::valueChanged), this,
                [this](int arg1) { stream.xhttpSettings.xmux.hKeepAlivePeriod = arg1; });
        connect(xhttpDownloadSettingsTxt, &QPlainTextEdit::textChanged, this, [this]() {
            const auto value = JsonObjectFromText(xhttpDownloadSettingsTxt->toPlainText());
            if (value.has_value())
                stream.xhttpSettings.downloadSettings = *value;
        });
        connect(xhttpExtraTxt, &QPlainTextEdit::textChanged, this, [this]() {
            const auto value = JsonObjectFromText(xhttpExtraTxt->toPlainText());
            if (value.has_value())
                stream.xhttpSettings.extra = *value;
        });
    }

    // HTTPUpgrade (Xray-core).
    {
        auto layout = addFormPage("httpupgrade");
        httpupgradeHostTxt = new QLineEdit();
        httpupgradePathTxt = new QLineEdit();
        httpupgradeHeadersTxt = new QPlainTextEdit();
        httpupgradeHeadersTxt->setPlaceholderText(tr("Header|Value, one per line"));
        httpupgradeAcceptProxyProtocolCB = new QCheckBox(tr("Accept PROXY protocol"));
        layout->addRow(tr("Host"), httpupgradeHostTxt);
        layout->addRow(tr("Path"), httpupgradePathTxt);
        layout->addRow(tr("Headers"), httpupgradeHeadersTxt);
        layout->addRow(httpupgradeAcceptProxyProtocolCB);
        connect(httpupgradeHostTxt, &QLineEdit::textEdited, this, [this](const QString &arg1) { stream.httpupgradeSettings.host = arg1; });
        connect(httpupgradePathTxt, &QLineEdit::textEdited, this, [this](const QString &arg1) { stream.httpupgradeSettings.path = arg1; });
        connect(httpupgradeHeadersTxt, &QPlainTextEdit::textChanged, this,
                [this]() { LoadHeadersText(httpupgradeHeadersTxt->toPlainText(), stream.httpupgradeSettings.headers); });
        connect(httpupgradeAcceptProxyProtocolCB, &QCheckBox::stateChanged, this,
                [this](int arg1) { stream.httpupgradeSettings.acceptProxyProtocol = arg1 == Qt::Checked; });
    }

    // Xray hysteria transport.
    {
        auto page = new QWidget(v2rayStackView);
        auto layout = new QFormLayout(page);
        v2rayStackView->addWidget(page);
        transportCombo->addItem("hysteria");
        hysteriaVersionSB = new QSpinBox();
        hysteriaVersionSB->setRange(0, 3);
        hysteriaAuthTxt = new QLineEdit();
        hysteriaUdpIdleTimeoutSB = new QSpinBox();
        hysteriaUdpIdleTimeoutSB->setRange(0, 600);
        hysteriaMasqTypeCB = new QComboBox();
        hysteriaMasqTypeCB->setEditable(true);
        hysteriaMasqTypeCB->addItems({ "404", "file", "proxy", "string" });
        hysteriaMasqDirTxt = new QLineEdit();
        hysteriaMasqUrlTxt = new QLineEdit();
        hysteriaMasqRewriteHostCB = new QCheckBox(tr("Rewrite Host"));
        hysteriaMasqXForwardedCB = new QCheckBox(tr("Add X-Forwarded headers"));
        hysteriaMasqInsecureCB = new QCheckBox(tr("Insecure TLS for proxy target"));
        hysteriaMasqContentTxt = new QPlainTextEdit();
        hysteriaMasqHeadersTxt = new QPlainTextEdit();
        hysteriaMasqHeadersTxt->setPlaceholderText(tr("Header|Value, one per line"));
        hysteriaMasqStatusCodeSB = new QSpinBox();
        hysteriaMasqStatusCodeSB->setRange(0, 999);
        layout->addRow(tr("Version"), hysteriaVersionSB);
        layout->addRow(tr("Auth"), hysteriaAuthTxt);
        layout->addRow(tr("UDP Idle Timeout"), hysteriaUdpIdleTimeoutSB);
        layout->addRow(tr("Masquerade Type"), hysteriaMasqTypeCB);
        layout->addRow(tr("Masquerade Dir"), hysteriaMasqDirTxt);
        layout->addRow(tr("Masquerade URL"), hysteriaMasqUrlTxt);
        layout->addRow(hysteriaMasqRewriteHostCB);
        layout->addRow(hysteriaMasqXForwardedCB);
        layout->addRow(hysteriaMasqInsecureCB);
        layout->addRow(tr("Masquerade Content"), hysteriaMasqContentTxt);
        layout->addRow(tr("Masquerade Headers"), hysteriaMasqHeadersTxt);
        layout->addRow(tr("Masquerade Status Code"), hysteriaMasqStatusCodeSB);
        connect(hysteriaVersionSB, QOverload<int>::of(&QSpinBox::valueChanged), this,
                [this](int arg1) { stream.hysteriaSettings.version = arg1; });
        connect(hysteriaAuthTxt, &QLineEdit::textEdited, this, [this](const QString &arg1) { stream.hysteriaSettings.auth = arg1; });
        connect(hysteriaUdpIdleTimeoutSB, QOverload<int>::of(&QSpinBox::valueChanged), this,
                [this](int arg1) { stream.hysteriaSettings.udpIdleTimeout = arg1; });
        connect(hysteriaMasqTypeCB, &QComboBox::currentTextChanged, this,
                [this](const QString &arg1) { stream.hysteriaSettings.masquerade.type = arg1; });
        connect(hysteriaMasqDirTxt, &QLineEdit::textEdited, this,
                [this](const QString &arg1) { stream.hysteriaSettings.masquerade.dir = arg1; });
        connect(hysteriaMasqUrlTxt, &QLineEdit::textEdited, this,
                [this](const QString &arg1) { stream.hysteriaSettings.masquerade.url = arg1; });
        connect(hysteriaMasqRewriteHostCB, &QCheckBox::stateChanged, this,
                [this](int arg1) { stream.hysteriaSettings.masquerade.rewriteHost = arg1 == Qt::Checked; });
        connect(hysteriaMasqXForwardedCB, &QCheckBox::stateChanged, this,
                [this](int arg1) { stream.hysteriaSettings.masquerade.xForwarded = arg1 == Qt::Checked; });
        connect(hysteriaMasqInsecureCB, &QCheckBox::stateChanged, this,
                [this](int arg1) { stream.hysteriaSettings.masquerade.insecure = arg1 == Qt::Checked; });
        connect(hysteriaMasqContentTxt, &QPlainTextEdit::textChanged, this,
                [this]() { stream.hysteriaSettings.masquerade.content = hysteriaMasqContentTxt->toPlainText(); });
        connect(hysteriaMasqHeadersTxt, &QPlainTextEdit::textChanged, this,
                [this]() { LoadHeadersText(hysteriaMasqHeadersTxt->toPlainText(), stream.hysteriaSettings.masquerade.headers); });
        connect(hysteriaMasqStatusCodeSB, QOverload<int>::of(&QSpinBox::valueChanged), this,
                [this](int arg1) { stream.hysteriaSettings.masquerade.statusCode = arg1; });
    }

    // v2ray Hysteria2 transport.
    {
        auto page = new QWidget(v2rayStackView);
        auto layout = new QFormLayout(page);
        v2rayStackView->addWidget(page);
        transportCombo->addItem("hysteria2");
        hy2PasswordTxt = new QLineEdit();
        hy2CongestionTypeCB = new QComboBox();
        hy2CongestionTypeCB->setEditable(true);
        hy2CongestionTypeCB->addItems({ "", "brutal", "bbr" });
        hy2UpMbpsSB = new QSpinBox();
        hy2UpMbpsSB->setRange(0, std::numeric_limits<int>::max());
        hy2DownMbpsSB = new QSpinBox();
        hy2DownMbpsSB->setRange(0, std::numeric_limits<int>::max());
        hy2UseUdpExtensionCB = new QCheckBox(tr("Use UDP extension"));
        hy2IgnoreClientBandwidthCB = new QCheckBox(tr("Ignore client bandwidth"));
        layout->addRow(tr("Password"), hy2PasswordTxt);
        layout->addRow(tr("Congestion Type"), hy2CongestionTypeCB);
        layout->addRow(tr("Up Mbps"), hy2UpMbpsSB);
        layout->addRow(tr("Down Mbps"), hy2DownMbpsSB);
        layout->addRow(hy2UseUdpExtensionCB);
        layout->addRow(hy2IgnoreClientBandwidthCB);
        connect(hy2PasswordTxt, &QLineEdit::textEdited, this, [this](const QString &arg1) { stream.hy2Settings.password = arg1; });
        connect(hy2CongestionTypeCB, &QComboBox::currentTextChanged, this,
                [this](const QString &arg1) { stream.hy2Settings.congestion.type = arg1; });
        connect(hy2UpMbpsSB, QOverload<int>::of(&QSpinBox::valueChanged), this,
                [this](int arg1) { stream.hy2Settings.congestion.up_mbps = arg1; });
        connect(hy2DownMbpsSB, QOverload<int>::of(&QSpinBox::valueChanged), this,
                [this](int arg1) { stream.hy2Settings.congestion.down_mbps = arg1; });
        connect(hy2UseUdpExtensionCB, &QCheckBox::stateChanged, this,
                [this](int arg1) { stream.hy2Settings.use_udp_extension = arg1 == Qt::Checked; });
        connect(hy2IgnoreClientBandwidthCB, &QCheckBox::stateChanged, this,
                [this](int arg1) { stream.hy2Settings.ignore_client_bandwidth = arg1 == Qt::Checked; });
    }

    // MASQUE transport (Xray-core).
    {
        auto page = new QWidget(v2rayStackView);
        auto pageLayout = new QVBoxLayout(page);
        auto tabs = new QTabWidget(page);
        pageLayout->addWidget(tabs);
        v2rayStackView->addWidget(page);
        transportCombo->addItem("masque");

        auto basic = AddFormTab(tabs, tr("Basic"));
        masqueHostTxt = new QLineEdit();
        masquePathTxt = new QLineEdit();
        masqueUserTxt = new QLineEdit();
        masquePassTxt = new QLineEdit();
        masqueHeadersTxt = new QPlainTextEdit();
        masqueHeadersTxt->setPlaceholderText(tr("Header|Value, one per line"));
        basic->addRow(tr("Host"), masqueHostTxt);
        basic->addRow(tr("Path"), masquePathTxt);
        basic->addRow(tr("User"), masqueUserTxt);
        basic->addRow(tr("Password"), masquePassTxt);
        basic->addRow(tr("Headers"), masqueHeadersTxt);

        auto warp = AddFormTab(tabs, tr("WARP"));
        masqueWarpPrivateKeyTxt = new QLineEdit();
        masqueWarpPublicKeyTxt = new QLineEdit();
        masqueWarpAddressTxt = new QPlainTextEdit();
        masqueWarpAddressTxt->setPlaceholderText(tr("One address per line"));
        warp->addRow(tr("Private Key"), masqueWarpPrivateKeyTxt);
        warp->addRow(tr("Public Key"), masqueWarpPublicKeyTxt);
        warp->addRow(tr("Address"), masqueWarpAddressTxt);

        auto xmuxLayout = AddFormTab(tabs, tr("Xmux"));
        masqueXmux.maxConcurrency = new QLineEdit();
        masqueXmux.maxConnections = new QLineEdit();
        masqueXmux.cMaxReuseTimes = new QLineEdit();
        masqueXmux.hMaxRequestTimes = new QLineEdit();
        masqueXmux.hMaxReusableSecs = new QLineEdit();
        masqueXmux.hKeepAlivePeriod = new QSpinBox();
        masqueXmux.hKeepAlivePeriod->setRange(0, std::numeric_limits<int>::max());
        xmuxLayout->addRow(tr("Max Concurrency"), masqueXmux.maxConcurrency);
        xmuxLayout->addRow(tr("Max Connections"), masqueXmux.maxConnections);
        xmuxLayout->addRow(tr("C Max Reuse Times"), masqueXmux.cMaxReuseTimes);
        xmuxLayout->addRow(tr("H Max Request Times"), masqueXmux.hMaxRequestTimes);
        xmuxLayout->addRow(tr("H Max Reusable Secs"), masqueXmux.hMaxReusableSecs);
        xmuxLayout->addRow(tr("H Keep Alive Period"), masqueXmux.hKeepAlivePeriod);

        connect(masqueHostTxt, &QLineEdit::textEdited, this, [this](const QString &arg1) { stream.masqueSettings.host = arg1; });
        connect(masquePathTxt, &QLineEdit::textEdited, this, [this](const QString &arg1) { stream.masqueSettings.path = arg1; });
        connect(masqueUserTxt, &QLineEdit::textEdited, this, [this](const QString &arg1) { stream.masqueSettings.user = arg1; });
        connect(masquePassTxt, &QLineEdit::textEdited, this, [this](const QString &arg1) { stream.masqueSettings.pass = arg1; });
        connect(masqueHeadersTxt, &QPlainTextEdit::textChanged, this,
                [this]() { LoadHeadersText(masqueHeadersTxt->toPlainText(), stream.masqueSettings.headers); });
        connect(masqueWarpPrivateKeyTxt, &QLineEdit::textEdited, this,
                [this](const QString &arg1) { stream.masqueSettings.warp.privateKey = arg1; });
        connect(masqueWarpPublicKeyTxt, &QLineEdit::textEdited, this,
                [this](const QString &arg1) { stream.masqueSettings.warp.publicKey = arg1; });
        connect(masqueWarpAddressTxt, &QPlainTextEdit::textChanged, this,
                [this]() { stream.masqueSettings.warp.address = SplitLines(masqueWarpAddressTxt->toPlainText()); });
        connect(masqueXmux.maxConcurrency, &QLineEdit::textEdited, this,
                [this](const QString &arg1) { stream.masqueSettings.xmux.maxConcurrency = RangeFromText(arg1); });
        connect(masqueXmux.maxConnections, &QLineEdit::textEdited, this,
                [this](const QString &arg1) { stream.masqueSettings.xmux.maxConnections = RangeFromText(arg1); });
        connect(masqueXmux.cMaxReuseTimes, &QLineEdit::textEdited, this,
                [this](const QString &arg1) { stream.masqueSettings.xmux.cMaxReuseTimes = RangeFromText(arg1); });
        connect(masqueXmux.hMaxRequestTimes, &QLineEdit::textEdited, this,
                [this](const QString &arg1) { stream.masqueSettings.xmux.hMaxRequestTimes = RangeFromText(arg1); });
        connect(masqueXmux.hMaxReusableSecs, &QLineEdit::textEdited, this,
                [this](const QString &arg1) { stream.masqueSettings.xmux.hMaxReusableSecs = RangeFromText(arg1); });
        connect(masqueXmux.hKeepAlivePeriod, QOverload<int>::of(&QSpinBox::valueChanged), this,
                [this](int arg1) { stream.masqueSettings.xmux.hKeepAlivePeriod = arg1; });
    }

    // XDRIVE transport (Xray-core).
    {
        auto page = new QWidget(v2rayStackView);
        auto pageLayout = new QVBoxLayout(page);
        auto tabs = new QTabWidget(page);
        pageLayout->addWidget(tabs);
        v2rayStackView->addWidget(page);
        transportCombo->addItem("xdrive");

        auto basic = AddFormTab(tabs, tr("Basic"));
        xdriveRemoteFolderTxt = new QLineEdit();
        xdriveServiceTxt = new QComboBox();
        xdriveServiceTxt->setEditable(true);
        xdriveServiceTxt->addItems({ "google-drive", "template", "local" });
        xdriveSecretsTxt = new QPlainTextEdit();
        xdriveSecretsTxt->setPlaceholderText(tr("One secret per line (Google Drive needs ClientID, ClientSecret, RefreshToken)"));
        basic->addRow(tr("Remote Folder"), xdriveRemoteFolderTxt);
        basic->addRow(tr("Service"), xdriveServiceTxt);
        basic->addRow(tr("Secrets"), xdriveSecretsTxt);

        auto tuning = AddFormTab(tabs, tr("Tuning"));
        xdriveSegmentBytesSB = new QSpinBox();
        xdriveFlushIntervalMsSB = new QSpinBox();
        xdrivePollIntervalMsSB = new QSpinBox();
        xdriveMaxPollIntervalMsSB = new QSpinBox();
        xdriveSessionTtlSecondsSB = new QSpinBox();
        xdriveConcurrencySB = new QSpinBox();
        xdriveEagerWindowMsSB = new QSpinBox();
        xdriveHoleTimeoutMsSB = new QSpinBox();
        for (auto spin : { xdriveSegmentBytesSB, xdriveFlushIntervalMsSB, xdrivePollIntervalMsSB, xdriveMaxPollIntervalMsSB,
                           xdriveSessionTtlSecondsSB, xdriveConcurrencySB, xdriveEagerWindowMsSB, xdriveHoleTimeoutMsSB })
            spin->setRange(0, std::numeric_limits<int>::max());
        tuning->addRow(tr("Segment Bytes"), xdriveSegmentBytesSB);
        tuning->addRow(tr("Flush Interval (ms)"), xdriveFlushIntervalMsSB);
        tuning->addRow(tr("Poll Interval (ms)"), xdrivePollIntervalMsSB);
        tuning->addRow(tr("Max Poll Interval (ms)"), xdriveMaxPollIntervalMsSB);
        tuning->addRow(tr("Session TTL (seconds)"), xdriveSessionTtlSecondsSB);
        tuning->addRow(tr("Concurrency"), xdriveConcurrencySB);
        tuning->addRow(tr("Eager Window (ms)"), xdriveEagerWindowMsSB);
        tuning->addRow(tr("Hole Timeout (ms)"), xdriveHoleTimeoutMsSB);

        auto advanced = AddFormTab(tabs, tr("Template"));
        xdriveTemplateTxt = new QPlainTextEdit();
        xdriveTemplateTxt->setPlaceholderText(tr("JSON template object (service=template)"));
        advanced->addRow(xdriveTemplateTxt);

        connect(xdriveRemoteFolderTxt, &QLineEdit::textEdited, this,
                [this](const QString &arg1) { stream.xdriveSettings.remoteFolder = arg1; });
        connect(xdriveServiceTxt, &QComboBox::currentTextChanged, this,
                [this](const QString &arg1) { stream.xdriveSettings.service = arg1; });
        connect(xdriveSecretsTxt, &QPlainTextEdit::textChanged, this,
                [this]() { stream.xdriveSettings.secrets = SplitLines(xdriveSecretsTxt->toPlainText()); });
        connect(xdriveSegmentBytesSB, QOverload<int>::of(&QSpinBox::valueChanged), this,
                [this](int arg1) { stream.xdriveSettings.segmentBytes = arg1; });
        connect(xdriveFlushIntervalMsSB, QOverload<int>::of(&QSpinBox::valueChanged), this,
                [this](int arg1) { stream.xdriveSettings.flushIntervalMs = arg1; });
        connect(xdrivePollIntervalMsSB, QOverload<int>::of(&QSpinBox::valueChanged), this,
                [this](int arg1) { stream.xdriveSettings.pollIntervalMs = arg1; });
        connect(xdriveMaxPollIntervalMsSB, QOverload<int>::of(&QSpinBox::valueChanged), this,
                [this](int arg1) { stream.xdriveSettings.maxPollIntervalMs = arg1; });
        connect(xdriveSessionTtlSecondsSB, QOverload<int>::of(&QSpinBox::valueChanged), this,
                [this](int arg1) { stream.xdriveSettings.sessionTtlSeconds = arg1; });
        connect(xdriveConcurrencySB, QOverload<int>::of(&QSpinBox::valueChanged), this,
                [this](int arg1) { stream.xdriveSettings.concurrency = arg1; });
        connect(xdriveEagerWindowMsSB, QOverload<int>::of(&QSpinBox::valueChanged), this,
                [this](int arg1) { stream.xdriveSettings.eagerWindowMs = arg1; });
        connect(xdriveHoleTimeoutMsSB, QOverload<int>::of(&QSpinBox::valueChanged), this,
                [this](int arg1) { stream.xdriveSettings.holeTimeoutMs = arg1; });
        connect(xdriveTemplateTxt, &QPlainTextEdit::textChanged, this, [this]() {
            const auto value = JsonObjectFromText(xdriveTemplateTxt->toPlainText());
            if (value.has_value())
                stream.xdriveSettings.templateConfig = *value;
        });
    }

    // REALITY (Xray-core).
    {
        realityPublicKeyTxt = new QLineEdit();
        realityShortIdTxt = new QLineEdit();
        realitySpiderXTxt = new QLineEdit();
        realityFingerprintTxt = new QLineEdit();
        realityPrivateKeyTxt = new QLineEdit();
        realityTargetTxt = new QLineEdit();
        formLayout->addRow(tr("REALITY Public Key"), realityPublicKeyTxt);
        formLayout->addRow(tr("REALITY Short ID"), realityShortIdTxt);
        formLayout->addRow(tr("REALITY SpiderX"), realitySpiderXTxt);
        formLayout->addRow(tr("REALITY Fingerprint"), realityFingerprintTxt);
        formLayout->addRow(tr("REALITY Private Key (server)"), realityPrivateKeyTxt);
        formLayout->addRow(tr("REALITY Target (server)"), realityTargetTxt);

        auto realityServerGroup = new QGroupBox(tr("REALITY Server Options"), this);
        auto realityServerLayout = new QFormLayout(realityServerGroup);
        realityMasterKeyLogTxt = new QLineEdit();
        realityShowCB = new QCheckBox(tr("Show REALITY diagnostics"));
        realityDestTxt = new QLineEdit();
        realityTypeTxt = new QLineEdit();
        realityXverSB = new QSpinBox();
        realityXverSB->setRange(0, 2);
        realityServerNamesTxt = new QPlainTextEdit();
        realityServerNamesTxt->setPlaceholderText(tr("One server name per line"));
        realityMinClientVerTxt = new QLineEdit();
        realityMaxClientVerTxt = new QLineEdit();
        realityMaxTimeDiffSB = new QSpinBox();
        realityMaxTimeDiffSB->setRange(0, std::numeric_limits<int>::max());
        realityShortIdsTxt = new QPlainTextEdit();
        realityShortIdsTxt->setPlaceholderText(tr("One short ID per line"));
        realityMldsa65SeedTxt = new QLineEdit();
        realityLimitUploadAfterTxt = new QLineEdit();
        realityLimitUploadBytesTxt = new QLineEdit();
        realityLimitUploadBurstTxt = new QLineEdit();
        realityLimitDownloadAfterTxt = new QLineEdit();
        realityLimitDownloadBytesTxt = new QLineEdit();
        realityLimitDownloadBurstTxt = new QLineEdit();
        realityServerLayout->addRow(tr("Master Key Log"), realityMasterKeyLogTxt);
        realityServerLayout->addRow(realityShowCB);
        realityServerLayout->addRow(tr("Dest"), realityDestTxt);
        realityServerLayout->addRow(tr("Type"), realityTypeTxt);
        realityServerLayout->addRow(tr("Xver"), realityXverSB);
        realityServerLayout->addRow(tr("Server Names"), realityServerNamesTxt);
        realityServerLayout->addRow(tr("Min Client Version"), realityMinClientVerTxt);
        realityServerLayout->addRow(tr("Max Client Version"), realityMaxClientVerTxt);
        realityServerLayout->addRow(tr("Max Time Diff"), realityMaxTimeDiffSB);
        realityServerLayout->addRow(tr("Short IDs"), realityShortIdsTxt);
        realityServerLayout->addRow(tr("ML-DSA-65 Seed"), realityMldsa65SeedTxt);
        realityServerLayout->addRow(tr("Limit Fallback Upload After Bytes"), realityLimitUploadAfterTxt);
        realityServerLayout->addRow(tr("Limit Fallback Upload Bytes/Sec"), realityLimitUploadBytesTxt);
        realityServerLayout->addRow(tr("Limit Fallback Upload Burst Bytes/Sec"), realityLimitUploadBurstTxt);
        realityServerLayout->addRow(tr("Limit Fallback Download After Bytes"), realityLimitDownloadAfterTxt);
        realityServerLayout->addRow(tr("Limit Fallback Download Bytes/Sec"), realityLimitDownloadBytesTxt);
        realityServerLayout->addRow(tr("Limit Fallback Download Burst Bytes/Sec"), realityLimitDownloadBurstTxt);
        formLayout->addRow(realityServerGroup);

        connect(realityPublicKeyTxt, &QLineEdit::textEdited, this, [this](const QString &arg1) {
            stream.realitySettings.publicKey = arg1;
            stream.realitySettings.password = arg1;
        });
        connect(realityShortIdTxt, &QLineEdit::textEdited, this, [this](const QString &arg1) { stream.realitySettings.shortId = arg1; });
        connect(realitySpiderXTxt, &QLineEdit::textEdited, this, [this](const QString &arg1) { stream.realitySettings.spiderX = arg1; });
        connect(realityFingerprintTxt, &QLineEdit::textEdited, this, [this](const QString &arg1) { stream.realitySettings.fingerprint = arg1; });
        connect(realityPrivateKeyTxt, &QLineEdit::textEdited, this, [this](const QString &arg1) { stream.realitySettings.privateKey = arg1; });
        connect(realityTargetTxt, &QLineEdit::textEdited, this, [this](const QString &arg1) { stream.realitySettings.target = arg1; });
        connect(realityMasterKeyLogTxt, &QLineEdit::textEdited, this,
                [this](const QString &arg1) { stream.realitySettings.masterKeyLog = arg1; });
        connect(realityShowCB, &QCheckBox::stateChanged, this, [this](int arg1) { stream.realitySettings.show = arg1 == Qt::Checked; });
        connect(realityDestTxt, &QLineEdit::textEdited, this, [this](const QString &arg1) { stream.realitySettings.dest = arg1; });
        connect(realityTypeTxt, &QLineEdit::textEdited, this, [this](const QString &arg1) { stream.realitySettings.type = arg1; });
        connect(realityXverSB, QOverload<int>::of(&QSpinBox::valueChanged), this,
                [this](int arg1) { stream.realitySettings.xver = arg1; });
        connect(realityServerNamesTxt, &QPlainTextEdit::textChanged, this,
                [this]() { stream.realitySettings.serverNames = SplitLines(realityServerNamesTxt->toPlainText()); });
        connect(realityMinClientVerTxt, &QLineEdit::textEdited, this,
                [this](const QString &arg1) { stream.realitySettings.minClientVer = arg1; });
        connect(realityMaxClientVerTxt, &QLineEdit::textEdited, this,
                [this](const QString &arg1) { stream.realitySettings.maxClientVer = arg1; });
        connect(realityMaxTimeDiffSB, QOverload<int>::of(&QSpinBox::valueChanged), this,
                [this](int arg1) { stream.realitySettings.maxTimeDiff = arg1; });
        connect(realityShortIdsTxt, &QPlainTextEdit::textChanged, this,
                [this]() { stream.realitySettings.shortIds = SplitLines(realityShortIdsTxt->toPlainText()); });
        connect(realityMldsa65SeedTxt, &QLineEdit::textEdited, this,
                [this](const QString &arg1) { stream.realitySettings.mldsa65Seed = arg1; });
        connect(realityLimitUploadAfterTxt, &QLineEdit::textEdited, this,
                [this](const QString &arg1) { stream.realitySettings.limitFallbackUpload.afterBytes = arg1.toLongLong(); });
        connect(realityLimitUploadBytesTxt, &QLineEdit::textEdited, this,
                [this](const QString &arg1) { stream.realitySettings.limitFallbackUpload.bytesPerSec = arg1.toLongLong(); });
        connect(realityLimitUploadBurstTxt, &QLineEdit::textEdited, this,
                [this](const QString &arg1) { stream.realitySettings.limitFallbackUpload.burstBytesPerSec = arg1.toLongLong(); });
        connect(realityLimitDownloadAfterTxt, &QLineEdit::textEdited, this,
                [this](const QString &arg1) { stream.realitySettings.limitFallbackDownload.afterBytes = arg1.toLongLong(); });
        connect(realityLimitDownloadBytesTxt, &QLineEdit::textEdited, this,
                [this](const QString &arg1) { stream.realitySettings.limitFallbackDownload.bytesPerSec = arg1.toLongLong(); });
        connect(realityLimitDownloadBurstTxt, &QLineEdit::textEdited, this,
                [this](const QString &arg1) { stream.realitySettings.limitFallbackDownload.burstBytesPerSec = arg1.toLongLong(); });
    }

    // Additional gRPC options.
    {
        grpcAuthorityTxt = new QLineEdit();
        formLayout_6->addRow(tr("Authority"), grpcAuthorityTxt);
        connect(grpcAuthorityTxt, &QLineEdit::textEdited, this, [this](const QString &arg1) { stream.grpcSettings.authority = arg1; });
    }

    // Additional mKCP options.
    {
        kcpCwndMultiplierSB = new QSpinBox();
        kcpCwndMultiplierSB->setRange(0, 1000);
        kcpMaxSendingWindowSB = new QSpinBox();
        kcpMaxSendingWindowSB->setRange(0, 1 << 24);
        formLayout_5->addRow(tr("Congestion Window Multiplier"), kcpCwndMultiplierSB);
        formLayout_5->addRow(tr("Max Sending Window"), kcpMaxSendingWindowSB);
        connect(kcpCwndMultiplierSB, QOverload<int>::of(&QSpinBox::valueChanged), this,
                [this](int arg1) { stream.kcpSettings.cwndMultiplier = arg1; });
        connect(kcpMaxSendingWindowSB, QOverload<int>::of(&QSpinBox::valueChanged), this,
                [this](int arg1) { stream.kcpSettings.maxSendingWindow = arg1; });
    }

    // Additional socket options.
    {
        sockoptTcpMptcpCB = new QCheckBox(tr("TCP MPTCP"));
        sockoptV6OnlyCB = new QCheckBox(tr("IPv6 only"));
        sockoptDomainStrategyCB = new QComboBox();
        sockoptDomainStrategyCB->addItems({ "", "AsIs", "UseIP", "UseIPv4", "UseIPv6", "UseIPv4v6", "UseIPv6v4", "ForceIP", "ForceIPv4",
                                           "ForceIPv6", "ForceIPv4v6", "ForceIPv6v4" });
        sockoptDialerProxyTxt = new QLineEdit();
        sockoptTcpCongestionTxt = new QLineEdit();
        sockoptInterfaceTxt = new QLineEdit();
        sockoptTcpUserTimeoutSB = new QSpinBox();
        sockoptTcpUserTimeoutSB->setRange(0, 1 << 30);
        formLayout_4->addRow(tr("TCP MPTCP"), sockoptTcpMptcpCB);
        formLayout_4->addRow(tr("IPv6 only"), sockoptV6OnlyCB);
        formLayout_4->addRow(tr("Domain Strategy"), sockoptDomainStrategyCB);
        formLayout_4->addRow(tr("Dialer Proxy"), sockoptDialerProxyTxt);
        formLayout_4->addRow(tr("TCP Congestion"), sockoptTcpCongestionTxt);
        formLayout_4->addRow(tr("Bind Interface"), sockoptInterfaceTxt);
        formLayout_4->addRow(tr("TCP User Timeout"), sockoptTcpUserTimeoutSB);
        connect(sockoptTcpMptcpCB, &QCheckBox::stateChanged, this, [this](int arg1) { stream.sockopt.tcpMptcp = arg1 == Qt::Checked; });
        connect(sockoptV6OnlyCB, &QCheckBox::stateChanged, this, [this](int arg1) { stream.sockopt.v6only = arg1 == Qt::Checked; });
        connect(sockoptDomainStrategyCB, &QComboBox::currentTextChanged, this,
                [this](const QString &arg1) { stream.sockopt.domainStrategy = arg1; });
        connect(sockoptDialerProxyTxt, &QLineEdit::textEdited, this, [this](const QString &arg1) { stream.sockopt.dialerProxy = arg1; });
        connect(sockoptTcpCongestionTxt, &QLineEdit::textEdited, this, [this](const QString &arg1) { stream.sockopt.tcpCongestion = arg1; });
        connect(sockoptInterfaceTxt, &QLineEdit::textEdited, this, [this](const QString &arg1) { stream.sockopt.interface = arg1; });
        connect(sockoptTcpUserTimeoutSB, QOverload<int>::of(&QSpinBox::valueChanged), this,
                [this](int arg1) { stream.sockopt.tcpUserTimeout = arg1; });
    }

    if (securityTypeCB->findText("Reality") < 0)
        securityTypeCB->addItem("Reality");

    // A raw JSON escape hatch for all newly added core options.  This keeps
    // Qv2ray useful even when a core adds another field before a dedicated
    // widget exists.
    auto advancedPage = new QWidget(tabWidget);
    auto advancedLayout = new QVBoxLayout(advancedPage);
    advancedStreamJsonEdit = new QPlainTextEdit(advancedPage);
    advancedStreamJsonEdit->setFont(QFont("Monospace"));
    advancedStreamJsonEdit->setLineWrapMode(QPlainTextEdit::NoWrap);
    auto applyButton = new QPushButton(tr("Apply JSON"), advancedPage);
    advancedLayout->addWidget(new QLabel(tr("Full streamSettings JSON (including Xray-only fields):"), advancedPage));
    advancedLayout->addWidget(advancedStreamJsonEdit);
    advancedLayout->addWidget(applyButton);
    tabWidget->addTab(advancedPage, tr("Advanced JSON"));
    connect(applyButton, &QPushButton::clicked, this, [this]() {
        const auto text = advancedStreamJsonEdit->toPlainText();
        const auto error = VerifyJsonString(text);
        if (!error.isEmpty())
        {
            QvMessageBoxWarn(this, tr("Invalid JSON"), error);
            return;
        }
        const auto json = JsonFromString(text);
        stream = StreamSettingsObject::fromJson(json);
        SetStreamObject(stream);
    });
}

QvMessageBusSlotImpl(StreamSettingsWidget)
{
    switch (msg)
    {
        MBRetranslateDefaultImpl;
        case UPDATE_COLORSCHEME:
        case HIDE_WINDOWS:
        case SHOW_WINDOWS: break;
    }
}

StreamSettingsObject StreamSettingsWidget::GetStreamSettings() const
{
    return stream;
}

void StreamSettingsWidget::SetStreamObject(const StreamSettingsObject &sso)
{
    stream = sso;
    openCertEditorBtn->setEnabled(true);
    openCertEditorBtn->setToolTip(tr("Edit TLS certificates"));
    // Always emit the portable "network" spelling.
    stream.method.clear();
    // Normalize names removed/renamed by modern cores so that the combo box
    // can select the right page.
    if (stream.network == "raw")
        stream.network = "tcp";
    else if (stream.network == "websocket")
        stream.network = "ws";
    else if (stream.network == "mkcp")
        stream.network = "kcp";
    else if (stream.network == "gun")
        stream.network = "grpc";
    else if (stream.network == "ds")
        stream.network = "domainsocket";
    else if (stream.network == "h2")
        stream.network = "http";
    else if (stream.network == "splithttp")
        stream.network = "xhttp";
    else if (stream.network == "hy2")
        stream.network = "hysteria2";

    if (stream.network == "hysteria" && stream.hysteriaSettings.version == 0)
        stream.hysteriaSettings.version = 2;

    if (stream.security == "xtls")
    {
        // XTLS was removed from both cores.  Migrate to TLS + vision flow.
        stream.security = "tls";
        if (stream.tlsSettings.serverName.isEmpty())
            stream.tlsSettings.serverName = stream.xtlsSettings.serverName;
        if (stream.xtlsSettings.allowInsecure)
            stream.tlsSettings.allowInsecure = stream.tlsSettings.allowInsecure || stream.xtlsSettings.allowInsecure;
        if (stream.xtlsSettings.enableSessionResumption)
            stream.tlsSettings.enableSessionResumption = true;
        if (stream.xtlsSettings.disableSystemRoot)
            stream.tlsSettings.disableSystemRoot = true;
        if (stream.tlsSettings.alpn.isEmpty())
            stream.tlsSettings.alpn = stream.xtlsSettings.alpn;
        if (stream.tlsSettings.certificates.isEmpty())
            stream.tlsSettings.certificates = stream.xtlsSettings.certificates;
        if (stream.tlsSettings.pinnedPeerCertificateChainSha256.isEmpty())
            stream.tlsSettings.pinnedPeerCertificateChainSha256 = stream.xtlsSettings.pinnedPeerCertificateChainSha256;
        stream.xtlsSettings = {};
    }

    transportCombo->setCurrentText(stream.network);
    // TLS / REALITY
    {
        const static QMap<QString, int> securityIndexMap{ { "none", 0 }, { "tls", 1 }, { "xtls", 2 }, { "reality", 3 } };
        if (securityIndexMap.contains(stream.security))
            securityTypeCB->setCurrentIndex(securityIndexMap[stream.security]);
        else
            LOG("Unsupported Security Type:", stream.security);

#define tls_process(prefix)                                                                                                                          \
    {                                                                                                                                                \
        serverNameTxt->setText(stream.prefix##Settings.serverName);                                                                                  \
        allowInsecureCB->setChecked(stream.prefix##Settings.allowInsecure);                                                                          \
        enableSessionResumptionCB->setChecked(stream.prefix##Settings.enableSessionResumption);                                                      \
        disableSystemRoot->setChecked(stream.prefix##Settings.disableSystemRoot);                                                                    \
        alpnTxt->setText(stream.prefix##Settings.alpn.join("|"));                                                                                    \
    }

        if (stream.security == "reality")
        {
            serverNameTxt->setText(stream.realitySettings.serverName);
            allowInsecureCB->setChecked(false);
            enableSessionResumptionCB->setChecked(false);
            disableSystemRoot->setChecked(false);
            alpnTxt->clear();
        }
        else
        {
            tls_process(tls);
        }
    }
    // TCP
    {
        tcpHeaderTypeCB->setCurrentText(stream.tcpSettings.header.type);
        tcpRequestTxt->setPlainText(JsonToString(stream.tcpSettings.header.request.toJson()));
        tcpRespTxt->setPlainText(JsonToString(stream.tcpSettings.header.response.toJson()));
    }
    // HTTP
    {
        httpHostTxt->setPlainText(stream.httpSettings.host.join(NEWLINE));
        httpPathTxt->setText(stream.httpSettings.path);
        httpMethodCB->setCurrentText(stream.httpSettings.method);
        httpHeadersTxt->setPlainText(JsonToString(stream.httpSettings.toJson()["headers"].toObject()));
    }
    // WS
    {
        wsPathTxt->setText(stream.wsSettings.path);
        QString wsHeaders;
        auto headers = stream.wsSettings.headers;
        // Xray may store Host in the independent "host" field.
        if (!stream.wsSettings.host.isEmpty() && !headers.contains("Host"))
            headers["Host"] = stream.wsSettings.host;
        for (const auto &[key, value] : headers.toStdMap())
        {
            wsHeaders = wsHeaders % key % "|" % value % NEWLINE;
        }
        wsHeadersTxt->setPlainText(wsHeaders);
        wsEarlyDataSB->setValue(stream.wsSettings.maxEarlyData);
        wsBrowserForwardCB->setChecked(stream.wsSettings.useBrowserForwarding);
        wsEarlyDataHeaderNameCB->setCurrentText(stream.wsSettings.earlyDataHeaderName);
    }
    // mKCP
    {
        kcpMTU->setValue(stream.kcpSettings.mtu);
        kcpTTI->setValue(stream.kcpSettings.tti);
        kcpHeaderType->setCurrentText(stream.kcpSettings.header.type);
        kcpCongestionCB->setChecked(stream.kcpSettings.congestion);
        kcpReadBufferSB->setValue(stream.kcpSettings.readBufferSize);
        kcpUploadCapacSB->setValue(stream.kcpSettings.uplinkCapacity);
        kcpDownCapacitySB->setValue(stream.kcpSettings.downlinkCapacity);
        kcpWriteBufferSB->setValue(stream.kcpSettings.writeBufferSize);
        kcpSeedTxt->setText(stream.kcpSettings.seed);
    }
    // DS
    {
        dsPathTxt->setText(stream.dsSettings.path);
    }
    // QUIC
    {
        quicKeyTxt->setText(stream.quicSettings.key);
        quicSecurityCB->setCurrentText(stream.quicSettings.security);
        quicHeaderTypeCB->setCurrentText(stream.quicSettings.header.type);
    }
    // XHTTP
    if (xhttpHostTxt)
    {
        const auto &xhttp = stream.xhttpSettings;
        xhttpHostTxt->setText(xhttp.host);
        xhttpPathTxt->setText(xhttp.path);
        xhttpModeCB->setCurrentText(xhttp.mode);
        xhttpHeadersTxt->setPlainText(HeadersToText(xhttp.headers));
        xhttpXPaddingBytesTxt->setText(RangeToText(xhttp.xPaddingBytes));
        xhttpXPaddingObfsModeCB->setChecked(xhttp.xPaddingObfsMode);
        xhttpXPaddingKeyTxt->setText(xhttp.xPaddingKey);
        xhttpXPaddingHeaderTxt->setText(xhttp.xPaddingHeader);
        xhttpXPaddingPlacementCB->setCurrentText(xhttp.xPaddingPlacement);
        xhttpXPaddingMethodCB->setCurrentText(xhttp.xPaddingMethod);
        xhttpUplinkHTTPMethodCB->setCurrentText(xhttp.uplinkHTTPMethod);
        xhttpSessionIDPlacementCB->setCurrentText(xhttp.sessionIDPlacement);
        xhttpSessionIDKeyTxt->setText(xhttp.sessionIDKey);
        xhttpSessionIDTableTxt->setText(xhttp.sessionIDTable);
        xhttpSessionIDLengthTxt->setText(RangeToText(xhttp.sessionIDLength));
        xhttpSeqPlacementCB->setCurrentText(xhttp.seqPlacement);
        xhttpSeqKeyTxt->setText(xhttp.seqKey);
        xhttpUplinkDataPlacementCB->setCurrentText(xhttp.uplinkDataPlacement);
        xhttpUplinkDataKeyTxt->setText(xhttp.uplinkDataKey);
        xhttpUplinkChunkSizeTxt->setText(RangeToText(xhttp.uplinkChunkSize));
        xhttpNoGRPCHeaderCB->setChecked(xhttp.noGRPCHeader);
        xhttpNoSSEHeaderCB->setChecked(xhttp.noSSEHeader);
        xhttpScMaxEachPostBytesTxt->setText(RangeToText(xhttp.scMaxEachPostBytes));
        xhttpScMinPostsIntervalMsTxt->setText(RangeToText(xhttp.scMinPostsIntervalMs));
        xhttpScMaxBufferedPostsTxt->setText(QString::number(xhttp.scMaxBufferedPosts));
        xhttpScStreamUpServerSecsTxt->setText(RangeToText(xhttp.scStreamUpServerSecs));
        xhttpServerMaxHeaderBytesSB->setValue(xhttp.serverMaxHeaderBytes);
        xhttpXmux.maxConcurrency->setText(RangeToText(xhttp.xmux.maxConcurrency));
        xhttpXmux.maxConnections->setText(RangeToText(xhttp.xmux.maxConnections));
        xhttpXmux.cMaxReuseTimes->setText(RangeToText(xhttp.xmux.cMaxReuseTimes));
        xhttpXmux.hMaxRequestTimes->setText(RangeToText(xhttp.xmux.hMaxRequestTimes));
        xhttpXmux.hMaxReusableSecs->setText(RangeToText(xhttp.xmux.hMaxReusableSecs));
        xhttpXmux.hKeepAlivePeriod->setValue(static_cast<int>(std::min<qint64>(xhttp.xmux.hKeepAlivePeriod, std::numeric_limits<int>::max())));
        xhttpDownloadSettingsTxt->setPlainText(JsonObjectToText(xhttp.downloadSettings));
        xhttpExtraTxt->setPlainText(JsonObjectToText(xhttp.extra));
    }
    // HTTPUpgrade
    if (httpupgradeHostTxt)
    {
        httpupgradeHostTxt->setText(stream.httpupgradeSettings.host);
        httpupgradePathTxt->setText(stream.httpupgradeSettings.path);
        httpupgradeHeadersTxt->setPlainText(HeadersToText(stream.httpupgradeSettings.headers));
        httpupgradeAcceptProxyProtocolCB->setChecked(stream.httpupgradeSettings.acceptProxyProtocol);
    }
    // Xray hysteria transport
    if (hysteriaVersionSB)
    {
        const auto &masq = stream.hysteriaSettings.masquerade;
        hysteriaVersionSB->setValue(stream.hysteriaSettings.version);
        hysteriaAuthTxt->setText(stream.hysteriaSettings.auth);
        hysteriaUdpIdleTimeoutSB->setValue(static_cast<int>(stream.hysteriaSettings.udpIdleTimeout));
        hysteriaMasqTypeCB->setCurrentText(masq.type);
        hysteriaMasqDirTxt->setText(masq.dir);
        hysteriaMasqUrlTxt->setText(masq.url);
        hysteriaMasqRewriteHostCB->setChecked(masq.rewriteHost);
        hysteriaMasqXForwardedCB->setChecked(masq.xForwarded);
        hysteriaMasqInsecureCB->setChecked(masq.insecure);
        hysteriaMasqContentTxt->setPlainText(masq.content);
        hysteriaMasqHeadersTxt->setPlainText(HeadersToText(masq.headers));
        hysteriaMasqStatusCodeSB->setValue(masq.statusCode);
    }
    // v2ray Hysteria2 transport
    if (hy2PasswordTxt)
    {
        const auto &hy2 = stream.hy2Settings;
        hy2PasswordTxt->setText(hy2.password);
        hy2CongestionTypeCB->setCurrentText(hy2.congestion.type);
        hy2UpMbpsSB->setValue(static_cast<int>(std::min<qint64>(hy2.congestion.up_mbps, std::numeric_limits<int>::max())));
        hy2DownMbpsSB->setValue(static_cast<int>(std::min<qint64>(hy2.congestion.down_mbps, std::numeric_limits<int>::max())));
        hy2UseUdpExtensionCB->setChecked(hy2.use_udp_extension);
        hy2IgnoreClientBandwidthCB->setChecked(hy2.ignore_client_bandwidth);
    }
    // MASQUE
    if (masqueHostTxt)
    {
        const auto &masque = stream.masqueSettings;
        masqueHostTxt->setText(masque.host);
        masquePathTxt->setText(masque.path);
        masqueUserTxt->setText(masque.user);
        masquePassTxt->setText(masque.pass);
        masqueHeadersTxt->setPlainText(HeadersToText(masque.headers));
        masqueWarpPrivateKeyTxt->setText(masque.warp.privateKey);
        masqueWarpPublicKeyTxt->setText(masque.warp.publicKey);
        masqueWarpAddressTxt->setPlainText(masque.warp.address.join(NEWLINE));
        masqueXmux.maxConcurrency->setText(RangeToText(masque.xmux.maxConcurrency));
        masqueXmux.maxConnections->setText(RangeToText(masque.xmux.maxConnections));
        masqueXmux.cMaxReuseTimes->setText(RangeToText(masque.xmux.cMaxReuseTimes));
        masqueXmux.hMaxRequestTimes->setText(RangeToText(masque.xmux.hMaxRequestTimes));
        masqueXmux.hMaxReusableSecs->setText(RangeToText(masque.xmux.hMaxReusableSecs));
        masqueXmux.hKeepAlivePeriod->setValue(static_cast<int>(std::min<qint64>(masque.xmux.hKeepAlivePeriod, std::numeric_limits<int>::max())));
    }
    // XDRIVE
    if (xdriveRemoteFolderTxt)
    {
        const auto &xdrive = stream.xdriveSettings;
        xdriveRemoteFolderTxt->setText(xdrive.remoteFolder);
        xdriveServiceTxt->setCurrentText(xdrive.service);
        xdriveSecretsTxt->setPlainText(xdrive.secrets.join(NEWLINE));
        xdriveSegmentBytesSB->setValue(static_cast<int>(std::min<qint64>(xdrive.segmentBytes, std::numeric_limits<int>::max())));
        xdriveFlushIntervalMsSB->setValue(static_cast<int>(std::min<qint64>(xdrive.flushIntervalMs, std::numeric_limits<int>::max())));
        xdrivePollIntervalMsSB->setValue(static_cast<int>(std::min<qint64>(xdrive.pollIntervalMs, std::numeric_limits<int>::max())));
        xdriveMaxPollIntervalMsSB->setValue(static_cast<int>(std::min<qint64>(xdrive.maxPollIntervalMs, std::numeric_limits<int>::max())));
        xdriveSessionTtlSecondsSB->setValue(static_cast<int>(std::min<qint64>(xdrive.sessionTtlSeconds, std::numeric_limits<int>::max())));
        xdriveConcurrencySB->setValue(static_cast<int>(std::min<qint64>(xdrive.concurrency, std::numeric_limits<int>::max())));
        xdriveEagerWindowMsSB->setValue(static_cast<int>(std::min<qint64>(xdrive.eagerWindowMs, std::numeric_limits<int>::max())));
        xdriveHoleTimeoutMsSB->setValue(static_cast<int>(std::min<qint64>(xdrive.holeTimeoutMs, std::numeric_limits<int>::max())));
        xdriveTemplateTxt->setPlainText(JsonObjectToText(xdrive.templateConfig));
    }
    // REALITY
    if (realityPublicKeyTxt)
    {
        const auto &reality = stream.realitySettings;
        realityPublicKeyTxt->setText(reality.publicKey);
        realityShortIdTxt->setText(reality.shortId);
        realitySpiderXTxt->setText(reality.spiderX);
        realityFingerprintTxt->setText(reality.fingerprint);
        realityPrivateKeyTxt->setText(reality.privateKey);
        realityTargetTxt->setText(reality.target.value.toString());
        realityMasterKeyLogTxt->setText(reality.masterKeyLog);
        realityShowCB->setChecked(reality.show);
        realityDestTxt->setText(reality.dest.value.toString());
        realityTypeTxt->setText(reality.type);
        realityXverSB->setValue(reality.xver);
        realityServerNamesTxt->setPlainText(reality.serverNames.join(NEWLINE));
        realityMinClientVerTxt->setText(reality.minClientVer);
        realityMaxClientVerTxt->setText(reality.maxClientVer);
        realityMaxTimeDiffSB->setValue(static_cast<int>(std::min<qint64>(reality.maxTimeDiff, std::numeric_limits<int>::max())));
        realityShortIdsTxt->setPlainText(reality.shortIds.join(NEWLINE));
        realityMldsa65SeedTxt->setText(reality.mldsa65Seed);
        realityLimitUploadAfterTxt->setText(QString::number(reality.limitFallbackUpload.afterBytes));
        realityLimitUploadBytesTxt->setText(QString::number(reality.limitFallbackUpload.bytesPerSec));
        realityLimitUploadBurstTxt->setText(QString::number(reality.limitFallbackUpload.burstBytesPerSec));
        realityLimitDownloadAfterTxt->setText(QString::number(reality.limitFallbackDownload.afterBytes));
        realityLimitDownloadBytesTxt->setText(QString::number(reality.limitFallbackDownload.bytesPerSec));
        realityLimitDownloadBurstTxt->setText(QString::number(reality.limitFallbackDownload.burstBytesPerSec));
        if (stream.realitySettings.serverName.isEmpty() && !stream.realitySettings.serverNames.isEmpty())
            stream.realitySettings.serverName = stream.realitySettings.serverNames.first();
    }
    // gRPC
    {
        grpcServiceNameTxt->setText(stream.grpcSettings.serviceName);
        grpcModeCB->setCurrentText(stream.grpcSettings.multiMode ? "multi" : "gun");
        if (grpcAuthorityTxt)
            grpcAuthorityTxt->setText(stream.grpcSettings.authority);
    }
    // mKCP
    if (kcpCwndMultiplierSB)
    {
        kcpCwndMultiplierSB->setValue(stream.kcpSettings.cwndMultiplier);
        kcpMaxSendingWindowSB->setValue(stream.kcpSettings.maxSendingWindow);
    }
    // SOCKOPT
    {
        tProxyCB->setCurrentText(stream.sockopt.tproxy);
        tcpFastOpenCB->setChecked(stream.sockopt.tcpFastOpen);
        soMarkSpinBox->setValue(stream.sockopt.mark);
        tcpKeepAliveIntervalSpinBox->setValue(stream.sockopt.tcpKeepAliveInterval);
        if (sockoptTcpMptcpCB)
        {
            sockoptTcpMptcpCB->setChecked(stream.sockopt.tcpMptcp || stream.sockopt.mptcp);
            sockoptV6OnlyCB->setChecked(stream.sockopt.v6only);
            sockoptDomainStrategyCB->setCurrentText(stream.sockopt.domainStrategy);
            sockoptDialerProxyTxt->setText(stream.sockopt.dialerProxy);
            sockoptTcpCongestionTxt->setText(stream.sockopt.tcpCongestion);
            sockoptInterfaceTxt->setText(stream.sockopt.interface);
            sockoptTcpUserTimeoutSB->setValue(stream.sockopt.tcpUserTimeout);
        }
    }
    if (advancedStreamJsonEdit)
        advancedStreamJsonEdit->setPlainText(JsonToString(stream.toJson()));
}

void StreamSettingsWidget::on_httpPathTxt_textEdited(const QString &arg1)
{
    stream.httpSettings.path = arg1;
}

void StreamSettingsWidget::on_httpHostTxt_textChanged()
{
    const auto hosts = httpHostTxt->toPlainText().replace("\r", "").split("\n");
    stream.httpSettings.host.clear();
    for (const auto &host : hosts)
    {
        if (!host.trimmed().isEmpty())
            stream.httpSettings.host.push_back(host.trimmed());
    }
}

void StreamSettingsWidget::on_wsHeadersTxt_textChanged()
{
    const auto headers = SplitLines(wsHeadersTxt->toPlainText());
    stream.wsSettings.headers.clear();
    for (const auto &header : headers)
    {
        if (header.isEmpty())
            continue;

        if (!header.contains("|"))
        {
            LOG("Header missing '|' separator");
            RED(wsHeadersTxt);
            return;
        }

        const auto index = header.indexOf("|");
        auto key = header.left(index);
        auto value = header.right(header.length() - index - 1);
        stream.wsSettings.headers[key] = value;
    }
    stream.wsSettings.host = stream.wsSettings.headers.value("Host", stream.wsSettings.headers.value("host"));
    BLACK(wsHeadersTxt);
}

void StreamSettingsWidget::on_tcpRequestDefBtn_clicked()
{
    tcpRequestTxt->clear();
    tcpRequestTxt->setPlainText(JsonToString(HTTPRequestObject().toJson()));
    stream.tcpSettings.header.request = HTTPRequestObject();
}

void StreamSettingsWidget::on_tcpRespDefBtn_clicked()
{
    tcpRespTxt->clear();
    tcpRespTxt->setPlainText(JsonToString(HTTPResponseObject().toJson()));
    stream.tcpSettings.header.response = HTTPResponseObject();
}

void StreamSettingsWidget::on_soMarkSpinBox_valueChanged(int arg1)
{
    stream.sockopt.mark = arg1;
}

void StreamSettingsWidget::on_tcpFastOpenCB_stateChanged(int arg1)
{
    stream.sockopt.tcpFastOpen = arg1 == Qt::Checked;
}

void StreamSettingsWidget::on_tProxyCB_currentIndexChanged(int arg1)
{
    stream.sockopt.tproxy = tProxyCB->itemText(arg1);
}

void StreamSettingsWidget::on_quicSecurityCB_currentIndexChanged(int arg1)
{
    stream.quicSettings.security = quicSecurityCB->itemText(arg1);
}

void StreamSettingsWidget::on_quicKeyTxt_textEdited(const QString &arg1)
{
    stream.quicSettings.key = arg1;
}

void StreamSettingsWidget::on_quicHeaderTypeCB_currentIndexChanged(int arg1)
{
    stream.quicSettings.header.type = quicHeaderTypeCB->itemText(arg1);
}

void StreamSettingsWidget::on_tcpHeaderTypeCB_currentIndexChanged(int arg1)
{
    stream.tcpSettings.header.type = tcpHeaderTypeCB->itemText(arg1);
}

void StreamSettingsWidget::on_wsPathTxt_textEdited(const QString &arg1)
{
    stream.wsSettings.path = arg1;
}

void StreamSettingsWidget::on_kcpMTU_valueChanged(int arg1)
{
    stream.kcpSettings.mtu = arg1;
}

void StreamSettingsWidget::on_kcpTTI_valueChanged(int arg1)
{
    stream.kcpSettings.tti = arg1;
}

void StreamSettingsWidget::on_kcpUploadCapacSB_valueChanged(int arg1)
{
    stream.kcpSettings.uplinkCapacity = arg1;
}

void StreamSettingsWidget::on_kcpCongestionCB_stateChanged(int arg1)
{
    stream.kcpSettings.congestion = arg1 == Qt::Checked;
}

void StreamSettingsWidget::on_kcpDownCapacitySB_valueChanged(int arg1)
{
    stream.kcpSettings.downlinkCapacity = arg1;
}

void StreamSettingsWidget::on_kcpReadBufferSB_valueChanged(int arg1)
{
    stream.kcpSettings.readBufferSize = arg1;
}

void StreamSettingsWidget::on_kcpWriteBufferSB_valueChanged(int arg1)
{
    stream.kcpSettings.writeBufferSize = arg1;
}

void StreamSettingsWidget::on_kcpHeaderType_currentIndexChanged(int arg1)
{
    stream.kcpSettings.header.type = kcpHeaderType->itemText(arg1);
}

void StreamSettingsWidget::on_kcpSeedTxt_textEdited(const QString &arg1)
{
    stream.kcpSettings.seed = arg1;
}

void StreamSettingsWidget::on_dsPathTxt_textEdited(const QString &arg1)
{
    stream.dsSettings.path = arg1;
}

void StreamSettingsWidget::on_tcpRequestEditBtn_clicked()
{
    JsonEditor w(JsonFromString(tcpRequestTxt->toPlainText()), this);
    auto rJson = w.OpenEditor();
    tcpRequestTxt->setPlainText(JsonToString(rJson));
    auto tcpReqObject = HTTPRequestObject::fromJson(rJson);
    stream.tcpSettings.header.request = tcpReqObject;
}

void StreamSettingsWidget::on_tcpResponseEditBtn_clicked()
{
    JsonEditor w(JsonFromString(tcpRespTxt->toPlainText()), this);
    auto rJson = w.OpenEditor();
    tcpRespTxt->setPlainText(JsonToString(rJson));
    auto tcpRspObject = HTTPResponseObject::fromJson(rJson);
    stream.tcpSettings.header.response = tcpRspObject;
}

void StreamSettingsWidget::on_transportCombo_currentIndexChanged(int arg1)
{
    stream.network = transportCombo->itemText(arg1);
    if (stream.network == "hysteria" && stream.hysteriaSettings.version == 0)
        stream.hysteriaSettings.version = 2;
    v2rayStackView->setCurrentIndex(arg1);
}

void StreamSettingsWidget::on_securityTypeCB_currentIndexChanged(int arg1)
{
    stream.security = securityTypeCB->itemText(arg1).toLower();
}

//
// Dirty hack, since XTLSSettings are the same as TLSSettings (Split them if required in the future)
//
void StreamSettingsWidget::on_serverNameTxt_textEdited(const QString &arg1)
{
    stream.tlsSettings.serverName = arg1.trimmed();
    stream.xtlsSettings.serverName = arg1.trimmed();
    stream.realitySettings.serverName = arg1.trimmed();
}

void StreamSettingsWidget::on_allowInsecureCB_stateChanged(int arg1)
{
    stream.tlsSettings.allowInsecure = arg1 == Qt::Checked;
    stream.xtlsSettings.allowInsecure = arg1 == Qt::Checked;
}

void StreamSettingsWidget::on_enableSessionResumptionCB_stateChanged(int arg1)
{
    stream.tlsSettings.enableSessionResumption = arg1 == Qt::Checked;
    stream.xtlsSettings.enableSessionResumption = arg1 == Qt::Checked;
}

void StreamSettingsWidget::on_alpnTxt_textEdited(const QString &arg1)
{
#if QT_VERSION >= QT_VERSION_CHECK(5, 14, 0)
    stream.tlsSettings.alpn = arg1.split('|', Qt::SplitBehaviorFlags::SkipEmptyParts);
    stream.xtlsSettings.alpn = arg1.split('|', Qt::SplitBehaviorFlags::SkipEmptyParts);
#else
    stream.tlsSettings.alpn = arg1.split('|', QString::SkipEmptyParts);
    stream.xtlsSettings.alpn = arg1.split('|', QString::SkipEmptyParts);
#endif
}

void StreamSettingsWidget::on_disableSystemRoot_stateChanged(int arg1)
{
    stream.tlsSettings.disableSystemRoot = arg1;
    stream.xtlsSettings.disableSystemRoot = arg1;
}

void StreamSettingsWidget::on_openCertEditorBtn_clicked()
{
    auto certificates = stream.tlsSettings.certificates;
    if (EditCertificates(this, certificates))
    {
        stream.tlsSettings.certificates = certificates;
        if (advancedStreamJsonEdit)
            advancedStreamJsonEdit->setPlainText(JsonToString(stream.toJson()));
    }
}

void StreamSettingsWidget::on_grpcServiceNameTxt_textEdited(const QString &arg1)
{
    stream.grpcSettings.serviceName = arg1;
}

void StreamSettingsWidget::on_grpcModeCB_currentIndexChanged(int arg1)
{
    stream.grpcSettings.multiMode = grpcModeCB->itemText(arg1).toLower() == "multi";
}

void StreamSettingsWidget::on_wsEarlyDataSB_valueChanged(int arg1)
{
    stream.wsSettings.maxEarlyData = arg1;
}

void StreamSettingsWidget::on_wsBrowserForwardCB_stateChanged(int arg1)
{
    stream.wsSettings.useBrowserForwarding = arg1 == Qt::Checked;
}

void StreamSettingsWidget::on_pinnedPeerCertificateChainSha256Btn_clicked()
{
    ChainSha256Editor ed(this, stream.tlsSettings.pinnedPeerCertificateChainSha256);
    if (ed.exec() == QDialog::Accepted)
    {
        stream.tlsSettings.pinnedPeerCertificateChainSha256 = QList<QString>(ed);
    }
}

void StreamSettingsWidget::on_wsEarlyDataHeaderNameCB_currentIndexChanged(int arg1)
{
    stream.wsSettings.earlyDataHeaderName = wsEarlyDataHeaderNameCB->itemText(arg1);
}

void StreamSettingsWidget::on_httpMethodCB_currentTextChanged(const QString &arg1)
{
    stream.httpSettings.method = arg1;
}

void StreamSettingsWidget::on_tcpKeepAliveIntervalSpinBox_valueChanged(int arg1)
{
    stream.sockopt.tcpKeepAliveInterval = arg1;
}

void StreamSettingsWidget::on_httpHeadersDefBtn_clicked()
{
    httpHeadersTxt->clear();
    httpHeadersTxt->setPlainText(JsonToString(HttpObject().toJson()["headers"].toObject()));
    stream.httpSettings.headers = HttpObject().headers;
}

void StreamSettingsWidget::on_httpHeadersEditBtn_clicked()
{
    JsonEditor w(JsonFromString(httpHeadersTxt->toPlainText()), this);
    auto rJson = w.OpenEditor();
    httpHeadersTxt->setPlainText(JsonToString(rJson));

    auto json = HttpObject().toJson();
    json["headers"] = rJson;
    stream.httpSettings.headers = HttpObject::fromJson(json).headers;
}
