#pragma once
#include "tiktok-native/hosted_signing_service.hpp"
#include <QWidget>
#include <QTimer>
#include <QStringList>
class QProgressBar;
class RapidApiQuotaWidget : public QWidget {
public:
    explicit RapidApiQuotaWidget(QWidget* parent = nullptr);
    void SetApiKey(const QString& key);
    // Pool mode: show the quota of the currently active key (primary or one
    // of the backups) and list every key's state in the tooltip.
    void SetPoolKeys(const QString& primary, const QStringList& backups, int threshold);
private:
    void Refresh();
    HostedSigningServiceConfig service_;
    QStringList poolBackups_;
    int poolThreshold_ = 200;
    QProgressBar* bar_;
    QTimer timer_;
};
