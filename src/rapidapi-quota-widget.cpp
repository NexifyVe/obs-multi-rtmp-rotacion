#include "rapidapi-quota-widget.h"
#include "tiktok-native/rapidapi_quota.hpp"
#include "tiktok-native/rapidapi_key_pool.hpp"
#include <obs-module.h>
#include <QDateTime>
#include <QFormLayout>
#include <QLocale>
#include <QProgressBar>
#include <algorithm>

RapidApiQuotaWidget::RapidApiQuotaWidget(QWidget* parent) : QWidget(parent)
{
    setObjectName("rapidApiQuota");
    auto layout = new QFormLayout(this);
    layout->setContentsMargins(0, 0, 0, 0);
    layout->setFieldGrowthPolicy(QFormLayout::AllNonFixedFieldsGrow);
    bar_ = new QProgressBar(this);
    bar_->setObjectName("rapidApiQuotaBar");
    bar_->setAccessibleName(obs_module_text("Quota.Label"));
    bar_->setMinimumHeight(24);
    bar_->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
    bar_->setTextVisible(true);
    layout->addRow(obs_module_text("Quota.Label"), bar_);
    QObject::connect(&timer_, &QTimer::timeout, this, [this] { if (isVisible()) Refresh(); });
    timer_.start(1000);
    Refresh();
}

void RapidApiQuotaWidget::SetApiKey(const QString& key)
{
    service_.api_key = key.trimmed();
    Refresh();
}

void RapidApiQuotaWidget::SetPoolKeys(const QString& primary, const QStringList& backups, int threshold)
{
    service_.api_key = primary.trimmed();
    poolBackups_ = backups;
    poolThreshold_ = threshold;
    Refresh();
}

void RapidApiQuotaWidget::Refresh()
{
    const QLocale locale;
    bool low = false;
    bool pool = false;
    int active_index = 0, key_count = 1;
    HostedSigningServiceConfig active_service = service_;
    if (!poolBackups_.isEmpty() && !service_.api_key.isEmpty()) {
        // Pool mode: report the key the next signing call will actually use.
        pool = true;
        const auto snapshot = RapidApiKeyPoolStatus(service_);
        const QString active = ResolveRapidApiKey(service_);
        active_service.api_key = active;
        active_index = snapshot.active_index;
        key_count = snapshot.keys.isEmpty() ? 1 : snapshot.keys.size();
    }
    const auto quota = ReadRapidApiQuota(active_service);
    bar_->setRange(0, 1000);
    if (quota.limit > 0 && quota.remaining >= 0) {
        const auto remaining = std::clamp(quota.remaining, qint64(0), quota.limit);
        const double fraction = double(remaining) / double(quota.limit);
        bar_->setValue(int(fraction * 1000));
        bar_->setFormat(QString::fromUtf8(obs_module_text("Quota.RemainingOf")).arg(locale.toString(remaining), locale.toString(quota.limit)));
        low = fraction <= 0.1;
    } else if (quota.remaining >= 0) {
        bar_->setValue(quota.remaining > 0 ? 1000 : 0);
        bar_->setFormat(QString::fromUtf8(obs_module_text("Quota.Remaining")).arg(locale.toString(quota.remaining)));
        low = quota.remaining == 0;
    } else {
        bar_->setValue(0);
        bar_->setFormat(obs_module_text("Account.Unknown"));
    }
    if (pool) {
        const QString separator = QString(QChar(0x00B7));
        bar_->setFormat(bar_->format() + QStringLiteral(" ") + separator + QStringLiteral(" ") +
            QString::fromUtf8(obs_module_text("Quota.PoolKey")).arg(active_index > 0 ? active_index : 1).arg(key_count));
        low = low || active_index > 1;
    }
    const QString style = QStringLiteral("QProgressBar { border: 1px solid palette(mid); border-radius: 4px; background: palette(button); text-align: center; color: palette(text); } QProgressBar::chunk { border-radius: 3px; background: %1; }")
        .arg(low ? "#d9534f" : "palette(highlight)");
    if (bar_->styleSheet() != style) bar_->setStyleSheet(style);
    QStringList tips{QString::fromUtf8(obs_module_text("Quota.Passive"))};
    if (quota.has_calendar_reset()) tips << QString::fromUtf8(obs_module_text("Quota.Reset")).arg(
        locale.toString(QDateTime::fromSecsSinceEpoch(quota.reset_epoch_seconds).toLocalTime(), QLocale::ShortFormat));
    if (quota.observed_epoch_seconds > 0) tips << QString::fromUtf8(obs_module_text("Quota.Updated")).arg(
        locale.toString(QDateTime::fromSecsSinceEpoch(quota.observed_epoch_seconds).toLocalTime(), QLocale::ShortFormat));
    else tips << QString::fromUtf8(obs_module_text("Quota.NoUsage"));
    if (pool) {
        const auto snapshot = RapidApiKeyPoolStatus(service_);
        for (const auto& key : snapshot.keys) {
            QString state;
            if (key.invalid) state = obs_module_text("Quota.PoolInvalid");
            else if (key.parked) state = obs_module_text("Quota.PoolParked");
            else if (key.unknown) state = obs_module_text("Quota.PoolUnknown");
            else state = QString::fromUtf8(obs_module_text("Quota.PoolRemaining")).arg(locale.toString(key.remaining));
            if (key.active) state += QStringLiteral(" ") + QString(QChar(0x00B7)) + QStringLiteral(" ") + QString::fromUtf8(obs_module_text("Quota.PoolActive"));
            tips << QString::fromUtf8(obs_module_text("Quota.PoolKey")).arg(key.index).arg(snapshot.keys.size()) +
                QStringLiteral(" (...%1): %2").arg(key.fingerprint, state);
        }
        tips << QString::fromUtf8(obs_module_text("Quota.PoolThreshold")).arg(locale.toString(snapshot.threshold));
    }
    bar_->setToolTip(tips.join('\n'));
}
