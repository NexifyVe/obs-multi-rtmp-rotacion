// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 TikTok Live OBS Contributors

#include "rapidapi_key_pool.hpp"

#include "rapidapi_quota.hpp"

#include <QCryptographicHash>
#include <QDateTime>
#include <QHash>
#include <QMutex>
#include <QMutexLocker>

#include <algorithm>

namespace {

struct PoolEntry {
	qint64 remaining = -1;             // -1 unknown
	qint64 limit = -1;
	qint64 reset_epoch_seconds = 0;
	qint64 observed_epoch_seconds = 0;
	qint64 parked_until = 0;           // epoch seconds
	bool invalid = false;
	bool seeded = false;               // already read the persistent snapshot
};

struct KeyPool {
	QString primary;
	QStringList candidates;           // primary first, then backups
	int threshold = kDefaultRapidApiRotationThreshold;
	QHash<QByteArray, PoolEntry> entries; // key fingerprint -> state
};

QMutex pool_mutex;
QHash<QByteArray, KeyPool> pools;     // primary fingerprint -> pool

QByteArray Fingerprint(const QString &key)
{
	return QCryptographicHash::hash(key.trimmed().toUtf8(), QCryptographicHash::Sha256).toHex().left(10);
}

QString ResolveLocked(KeyPool &pool, const HostedSigningServiceConfig &service, qint64 now)
{
	for (const QString &candidate : pool.candidates) {
		const QByteArray id = Fingerprint(candidate);
		auto entry = pool.entries.find(id);
		if (entry == pool.entries.end()) {
			// Seed once from the persistent per-key quota snapshot so a
			// restart (or a pool configured after usage) keeps its knowledge.
			PoolEntry seeded;
			seeded.seeded = true;
			HostedSigningServiceConfig per_key = service;
			per_key.api_key = candidate;
			const auto quota = ReadRapidApiQuota(per_key);
			if (quota.known()) {
				seeded.remaining = quota.remaining;
				seeded.limit = quota.limit;
				seeded.reset_epoch_seconds = quota.reset_epoch_seconds;
				seeded.observed_epoch_seconds = quota.observed_epoch_seconds;
			}
			entry = pool.entries.insert(id, seeded);
		}
		const PoolEntry &state = entry.value();
		if (state.invalid)
			continue;
		if (state.parked_until > now)
			continue;
		const bool reset_passed = state.reset_epoch_seconds > 0 && now >= state.reset_epoch_seconds;
		const bool unknown = state.remaining < 0 || reset_passed;
		if (unknown || state.remaining >= pool.threshold)
			return candidate;
	}
	// Nobody is usable: the first candidate is returned so the call fails
	// with the caller's existing quota/subscription error.
	return pool.candidates.isEmpty() ? QString() : pool.candidates.first();
}

} // namespace

std::function<qint64()> rapidapi_key_pool_clock = [] { return QDateTime::currentSecsSinceEpoch(); };

int DefaultRapidApiRotationThreshold()
{
	return kDefaultRapidApiRotationThreshold;
}

void ConfigureRapidApiKeyPool(const QString &primary_key, const QStringList &backup_keys, int threshold)
{
	const QString primary = primary_key.trimmed();
	QMutexLocker lock(&pool_mutex);
	if (primary.isEmpty())
		return;
	const QByteArray id = Fingerprint(primary);
	KeyPool pool;
	pool.primary = primary;
	pool.threshold = threshold >= 1 ? std::min(threshold, 100000) : kDefaultRapidApiRotationThreshold;
	QStringList candidates{primary};
	for (const QString &raw : backup_keys) {
		const QString key = raw.trimmed();
		if (key.isEmpty() || candidates.contains(key))
			continue;
		// Mirror HostedSigningServiceConfig::valid() constraints.
		if (key.size() > 4096 || key.contains(QLatin1Char('\r')) || key.contains(QLatin1Char('\n')))
			continue;
		candidates << key;
	}
	pool.candidates = candidates;
	const auto previous = pools.constFind(id);
	if (previous != pools.constEnd())
		pool.entries = previous.value().entries; // keep quota/parked/invalid state
	pools.insert(id, pool);
}

void ResetRapidApiKeyPools()
{
	QMutexLocker lock(&pool_mutex);
	pools.clear();
}

QString ResolveRapidApiKey(const HostedSigningServiceConfig &service)
{
	const QString primary = service.api_key.trimmed();
	if (primary.isEmpty())
		return service.api_key;
	QMutexLocker lock(&pool_mutex);
	const auto found = pools.find(Fingerprint(primary));
	if (found == pools.end())
		return primary; // no backups configured: single-key behavior
	return ResolveLocked(found.value(), service, rapidapi_key_pool_clock());
}

void NoteRapidApiObservation(const HostedSigningServiceConfig &service, const QString &key,
	const RapidApiObservation &observation)
{
	const QString primary = service.api_key.trimmed();
	const QString used = key.trimmed();
	if (primary.isEmpty() || used.isEmpty())
		return;
	QMutexLocker lock(&pool_mutex);
	const auto found = pools.find(Fingerprint(primary));
	if (found == pools.end())
		return;
	KeyPool &pool = found.value();
	if (!pool.candidates.contains(used))
		return;
	PoolEntry &entry = pool.entries[Fingerprint(used)];
	if (observation.quota_known) {
		entry.remaining = observation.remaining;
		entry.limit = observation.limit;
		entry.reset_epoch_seconds = observation.reset_epoch_seconds;
		entry.observed_epoch_seconds = observation.observed_epoch_seconds;
		entry.seeded = true;
	}
	if (observation.transport_failed)
		return; // network blip: keep whatever state we had
	const qint64 now = rapidapi_key_pool_clock();
	const bool success = observation.http_status >= 200 && observation.http_status < 300;
	if (success) {
		entry.invalid = false;
		entry.parked_until = 0;
		return;
	}
	if (observation.http_status == 401 || observation.http_status == 403) {
		entry.invalid = true;
		entry.parked_until = 0;
		return;
	}
	if (observation.http_status == 429) {
		// Healthy monthly quota means a burst/hourly limit: park briefly.
		// Otherwise the monthly quota is gone: remember the key as empty.
		if (entry.remaining >= 0 && entry.remaining >= pool.threshold)
			entry.parked_until = now + kRapidApiRateLimitParkSeconds;
		else {
			entry.remaining = 0;
			entry.parked_until = 0;
		}
	}
}

RapidApiKeyPoolSnapshot RapidApiKeyPoolStatus(const HostedSigningServiceConfig &service)
{
	RapidApiKeyPoolSnapshot snapshot;
	const QString primary = service.api_key.trimmed();
	if (primary.isEmpty())
		return snapshot;
	QMutexLocker lock(&pool_mutex);
	const auto found = pools.find(Fingerprint(primary));
	if (found == pools.end())
		return snapshot;
	const KeyPool &pool = found.value();
	const qint64 now = rapidapi_key_pool_clock();
	const QString active = ResolveLocked(found.value(), service, now);
	snapshot.configured = true;
	snapshot.threshold = pool.threshold;
	for (int index = 0; index < pool.candidates.size(); ++index) {
		const QString &candidate = pool.candidates.at(index);
		RapidApiKeyPoolKeyStatus status;
		status.fingerprint = QString::fromLatin1(Fingerprint(candidate));
		status.index = index + 1;
		status.active = candidate == active;
		if (status.active)
			snapshot.active_index = status.index;
		const auto entry = pool.entries.constFind(Fingerprint(candidate));
		if (entry != pool.entries.constEnd()) {
			const PoolEntry &state = entry.value();
			status.invalid = state.invalid;
			status.parked = state.parked_until > now;
			status.remaining = state.remaining;
			status.reset_epoch_seconds = state.reset_epoch_seconds;
			const bool reset_passed = state.reset_epoch_seconds > 0 && now >= state.reset_epoch_seconds;
			status.unknown = state.remaining < 0 || reset_passed;
			status.usable = !status.invalid && !status.parked && (status.unknown || state.remaining >= pool.threshold);
		} else {
			status.unknown = true; // never used: usable
			status.usable = true;
		}
		if (status.usable)
			++snapshot.usable_count;
		snapshot.keys << status;
	}
	return snapshot;
}
