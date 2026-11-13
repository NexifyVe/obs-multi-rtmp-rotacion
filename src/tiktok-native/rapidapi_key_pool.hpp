// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 TikTok Live OBS Contributors

#pragma once

#include "hosted_signing_service.hpp"

#include <QList>
#include <QString>
#include <QStringList>

#include <functional>

// Rotating pool of RapidAPI keys: the primary first, then backups from other
// RapidAPI accounts. Every signing call resolves its key through the pool so a
// key that drops below the rotation margin is abandoned BEFORE it is
// exhausted. The LIVE keeps running: neither TikTok nor the viewer notices
// the switch, and the "stream stopped by itself" failure mode (a signature
// fetch failing on a dead key) disappears.
//
// The quota headers every RapidAPI response already carries are recorded per
// key, so learning the state of a backup costs nothing extra. Keys are only
// ever identified by a sha256 fingerprint in status reports.

// Margin kept on the active key before rotating away from it.
inline constexpr int kDefaultRapidApiRotationThreshold = 200;

// A 429 while the key still shows plenty of monthly quota is a burst/hourly
// rate limit, not exhaustion: park the key for a few minutes so rotation
// moves on, and readmit it automatically afterwards.
inline constexpr qint64 kRapidApiRateLimitParkSeconds = 300;

struct RapidApiKeyPoolKeyStatus {
	QString fingerprint;   // sha256 prefix, never the raw key
	int index = 0;         // 1-based position in the candidate list
	bool active = false;   // selected for the next request
	bool usable = false;
	bool invalid = false;  // rejected with 401/403
	bool parked = false;   // temporary burst/hourly rate limit
	bool unknown = false;  // no quota data (never called, or monthly reset passed)
	qint64 remaining = -1;
	qint64 reset_epoch_seconds = 0;
};

struct RapidApiKeyPoolSnapshot {
	bool configured = false; // a pool exists for this primary key
	int threshold = kDefaultRapidApiRotationThreshold;
	int active_index = 0;    // 1-based; 0 when unresolved
	int usable_count = 0;
	QList<RapidApiKeyPoolKeyStatus> keys;
};

// Registers (or replaces) the pool for one primary key. Backups must come
// from other RapidAPI accounts; duplicates, the primary itself, and
// malformed keys are dropped. Existing per-key runtime state (quota,
// parked, invalid) survives a re-configuration, so editing the field while
// live only adds or removes candidates. Called whenever target settings are
// saved and whenever a live session starts.
void ConfigureRapidApiKeyPool(const QString &primary_key, const QStringList &backup_keys, int threshold);

// The key the next signing call must use. A primary without a configured
// pool (no backups) or an empty key is returned unchanged: exact single-key
// behavior. When no candidate is usable, the first candidate is returned so
// the caller fails with its existing quota/subscription error.
QString ResolveRapidApiKey(const HostedSigningServiceConfig &service);

// Outcome of one signing request made with `key` (the resolved key), for the
// pool registered under service.api_key (the primary). Recording is skipped
// when no pool is configured.
struct RapidApiObservation {
	long http_status = 0;          // 0 when the transport itself failed
	bool transport_failed = false; // curl error: no response at all
	bool quota_known = false;
	qint64 remaining = -1;
	qint64 limit = -1;
	qint64 reset_epoch_seconds = 0;
	qint64 observed_epoch_seconds = 0;
};
void NoteRapidApiObservation(const HostedSigningServiceConfig &service, const QString &key,
	const RapidApiObservation &observation);

// Status summary for the quota widget tooltip.
RapidApiKeyPoolSnapshot RapidApiKeyPoolStatus(const HostedSigningServiceConfig &service);

int DefaultRapidApiRotationThreshold();

// Test hook: replaceable clock (epoch seconds). Production always uses the
// wall clock; tests swap it to exercise parks and monthly resets.
extern std::function<qint64()> rapidapi_key_pool_clock;

// Test hook: forget every configured pool.
void ResetRapidApiKeyPools();
