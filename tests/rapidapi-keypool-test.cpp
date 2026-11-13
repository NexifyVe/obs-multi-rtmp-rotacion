// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 TikTok Live OBS Contributors

// Offline tests for the rotating RapidAPI key pool. No network, no OBS: the
// TIKTOK_NATIVE_TESTING fixture answers signing requests per key so the
// rotation, parking, invalidation, and monthly-reset rules are exercised
// exactly as they run inside the plugin.

#include "rapidapi_key_pool.hpp"
#include "rapidapi_quota.hpp"
#include "frame_signing.hpp"
#include "tiktok_request_signer.hpp"
#include "http_fixture.hpp"
#include "localization.hpp"

#include <QDateTime>
#include <QDir>
#include <QHash>
#include <QTemporaryDir>

#include <iostream>
#include <string>

// localization.cpp needs OBS; the fallbacks are what production uses anyway.
QString text(const char *key) { return QString::fromUtf8(key); }
QString translated_or(const char *key, const QString &fallback)
{
        (void)key;
        return fallback;
}

namespace {

bool expect(bool condition, const char *message)
{
        if (!condition)
                std::cerr << "FAIL: " << message << '\n';
        return condition;
}

const QString primary = QStringLiteral("primary-key-1");
const QString backup1 = QStringLiteral("backup-key-1");
const QString backup2 = QStringLiteral("backup-key-2");

HostedSigningServiceConfig Service(const QString &key)
{
        HostedSigningServiceConfig service;
        service.api_key = key;
        return service;
}

RapidApiObservation Observed(long status, qint64 remaining, qint64 limit = 1000, qint64 reset = 0)
{
        RapidApiObservation observation;
        observation.http_status = status;
        observation.quota_known = remaining >= 0 || limit >= 0;
        observation.remaining = remaining;
        observation.limit = limit;
        observation.reset_epoch_seconds = reset;
        observation.observed_epoch_seconds = rapidapi_key_pool_clock();
        return observation;
}

qint64 fixed_now = 1'700'000'000;

struct KeyUseRecorder {
        QString last_key;
        int calls = 0;
};

} // namespace

int main()
{
        bool passed = true;
        rapidapi_key_pool_clock = [] { return fixed_now; };
        SetRapidApiQuotaDirectory(QString()); // keep snapshots in memory

        // --- 1. Unconfigured pool keeps single-key behavior -------------------
        ResetRapidApiKeyPools();
        passed &= expect(ResolveRapidApiKey(Service(primary)) == primary,
                "unconfigured pool must return the primary unchanged");
        RapidApiObservation stray = Observed(200, 50);
        NoteRapidApiObservation(Service(primary), primary, stray); // no pool: ignored
        passed &= expect(ResolveRapidApiKey(Service(primary)) == primary,
                "observations without a pool must not change resolution");

        // --- 2. Rotation below the threshold ----------------------------------
        ConfigureRapidApiKeyPool(primary, {backup1, backup2}, 200);
        passed &= expect(ResolveRapidApiKey(Service(primary)) == primary,
                "fresh primary (quota unknown) must stay active");
        NoteRapidApiObservation(Service(primary), primary, Observed(200, 150));
        passed &= expect(ResolveRapidApiKey(Service(primary)) == backup1,
                "primary at 150 (< 200) must rotate to the first backup");
        NoteRapidApiObservation(Service(primary), backup1, Observed(200, 199));
        passed &= expect(ResolveRapidApiKey(Service(primary)) == backup2,
                "backup1 at 199 (< 200) must rotate to backup2");
        NoteRapidApiObservation(Service(primary), backup2, Observed(200, 40));
        passed &= expect(ResolveRapidApiKey(Service(primary)) == primary,
                "exhausted pool must fall back to the first candidate");
        NoteRapidApiObservation(Service(primary), primary, Observed(200, 200));
        passed &= expect(ResolveRapidApiKey(Service(primary)) == primary,
                "remaining == threshold is still usable (>= rule)");

        // --- 3. Status snapshot ------------------------------------------------
        const auto snapshot = RapidApiKeyPoolStatus(Service(primary));
        passed &= expect(snapshot.configured && snapshot.keys.size() == 3,
                "status must list every candidate");
        passed &= expect(snapshot.active_index == 1 && snapshot.usable_count == 1,
                "status must report the active key and usable count");
        passed &= expect(!snapshot.keys.at(0).fingerprint.isEmpty() &&
                        snapshot.keys.at(0).fingerprint != primary,
                "status must expose fingerprints, never raw keys");

        // --- 4. 429 with healthy monthly quota parks the key --------------------
        ResetRapidApiKeyPools();
        ConfigureRapidApiKeyPool(primary, {backup1}, 200);
        NoteRapidApiObservation(Service(primary), primary, Observed(429, 900));
        passed &= expect(ResolveRapidApiKey(Service(primary)) == backup1,
                "a 429 with healthy quota must park the key and rotate");
        fixed_now += 299;
        passed &= expect(ResolveRapidApiKey(Service(primary)) == backup1,
                "a parked key stays parked before the park expires");
        fixed_now += 2;
        passed &= expect(ResolveRapidApiKey(Service(primary)) == primary,
                "a parked key is readmitted after 300 s");

        // --- 5. 429 with low (or unknown) quota means exhaustion ---------------
        ResetRapidApiKeyPools();
        ConfigureRapidApiKeyPool(primary, {backup1}, 200);
        NoteRapidApiObservation(Service(primary), primary, Observed(429, 120));
        passed &= expect(ResolveRapidApiKey(Service(primary)) == backup1,
                "a 429 with low quota must exhaust the key");
        const auto exhausted = RapidApiKeyPoolStatus(Service(primary));
        passed &= expect(exhausted.keys.at(0).remaining == 0 && !exhausted.keys.at(0).usable,
                "an exhausted key reports 0 remaining");
        fixed_now += 3600;
        passed &= expect(ResolveRapidApiKey(Service(primary)) == backup1,
                "exhaustion (remaining=0, no reset) does not heal with time");

        // --- 6. 401 invalidates; a success rehabilitates ------------------------
        ResetRapidApiKeyPools();
        ConfigureRapidApiKeyPool(primary, {backup1}, 200);
        NoteRapidApiObservation(Service(primary), primary, Observed(401, -1, -1));
        passed &= expect(ResolveRapidApiKey(Service(primary)) == backup1,
                "a 401 must invalidate the key");
        NoteRapidApiObservation(Service(primary), primary, Observed(200, 800));
        passed &= expect(ResolveRapidApiKey(Service(primary)) == primary,
                "a later success must rehabilitate the key");

        // --- 7. Monthly reset makes the key unknown (usable) again --------------
        ResetRapidApiKeyPools();
        ConfigureRapidApiKeyPool(primary, {backup1}, 200);
        NoteRapidApiObservation(Service(primary), primary, Observed(200, 5, 1000, fixed_now + 10));
        passed &= expect(ResolveRapidApiKey(Service(primary)) == backup1,
                "a key below threshold stays rotated before its reset");
        fixed_now += 11;
        passed &= expect(ResolveRapidApiKey(Service(primary)) == primary,
                "after the monthly reset the key is unknown and usable again");

        // --- 8. Seeding from the persistent per-key snapshots -------------------
        ResetRapidApiKeyPools();
        QTemporaryDir storage;
        SetRapidApiQuotaDirectory(storage.filePath("quota"));
        {
                QHash<QByteArray, QByteArray> headers;
                headers.insert("x-ratelimit-requests-limit", "1000");
                headers.insert("x-ratelimit-requests-remaining", "3");
                RecordRapidApiQuota(Service(backup1), headers);
        }
        ConfigureRapidApiKeyPool(primary, {backup1, backup2}, 200);
        NoteRapidApiObservation(Service(primary), primary, Observed(200, 500)); // primary fine
        passed &= expect(ResolveRapidApiKey(Service(primary)) == primary,
                "a healthy primary stays active");
        NoteRapidApiObservation(Service(primary), primary, Observed(200, 10)); // primary drops
        passed &= expect(ResolveRapidApiKey(Service(primary)) == backup2,
                "a backup seeded as exhausted from disk must be skipped");
        SetRapidApiQuotaDirectory(QString());

        // --- 9. End-to-end through RapidApiRequestSigner::fetch ----------------
        ResetRapidApiKeyPools();
        SetRapidApiQuotaDirectory(QString()); // drop per-key snapshot memory between tests
        ConfigureRapidApiKeyPool(primary, {backup1}, 200);
        {
                KeyUseRecorder recorder;
                tiktok_http_fixture = [&recorder](const QByteArray &, const QUrl &,
                        const TikTokHttpHeaders &headers, const QByteArray &) {
                        QByteArray key;
                        for (const auto &header : headers)
                                if (header.first == "X-RapidAPI-Key")
                                        key = header.second;
                        recorder.last_key = QString::fromUtf8(key);
                        ++recorder.calls;
                        TikTokHttpFixtureResponse response;
                        response.status = 200;
                        if (key == "primary-key-1") {
                                // Last response before the rotation margin.
                                response.headers.insert("x-ratelimit-requests-limit", "1000");
                                response.headers.insert("x-ratelimit-requests-remaining", "150");
                                response.body = R"({"headers":{"x-khronos":"1","x-ladon":"2","x-argus":"3"}})";
                        } else {
                                response.headers.insert("x-ratelimit-requests-limit", "1000");
                                response.headers.insert("x-ratelimit-requests-remaining", "900");
                                response.body = R"({"headers":{"x-khronos":"1","x-ladon":"2","x-argus":"3"}})";
                        }
                        return response;
                };
                TikTokRequestSignatureInput input;
                input.timestamp_seconds = 1700000000;
                input.aid = "8311";
                input.device_id = "123";
                const auto first = RapidApiRequestSigner::fetch(Service(primary), input);
                passed &= expect(first.error.isEmpty() && first.valid(), "first signed request must succeed");
                passed &= expect(recorder.last_key == primary, "first request must use the primary");
                const auto second = RapidApiRequestSigner::fetch(Service(primary), input);
                passed &= expect(second.error.isEmpty() && second.valid(), "second signed request must succeed");
                passed &= expect(recorder.last_key == backup1,
                        "after the primary drops to 150 the next request must use the backup");
                passed &= expect(second.quota.remaining == 900, "quota reported is the active key's");
                tiktok_http_fixture = nullptr;
        }

        // --- 10. End-to-end 429 parks and rotates -------------------------------
        ResetRapidApiKeyPools();
        SetRapidApiQuotaDirectory(QString());
        ConfigureRapidApiKeyPool(primary, {backup1}, 200);
        {
                QString last_key;
                tiktok_http_fixture = [&last_key](const QByteArray &, const QUrl &,
                        const TikTokHttpHeaders &headers, const QByteArray &) {
                        QByteArray key;
                        for (const auto &header : headers)
                                if (header.first == "X-RapidAPI-Key")
                                        key = header.second;
                        last_key = QString::fromUtf8(key);
                        TikTokHttpFixtureResponse response;
                        if (key == "primary-key-1") {
                                response.status = 429;
                                response.headers.insert("x-ratelimit-requests-limit", "1000");
                                response.headers.insert("x-ratelimit-requests-remaining", "950");
                                response.body = R"({"message":"API rate limit exceeded"})";
                        } else {
                                response.status = 200;
                                response.headers.insert("x-ratelimit-requests-limit", "1000");
                                response.headers.insert("x-ratelimit-requests-remaining", "900");
                                response.body = R"({"headers":{"x-khronos":"1","x-ladon":"2","x-argus":"3"}})";
                        }
                        return response;
                };
                TikTokRequestSignatureInput input;
                input.timestamp_seconds = 1700000000;
                input.aid = "8311";
                input.device_id = "123";
                const auto limited = RapidApiRequestSigner::fetch(Service(primary), input);
                passed &= expect(!limited.error.isEmpty(), "the 429 response must surface an error");
                passed &= expect(last_key == primary, "the limited request used the primary");
                const auto after = RapidApiRequestSigner::fetch(Service(primary), input);
                passed &= expect(after.error.isEmpty(), "the follow-up request must succeed");
                passed &= expect(last_key == backup1, "a burst-limited primary must be parked and skipped");
                tiktok_http_fixture = nullptr;
        }

        // --- 11. End-to-end frame batch rotation --------------------------------
        ResetRapidApiKeyPools();
        SetRapidApiQuotaDirectory(QString());
        ConfigureRapidApiKeyPool(primary, {backup1}, 200);
        {
                QString last_key;
                tiktok_http_fixture = [&last_key](const QByteArray &, const QUrl &,
                        const TikTokHttpHeaders &headers, const QByteArray &) {
                        QByteArray key;
                        for (const auto &header : headers)
                                if (header.first == "X-RapidAPI-Key")
                                        key = header.second;
                        last_key = QString::fromUtf8(key);
                        TikTokHttpFixtureResponse response;
                        response.status = 200;
                        response.headers.insert("x-ratelimit-requests-limit", "1000");
                        response.headers.insert("x-ratelimit-requests-remaining", key == "primary-key-1" ? "100" : "800");
                        response.body = R"({"signatures":[{"timestamp":1700000000,"signResult":{"frametype":"2","lid":"1877999593","signinfo":"a","signvalue":"b","signversion":"1.0"}},{"timestamp":1700000001,"signResult":{"frametype":"2","lid":"1877999593","signinfo":"c","signvalue":"d","signversion":"1.0"}}]})";
                        return response;
                };
                FrameSignInput input;
                input.aid = "8311";
                input.uid = "1001";
                input.device_id = "2002";
                input.room_id = "3003";
                input.frame_type = "2";
                input.mobile = false;
                const auto first = FrameSignClient::fetch_batch(Service(primary), input, 1700000000, 300, 1, nullptr);
                passed &= expect(first.valid(), "first frame batch must be usable");
                passed &= expect(last_key == primary, "first frame batch used the primary");
                const auto second = FrameSignClient::fetch_batch(Service(primary), input, 1700000000, 300, 1, nullptr);
                passed &= expect(second.valid(), "second frame batch must be usable");
                passed &= expect(last_key == backup1,
                        "frame batches must rotate once the primary shows 100 left");
                tiktok_http_fixture = nullptr;
        }

        // --- 12. Re-configuration keeps runtime state ---------------------------
        ResetRapidApiKeyPools();
        ConfigureRapidApiKeyPool(primary, {backup1}, 200);
        NoteRapidApiObservation(Service(primary), primary, Observed(401, -1, -1));
        ConfigureRapidApiKeyPool(primary, {backup1, backup2}, 300); // same primary, new threshold
        passed &= expect(ResolveRapidApiKey(Service(primary)) == backup1,
                "re-configuring a pool must keep invalid/parked state");

        std::cout << (passed ? "rapidapi-keypool: all tests passed\n" : "rapidapi-keypool: FAILURES\n");
        return passed ? 0 : 1;
}
