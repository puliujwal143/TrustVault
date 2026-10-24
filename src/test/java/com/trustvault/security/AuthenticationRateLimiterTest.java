package com.trustvault.security;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;

class AuthenticationRateLimiterTest {

    private AuthenticationRateLimiter rateLimiter;

    @BeforeEach
    void setUp() {
        rateLimiter = new AuthenticationRateLimiter();
        rateLimiter.clearAll();
    }

    static class MutableClock extends Clock {
        private Instant now;
        private final ZoneId zone = ZoneOffset.UTC;

        public MutableClock(Instant start) {
            this.now = start;
        }

        public void advance(Duration duration) {
            this.now = this.now.plus(duration);
        }

        @Override
        public ZoneId getZone() {
            return zone;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return now;
        }
    }

    @Test
    @DisplayName("1. Threshold enforcement: exactly 5 consecutive failures blocks target, 4 does not")
    void testThresholdEnforcement() {
        String ip = "192.168.1.100";
        String username = "alice";

        for (int i = 1; i <= 4; i++) {
            rateLimiter.recordFailure(ip, username);
            assertThat(rateLimiter.isBlocked(ip, username))
                    .as("Attempt %d should not trigger rate limit block", i)
                    .isFalse();
        }

        // 5th failure triggers block
        rateLimiter.recordFailure(ip, username);
        assertThat(rateLimiter.isBlocked(ip, username))
                .as("5th failure must trigger block")
                .isTrue();

        assertThat(rateLimiter.getRemainingBlockSeconds(ip, username))
                .isGreaterThan(0)
                .isLessThanOrEqualTo(15 * 60);
    }

    @Test
    @DisplayName("2. User and IP isolation: blocking alice from IP A does not block alice from IP B or bob from IP A")
    void testTargetIsolation() {
        String attackerIp = "198.51.100.5";
        String legitimateIp = "203.0.113.1";
        String targetUser = "alice";
        String otherUser = "bob";

        // Attacker attempts 5 failed logins for alice
        for (int i = 0; i < 5; i++) {
            rateLimiter.recordFailure(attackerIp, targetUser);
        }

        // Attacker is blocked for alice
        assertThat(rateLimiter.isBlocked(attackerIp, targetUser)).isTrue();

        // Legitimate user alice from her own IP is NOT blocked
        assertThat(rateLimiter.isBlocked(legitimateIp, targetUser))
                .as("Alice from her legitimate IP must not be locked out")
                .isFalse();

        // Other user bob from attacker IP is NOT blocked (has not exceeded user limit or IP spray limit)
        assertThat(rateLimiter.isBlocked(attackerIp, otherUser))
                .as("Bob from attacker IP must not be locked out by Alice's threshold")
                .isFalse();
    }

    @Test
    @DisplayName("3. Reset on success: successful authentication resets target failure counter")
    void testSuccessResetsFailureCounter() {
        String ip = "192.168.1.10";
        String username = "charlie";

        // 4 failed attempts (1 away from block)
        for (int i = 0; i < 4; i++) {
            rateLimiter.recordFailure(ip, username);
        }
        assertThat(rateLimiter.isBlocked(ip, username)).isFalse();

        // Successful authentication occurs
        rateLimiter.recordSuccess(ip, username);

        // Next failure starts fresh at 1, does NOT trigger block
        rateLimiter.recordFailure(ip, username);
        assertThat(rateLimiter.isBlocked(ip, username)).isFalse();

        // Requires another 4 failures (total 5 in new cycle) to block
        for (int i = 0; i < 3; i++) {
            rateLimiter.recordFailure(ip, username);
        }
        assertThat(rateLimiter.isBlocked(ip, username)).isFalse();

        rateLimiter.recordFailure(ip, username);
        assertThat(rateLimiter.isBlocked(ip, username)).isTrue();
    }

    @Test
    @DisplayName("4. Credential spraying defense: 20 failures across distinct usernames blocks the entire IP")
    void testIpLevelSprayingThreshold() {
        String sprayingIp = "198.51.100.99";

        // Attacker sprays 19 distinct usernames (1 failure each)
        for (int i = 1; i <= 19; i++) {
            rateLimiter.recordFailure(sprayingIp, "user_" + i);
            assertThat(rateLimiter.isBlocked(sprayingIp, "user_" + i)).isFalse();
        }

        // 20th failure across the IP triggers global IP block
        rateLimiter.recordFailure(sprayingIp, "user_20");

        // Now ANY username attempted from this IP is blocked
        assertThat(rateLimiter.isBlocked(sprayingIp, "random_victim")).isTrue();
        assertThat(rateLimiter.isBlocked(sprayingIp, null)).isTrue();

        // Other IPs are completely unaffected
        assertThat(rateLimiter.isBlocked("10.0.0.1", "random_victim")).isFalse();
    }

    @Test
    @DisplayName("5. Concurrency safety: multi-threaded concurrent failures are tracked without race conditions")
    void testConcurrentFailures() throws InterruptedException {
        int threads = 10;
        int failuresPerThread = 5;
        ExecutorService executor = Executors.newFixedThreadPool(threads);
        CountDownLatch startLatch = new CountDownLatch(1);
        CountDownLatch doneLatch = new CountDownLatch(threads);

        for (int i = 0; i < threads; i++) {
            final String user = "concurrent_user_" + i;
            executor.submit(() -> {
                try {
                    startLatch.await();
                    for (int j = 0; j < failuresPerThread; j++) {
                        rateLimiter.recordFailure("10.0.0.50", user);
                    }
                } catch (InterruptedException ignored) {
                } finally {
                    doneLatch.countDown();
                }
            });
        }

        startLatch.countDown();
        assertThat(doneLatch.await(5, TimeUnit.SECONDS)).isTrue();
        executor.shutdown();

        // Every concurrent user should be blocked
        for (int i = 0; i < threads; i++) {
            assertThat(rateLimiter.isBlocked("10.0.0.50", "concurrent_user_" + i)).isTrue();
        }
    }

    @Test
    @DisplayName("6. Clear all: completely empties the cache")
    void testClearAll() {
        rateLimiter.recordFailure("1.2.3.4", "alice");
        assertThat(rateLimiter.getTrackedEntriesCount()).isGreaterThan(0);

        rateLimiter.clearAll();
        assertThat(rateLimiter.getTrackedEntriesCount()).isEqualTo(0);
        assertThat(rateLimiter.isBlocked("1.2.3.4", "alice")).isFalse();
    }

    @Test
    @DisplayName("7. Inactivity window expiration: 4 failures, expired inactivity window, then subsequent failures")
    void testInactivityWindowExpiration() {
        MutableClock clock = new MutableClock(Instant.parse("2026-10-24T10:00:00Z"));
        AuthenticationRateLimiter timedLimiter = new AuthenticationRateLimiter(clock);
        String ip = "192.168.5.50";
        String username = "david";

        // 4 failures at T=0
        for (int i = 0; i < 4; i++) {
            timedLimiter.recordFailure(ip, username);
        }
        assertThat(timedLimiter.isBlocked(ip, username)).isFalse();

        // Advance time by 16 minutes (beyond 15-minute inactivity window)
        clock.advance(Duration.ofMinutes(16));

        // 5th failure occurs after inactivity window has expired
        // It must reset counter to 1 and NOT trigger a block!
        timedLimiter.recordFailure(ip, username);
        assertThat(timedLimiter.isBlocked(ip, username))
                .as("Failure after inactivity window expiration must reset counter to 1, not trigger block")
                .isFalse();

        // Requires 4 more failures within the new active window (total 5) to block
        for (int i = 0; i < 3; i++) {
            timedLimiter.recordFailure(ip, username);
            assertThat(timedLimiter.isBlocked(ip, username)).isFalse();
        }

        timedLimiter.recordFailure(ip, username);
        assertThat(timedLimiter.isBlocked(ip, username))
                .as("5th failure within active window must block the user")
                .isTrue();
    }

    @Test
    @DisplayName("8. Active lockout preservation: active lockouts are preserved until expiry and not cleared prematurely")
    void testActiveLockoutPreservation() {
        MutableClock clock = new MutableClock(Instant.parse("2026-10-24T10:00:00Z"));
        AuthenticationRateLimiter timedLimiter = new AuthenticationRateLimiter(clock);
        String ip = "192.168.5.55";
        String username = "emma";

        // 5 failures to trigger lockout until 10:15
        for (int i = 0; i < 5; i++) {
            timedLimiter.recordFailure(ip, username);
        }
        assertThat(timedLimiter.isBlocked(ip, username)).isTrue();
        assertThat(timedLimiter.getRemainingBlockSeconds(ip, username)).isEqualTo(15 * 60);

        // Advance 5 minutes into the lockout
        clock.advance(Duration.ofMinutes(5));
        assertThat(timedLimiter.isBlocked(ip, username)).isTrue();
        assertThat(timedLimiter.getRemainingBlockSeconds(ip, username)).isEqualTo(10 * 60);

        // Additional failed attempts while locked out must preserve original block window
        timedLimiter.recordFailure(ip, username);
        assertThat(timedLimiter.isBlocked(ip, username)).isTrue();
        assertThat(timedLimiter.getRemainingBlockSeconds(ip, username)).isEqualTo(10 * 60);

        // Advance past block expiry (11 minutes later -> 10:16)
        clock.advance(Duration.ofMinutes(11));
        assertThat(timedLimiter.isBlocked(ip, username))
                .as("After 15-minute backoff expires, user is no longer blocked")
                .isFalse();

        // Subsequent failure starts fresh at attempt 1
        timedLimiter.recordFailure(ip, username);
        assertThat(timedLimiter.isBlocked(ip, username)).isFalse();
    }

    @Test
    @DisplayName("9. Capacity pressure: active lockouts are strictly preserved during cache eviction")
    void testCapacityPressurePreservesActiveLockout() {
        MutableClock clock = new MutableClock(Instant.parse("2026-10-24T10:00:00Z"));
        AuthenticationRateLimiter boundedLimiter = new AuthenticationRateLimiter(clock);

        String lockedIp = "198.51.100.1";
        String lockedUser = "locked_user";

        // Create an active lockout
        for (int i = 0; i < 5; i++) {
            boundedLimiter.recordFailure(lockedIp, lockedUser);
        }
        assertThat(boundedLimiter.isBlocked(lockedIp, lockedUser)).isTrue();

        // Flood the cache with 11,000 distinct unblocked attempt keys (exceeding MAX_CACHE_ENTRIES of 10,000)
        for (int i = 1; i <= 11_000; i++) {
            boundedLimiter.recordFailure("203.0.113." + (i % 250), "flood_user_" + i);
        }

        // Active lockout must NOT be evicted merely to make room for new unblocked records
        assertThat(boundedLimiter.isBlocked(lockedIp, lockedUser))
                .as("Active lockout record must survive capacity eviction under high-cardinality traffic")
                .isTrue();

        // Tracked entries must remain strictly bounded to prevent OOM
        assertThat(boundedLimiter.getTrackedEntriesCount())
                .as("Tracked entries in memory must remain bounded around MAX_CACHE_ENTRIES")
                .isLessThanOrEqualTo(AuthenticationRateLimiter.MAX_CACHE_ENTRIES + 100);
    }

    @Test
    @DisplayName("10. Shared proxy / loopback protection: loopback IP is never subject to global IP-level lockout")
    void testLoopbackExemptFromGlobalIpLockout() {
        String loopbackIp = "127.0.0.1";

        // 25 failed attempts across 25 different users from loopback
        for (int i = 1; i <= 25; i++) {
            rateLimiter.recordFailure(loopbackIp, "user_" + i);
        }

        // Unrelated user from loopback is NOT blocked by an IP-level spray lockout
        assertThat(rateLimiter.isBlocked(loopbackIp, "unrelated_user"))
                .as("Loopback IP must never trigger a site-wide block for all users")
                .isFalse();

        // However, a user who individually exceeded 5 attempts IS blocked
        for (int i = 1; i <= 5; i++) {
            rateLimiter.recordFailure(loopbackIp, "targeted_victim");
        }
        assertThat(rateLimiter.isBlocked(loopbackIp, "targeted_victim"))
                .as("Specific targeted user on loopback must still be blocked after 5 failures")
                .isTrue();
    }

    @Test
    @DisplayName("11. Private IP boundary validation: accurately classifies RFC 1918, link-local, loopback, and rejects invalid/public IPs")
    void testPrivateAndLoopbackIpBoundaries() {
        // Null, blank, unknown, localhost
        assertThat(AuthenticationRateLimiter.isSharedOrLoopbackIp(null)).isTrue();
        assertThat(AuthenticationRateLimiter.isSharedOrLoopbackIp("")).isTrue();
        assertThat(AuthenticationRateLimiter.isSharedOrLoopbackIp("   ")).isTrue();
        assertThat(AuthenticationRateLimiter.isSharedOrLoopbackIp("unknown")).isTrue();
        assertThat(AuthenticationRateLimiter.isSharedOrLoopbackIp("localhost")).isTrue();
        assertThat(AuthenticationRateLimiter.isSharedOrLoopbackIp("::1")).isTrue();
        assertThat(AuthenticationRateLimiter.isSharedOrLoopbackIp("0:0:0:0:0:0:0:1")).isTrue();

        // 127.0.0.0/8 (Loopback: 127.0.0.0 - 127.255.255.255)
        assertThat(AuthenticationRateLimiter.isSharedOrLoopbackIp("127.0.0.0")).isTrue();
        assertThat(AuthenticationRateLimiter.isSharedOrLoopbackIp("127.0.0.1")).isTrue();
        assertThat(AuthenticationRateLimiter.isSharedOrLoopbackIp("127.255.255.254")).isTrue();
        assertThat(AuthenticationRateLimiter.isSharedOrLoopbackIp("127.255.255.255")).isTrue();
        assertThat(AuthenticationRateLimiter.isSharedOrLoopbackIp("126.255.255.255")).isFalse();
        assertThat(AuthenticationRateLimiter.isSharedOrLoopbackIp("128.0.0.0")).isFalse();

        // 10.0.0.0/8 (Class A Private: 10.0.0.0 - 10.255.255.255)
        assertThat(AuthenticationRateLimiter.isSharedOrLoopbackIp("10.0.0.0")).isTrue();
        assertThat(AuthenticationRateLimiter.isSharedOrLoopbackIp("10.0.0.1")).isTrue();
        assertThat(AuthenticationRateLimiter.isSharedOrLoopbackIp("10.255.255.254")).isTrue();
        assertThat(AuthenticationRateLimiter.isSharedOrLoopbackIp("10.255.255.255")).isTrue();
        assertThat(AuthenticationRateLimiter.isSharedOrLoopbackIp("9.255.255.255")).isFalse();
        assertThat(AuthenticationRateLimiter.isSharedOrLoopbackIp("11.0.0.0")).isFalse();
        assertThat(AuthenticationRateLimiter.isSharedOrLoopbackIp("11.0.0.1")).isFalse();

        // 172.16.0.0/12 (Class B Private: 172.16.0.0 - 172.31.255.255)
        assertThat(AuthenticationRateLimiter.isSharedOrLoopbackIp("172.16.0.0")).isTrue();
        assertThat(AuthenticationRateLimiter.isSharedOrLoopbackIp("172.16.0.1")).isTrue();
        assertThat(AuthenticationRateLimiter.isSharedOrLoopbackIp("172.24.10.5")).isTrue();
        assertThat(AuthenticationRateLimiter.isSharedOrLoopbackIp("172.31.255.254")).isTrue();
        assertThat(AuthenticationRateLimiter.isSharedOrLoopbackIp("172.31.255.255")).isTrue();
        assertThat(AuthenticationRateLimiter.isSharedOrLoopbackIp("172.15.255.255")).isFalse();
        assertThat(AuthenticationRateLimiter.isSharedOrLoopbackIp("172.32.0.0")).isFalse();
        assertThat(AuthenticationRateLimiter.isSharedOrLoopbackIp("172.32.0.1")).isFalse();

        // 192.168.0.0/16 (Class C Private: 192.168.0.0 - 192.168.255.255)
        assertThat(AuthenticationRateLimiter.isSharedOrLoopbackIp("192.168.0.0")).isTrue();
        assertThat(AuthenticationRateLimiter.isSharedOrLoopbackIp("192.168.0.1")).isTrue();
        assertThat(AuthenticationRateLimiter.isSharedOrLoopbackIp("192.168.255.254")).isTrue();
        assertThat(AuthenticationRateLimiter.isSharedOrLoopbackIp("192.168.255.255")).isTrue();
        assertThat(AuthenticationRateLimiter.isSharedOrLoopbackIp("192.167.255.255")).isFalse();
        assertThat(AuthenticationRateLimiter.isSharedOrLoopbackIp("192.169.0.0")).isFalse();
        assertThat(AuthenticationRateLimiter.isSharedOrLoopbackIp("192.169.0.1")).isFalse();

        // 169.254.0.0/16 (Link-Local: 169.254.0.0 - 169.254.255.255)
        assertThat(AuthenticationRateLimiter.isSharedOrLoopbackIp("169.254.0.0")).isTrue();
        assertThat(AuthenticationRateLimiter.isSharedOrLoopbackIp("169.254.1.1")).isTrue();
        assertThat(AuthenticationRateLimiter.isSharedOrLoopbackIp("169.254.255.255")).isTrue();
        assertThat(AuthenticationRateLimiter.isSharedOrLoopbackIp("169.253.255.255")).isFalse();
        assertThat(AuthenticationRateLimiter.isSharedOrLoopbackIp("169.255.0.0")).isFalse();

        // Invalid octets, out of range values, and malformed addresses
        assertThat(AuthenticationRateLimiter.isSharedOrLoopbackIp("192.168.1.999")).isFalse();
        assertThat(AuthenticationRateLimiter.isSharedOrLoopbackIp("192.168.1.256")).isFalse();
        assertThat(AuthenticationRateLimiter.isSharedOrLoopbackIp("256.0.0.1")).isFalse();
        assertThat(AuthenticationRateLimiter.isSharedOrLoopbackIp("192.168.1.-1")).isFalse();
        assertThat(AuthenticationRateLimiter.isSharedOrLoopbackIp("192.168.01.1")).isFalse();
        assertThat(AuthenticationRateLimiter.isSharedOrLoopbackIp("10.0.0.01")).isFalse();
        assertThat(AuthenticationRateLimiter.isSharedOrLoopbackIp("192.168.1")).isFalse();
        assertThat(AuthenticationRateLimiter.isSharedOrLoopbackIp("192.168.1.1.1")).isFalse();
        assertThat(AuthenticationRateLimiter.isSharedOrLoopbackIp("10.0.0.0/8")).isFalse();
        assertThat(AuthenticationRateLimiter.isSharedOrLoopbackIp("172.16.0.1/12")).isFalse();
        assertThat(AuthenticationRateLimiter.isSharedOrLoopbackIp("abc.def.ghi.jkl")).isFalse();
        assertThat(AuthenticationRateLimiter.isSharedOrLoopbackIp("...")).isFalse();

        // Public IPs
        assertThat(AuthenticationRateLimiter.isSharedOrLoopbackIp("8.8.8.8")).isFalse();
        assertThat(AuthenticationRateLimiter.isSharedOrLoopbackIp("203.0.113.195")).isFalse();
        assertThat(AuthenticationRateLimiter.isSharedOrLoopbackIp("198.51.100.88")).isFalse();
    }

    @Test
    @DisplayName("12. Private RFC 1918 IPs exempt from global IP lockout while enforcing targeted per-user lockout")
    void testPrivateIpsExemptFromGlobalIpLockout() {
        String privateIp = "192.168.1.100";

        // 25 failed attempts across 25 different users from private network IP
        for (int i = 1; i <= 25; i++) {
            rateLimiter.recordFailure(privateIp, "user_" + i);
        }

        // Unrelated user from the private network is NOT blocked by IP spray lockout
        assertThat(rateLimiter.isBlocked(privateIp, "unrelated_colleague"))
                .as("Private RFC 1918 address must not block all users sharing a gateway")
                .isFalse();

        // Targeted user who had 5 failures IS individually blocked
        for (int i = 1; i <= 5; i++) {
            rateLimiter.recordFailure(privateIp, "targeted_private_user");
        }
        assertThat(rateLimiter.isBlocked(privateIp, "targeted_private_user"))
                .as("User exceeding 5 failures on private network is blocked")
                .isTrue();
    }

    @Test
    @DisplayName("13. Log sanitization removes CRLF, tabs, control characters, and truncates oversized input")
    void testLogSanitization() {
        // Null and blank
        assertThat(AuthenticationRateLimiter.sanitizeForLog(null)).isEqualTo("[none]");
        assertThat(AuthenticationRateLimiter.sanitizeForLog("")).isEqualTo("[none]");
        assertThat(AuthenticationRateLimiter.sanitizeForLog("   ")).isEqualTo("[none]");

        // CRLF, tab, and control character injection
        assertThat(AuthenticationRateLimiter.sanitizeForLog("admin\r\n[ERROR] Forged log line"))
                .isEqualTo("admin__[ERROR] Forged log line");
        assertThat(AuthenticationRateLimiter.sanitizeForLog("user\twith\tcontrol\u0000chars"))
                .isEqualTo("user_with_control_chars");

        // Oversized input truncation
        String oversized = "a".repeat(150);
        String sanitized = AuthenticationRateLimiter.sanitizeForLog(oversized);
        assertThat(sanitized).hasSize(103); // 100 chars + "..."
        assertThat(sanitized).endsWith("...");
    }

    @Test
    @DisplayName("14. Oversized usernames: SHA-256 hashing preserves account isolation and consistent lifecycle")
    void testOversizedUsernameIsolationAndLifecycle() {
        String base = "a".repeat(150);
        String userA = base + "_1";
        String userB = base + "_2";
        String ip = "192.168.1.75";

        // 4 failed attempts for userA
        for (int i = 0; i < 4; i++) {
            rateLimiter.recordFailure(ip, userA);
            assertThat(rateLimiter.isBlocked(ip, userA)).isFalse();
        }

        // Successful login resets counter for userA
        rateLimiter.recordSuccess(ip, userA);

        // Next failure starts at attempt 1 (not blocked)
        rateLimiter.recordFailure(ip, userA);
        assertThat(rateLimiter.isBlocked(ip, userA)).isFalse();

        // 4 more failures (total 5 consecutive within active window) triggers block for userA
        for (int i = 0; i < 4; i++) {
            rateLimiter.recordFailure(ip, userA);
        }
        assertThat(rateLimiter.isBlocked(ip, userA)).isTrue();
        assertThat(rateLimiter.getRemainingBlockSeconds(ip, userA)).isGreaterThan(0);

        // Account isolation: userB sharing the first 150 characters is NOT blocked
        assertThat(rateLimiter.isBlocked(ip, userB))
                .as("Distinct oversized username must not be blocked due to hash collision or truncation")
                .isFalse();
    }
}
