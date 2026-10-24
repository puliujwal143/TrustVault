package com.trustvault.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Thread-safe, bounded in-memory rate limiter for authentication attempts.
 *
 * <p>Security & Operational Design:
 * <ul>
 *   <li><b>Targeted Brute-Force Defense:</b> Tracks consecutive authentication failures per
 *       composite key ({@code IP + ":" + normalizedUsername}). After {@value #MAX_ATTEMPTS_PER_TARGET}
 *       consecutive failures within the inactivity window, the specific user from that IP is
 *       temporarily blocked for {@value #BACKOFF_MINUTES} minutes.</li>
 *   <li><b>Credential Spraying Defense:</b> Tracks total consecutive failures per IP across all
 *       usernames. After {@value #MAX_ATTEMPTS_PER_IP} failures from the same client IP, all authentication
 *       attempts from that IP are temporarily blocked for {@value #BACKOFF_MINUTES} minutes.
 *       Shared proxy and loopback addresses are protected from global IP blocking to prevent
 *       accidental site-wide lockouts.</li>
 *   <li><b>Inactivity Window Expiration:</b> If a target account or IP experiences fewer failures
 *       than the blocking threshold and remains inactive for longer than {@link #EXPIRATION_WINDOW},
 *       the failure counter resets on the next attempt.</li>
 *   <li><b>Active Lockout Preservation:</b> Active lockouts are preserved until their intended
 *       expiry during standard eviction (which prioritizes expired and unblocked records). As an
 *       emergency anti-OOM fallback when the cache is saturated (&gt;95% capacity) entirely with
 *       active lockouts, the limiter evicts those closest to expiration to enforce memory bounds.</li>
 *   <li><b>Reset on Success:</b> Successfully authenticating immediately resets the failure
 *       counter for that specific user from that IP.</li>
 *   <li><b>Bounded Memory (Anti-OOM):</b> Bounded to {@value #MAX_CACHE_ENTRIES} entries with safe
 *       pruning under capacity pressure.</li>
 *   <li><b>Zero Sensitive Data:</b> Stores only normalized usernames and IPs; never accepts,
 *       handles, or stores passwords, tokens, or hashes.</li>
 * </ul>
 *
 * <p><b>Architecture Limitations & Multi-Instance Trade-offs:</b>
 * <ul>
 *   <li><b>Ephemeral / Reset on Restart:</b> In-memory state is local to the JVM process.
 *       Restarting or redeploying the application container resets failure counters.</li>
 *   <li><b>No Cross-Instance State Sharing:</b> In horizontal scaling environments with multiple
 *       active container instances behind a round-robin load balancer, counters are not shared
 *       across instances without an external distributed store (such as Redis). For TrustVault's
 *       current single-instance deployment on Render, this self-contained design provides robust
 *       brute-force defense without added infrastructure complexity or third-party dependencies.</li>
 * </ul>
 */
@Component
public class AuthenticationRateLimiter {

    private static final Logger log = LoggerFactory.getLogger(AuthenticationRateLimiter.class);

    public static final int MAX_ATTEMPTS_PER_TARGET = 5;
    public static final int MAX_ATTEMPTS_PER_IP = 20;
    public static final long BACKOFF_MINUTES = 15;
    public static final Duration BACKOFF_DURATION = Duration.ofMinutes(BACKOFF_MINUTES);
    public static final Duration EXPIRATION_WINDOW = Duration.ofMinutes(BACKOFF_MINUTES);
    public static final int MAX_CACHE_ENTRIES = 10_000;

    private final Clock clock;
    private final ConcurrentHashMap<String, AttemptRecord> cache = new ConcurrentHashMap<>();

    public AuthenticationRateLimiter() {
        this(Clock.systemUTC());
    }

    public AuthenticationRateLimiter(Clock clock) {
        this.clock = clock != null ? clock : Clock.systemUTC();
    }

    /**
     * Records a failed authentication attempt for a given client IP and username.
     *
     * @param ip       the client IP address (resolved safely from request)
     * @param username the target username attempted (optional/nullable)
     */
    public void recordFailure(String ip, String username) {
        String cleanIp = sanitizeIp(ip);
        String cleanUsername = sanitizeUsername(username);
        Instant now = clock.instant();

        ensureCapacity();

        // 1. Track composite key (IP + Username) if username is present
        if (cleanUsername != null) {
            String targetKey = buildTargetKey(cleanIp, cleanUsername);
            AttemptRecord targetRecord = cache.computeIfAbsent(targetKey, k -> new AttemptRecord(now));
            int count = targetRecord.recordFailure(now, EXPIRATION_WINDOW, BACKOFF_DURATION, MAX_ATTEMPTS_PER_TARGET);
            if (count >= MAX_ATTEMPTS_PER_TARGET && targetRecord.getBlockedUntil() != null) {
                log.warn("Rate limit triggered: IP '{}' temporarily blocked for username '{}' until {} (failures: {})",
                        cleanIp, cleanUsername, targetRecord.getBlockedUntil(), count);
            }
        }

        // 2. Track global IP key across all usernames to defend against credential spraying
        // Shared proxy, loopback, and unknown addresses are exempted from global IP-level lockout
        // to prevent collateral denial-of-service across unrelated visitors.
        if (!isSharedOrLoopbackIp(cleanIp)) {
            String ipKey = buildIpKey(cleanIp);
            AttemptRecord ipRecord = cache.computeIfAbsent(ipKey, k -> new AttemptRecord(now));
            int ipCount = ipRecord.recordFailure(now, EXPIRATION_WINDOW, BACKOFF_DURATION, MAX_ATTEMPTS_PER_IP);
            if (ipCount >= MAX_ATTEMPTS_PER_IP && ipRecord.getBlockedUntil() != null) {
                log.warn("IP spraying rate limit triggered: IP '{}' temporarily blocked for all usernames until {} (failures: {})",
                        cleanIp, ipRecord.getBlockedUntil(), ipCount);
            }
        }
    }

    /**
     * Resets the failure counter upon successful authentication.
     *
     * @param ip       the client IP address
     * @param username the authenticated username
     */
    public void recordSuccess(String ip, String username) {
        String cleanIp = sanitizeIp(ip);
        String cleanUsername = sanitizeUsername(username);

        if (cleanUsername != null) {
            String targetKey = buildTargetKey(cleanIp, cleanUsername);
            AttemptRecord removed = cache.remove(targetKey);
            if (removed != null && removed.getFailureCount() > 0) {
                log.debug("Reset failure counter for target '{}' from IP '{}'", cleanUsername, cleanIp);
            }
        }
    }

    /**
     * Checks whether authentication is currently blocked for the specified IP and username.
     *
     * @param ip       the client IP address
     * @param username the username being attempted (optional/nullable)
     * @return true if access is blocked due to excessive failures; false otherwise
     */
    public boolean isBlocked(String ip, String username) {
        String cleanIp = sanitizeIp(ip);
        String cleanUsername = sanitizeUsername(username);
        Instant now = clock.instant();

        // Check if IP is globally blocked (spraying defense)
        if (!isSharedOrLoopbackIp(cleanIp)) {
            String ipKey = buildIpKey(cleanIp);
            AttemptRecord ipRecord = cache.get(ipKey);
            if (ipRecord != null) {
                if (ipRecord.isBlocked(now)) {
                    return true;
                } else if (ipRecord.isExpired(now, EXPIRATION_WINDOW)) {
                    cache.remove(ipKey, ipRecord);
                }
            }
        }

        // Check if composite IP + username is blocked (targeted brute-force defense)
        if (cleanUsername != null) {
            String targetKey = buildTargetKey(cleanIp, cleanUsername);
            AttemptRecord targetRecord = cache.get(targetKey);
            if (targetRecord != null) {
                if (targetRecord.isBlocked(now)) {
                    return true;
                } else if (targetRecord.isExpired(now, EXPIRATION_WINDOW)) {
                    cache.remove(targetKey, targetRecord);
                }
            }
        }

        return false;
    }

    /**
     * Returns the remaining block duration in seconds for the given IP and username.
     * Returns 0 if not currently blocked.
     *
     * @param ip       the client IP address
     * @param username the username attempted
     * @return remaining seconds until block expiry
     */
    public long getRemainingBlockSeconds(String ip, String username) {
        String cleanIp = sanitizeIp(ip);
        String cleanUsername = sanitizeUsername(username);
        Instant now = clock.instant();

        Instant latestBlock = null;

        if (!isSharedOrLoopbackIp(cleanIp)) {
            String ipKey = buildIpKey(cleanIp);
            AttemptRecord ipRecord = cache.get(ipKey);
            if (ipRecord != null && ipRecord.isBlocked(now)) {
                latestBlock = ipRecord.getBlockedUntil();
            }
        }

        if (cleanUsername != null) {
            String targetKey = buildTargetKey(cleanIp, cleanUsername);
            AttemptRecord targetRecord = cache.get(targetKey);
            if (targetRecord != null && targetRecord.isBlocked(now)) {
                Instant targetBlock = targetRecord.getBlockedUntil();
                if (latestBlock == null || (targetBlock != null && targetBlock.isAfter(latestBlock))) {
                    latestBlock = targetBlock;
                }
            }
        }

        if (latestBlock == null || now.isAfter(latestBlock)) {
            return 0;
        }

        long seconds = Duration.between(now, latestBlock).toSeconds();
        return Math.max(1, seconds);
    }

    /**
     * Clears all in-memory rate-limiting counters. Primarily used for isolated test fixtures.
     */
    public void clearAll() {
        cache.clear();
    }

    /**
     * Returns the current number of tracked keys in memory.
     */
    public int getTrackedEntriesCount() {
        return cache.size();
    }

    /**
     * Determines whether an IP is a loopback, local, unknown, or RFC 1918 private network address.
     * Such addresses are exempted from global IP spraying lockouts to protect legitimate users
     * sharing proxy or internal gateway IP addresses, while targeted per-user rate limits remain enforced.
     *
     * <p>Protected ranges:
     * <ul>
     *   <li>IPv4 Loopback: {@code 127.0.0.0/8}</li>
     *   <li>Class A Private: {@code 10.0.0.0/8}</li>
     *   <li>Class B Private: {@code 172.16.0.0/12} (172.16.0.0 - 172.31.255.255)</li>
     *   <li>Class C Private: {@code 192.168.0.0/16}</li>
     *   <li>Link-Local: {@code 169.254.0.0/16}</li>
     *   <li>IPv6 Loopback / Localhost / Unknown</li>
     * </ul>
     */
    public static boolean isSharedOrLoopbackIp(String ip) {
        if (ip == null || ip.isBlank()) {
            return true;
        }
        String trimmed = ip.trim().toLowerCase(Locale.ROOT);
        if ("unknown".equals(trimmed) || "localhost".equals(trimmed) || "::1".equals(trimmed) || "0:0:0:0:0:0:0:1".equals(trimmed)) {
            return true;
        }

        // Strict IPv4 dotted-quad parsing and boundary validation
        String[] parts = trimmed.split("\\.", -1);
        if (parts.length != 4) {
            return false;
        }

        int[] octets = new int[4];
        for (int i = 0; i < 4; i++) {
            if (parts[i].isEmpty() || (parts[i].length() > 1 && parts[i].startsWith("0"))) {
                // Reject empty or leading-zero octets
                return false;
            }
            try {
                int val = Integer.parseInt(parts[i]);
                if (val < 0 || val > 255) {
                    return false;
                }
                octets[i] = val;
            } catch (NumberFormatException e) {
                return false;
            }
        }

        int o1 = octets[0];
        int o2 = octets[1];

        // 127.0.0.0/8 (IPv4 Loopback)
        if (o1 == 127) {
            return true;
        }

        // 10.0.0.0/8 (Class A Private)
        if (o1 == 10) {
            return true;
        }

        // 172.16.0.0/12 (Class B Private: 172.16.0.0 - 172.31.255.255)
        if (o1 == 172 && (o2 >= 16 && o2 <= 31)) {
            return true;
        }

        // 192.168.0.0/16 (Class C Private: 192.168.0.0 - 192.168.255.255)
        if (o1 == 192 && o2 == 168) {
            return true;
        }

        // 169.254.0.0/16 (Link-Local)
        if (o1 == 169 && o2 == 254) {
            return true;
        }

        return false;
    }

    /**
     * Evicts records to maintain memory bounds, preserving active lockouts except under extreme cache saturation.
     *
     * <p>Eviction Strategy:
     * <ol>
     *   <li>Pass 1: Evict expired records (expired blocks and unblocked records whose inactivity
     *       window has elapsed).</li>
     *   <li>Pass 2: If still above 90% capacity, evict unblocked records (non-lockouts). Active
     *       lockouts are strictly preserved.</li>
     *   <li>Pass 3 (Fail-Safe): If the cache is saturated (&gt;95% capacity) entirely with active
     *       lockouts, evict lockouts closest to expiration. This bounds memory and guarantees anti-OOM
     *       defense under massive distributed attacks.</li>
     * </ol>
     */
    private void ensureCapacity() {
        if (cache.size() < MAX_CACHE_ENTRIES) {
            return;
        }

        Instant now = clock.instant();

        // Pass 1: Evict all expired records
        Iterator<Map.Entry<String, AttemptRecord>> iterator = cache.entrySet().iterator();
        while (iterator.hasNext()) {
            Map.Entry<String, AttemptRecord> entry = iterator.next();
            if (entry.getValue().isExpired(now, EXPIRATION_WINDOW)) {
                iterator.remove();
            }
        }

        // Pass 2: If still >= 90% capacity, evict ONLY unblocked records to preserve active lockouts
        if (cache.size() >= (MAX_CACHE_ENTRIES * 0.9)) {
            int targetToPrune = (int) (MAX_CACHE_ENTRIES * 0.2);
            int prunedUnblocked = 0;

            Iterator<Map.Entry<String, AttemptRecord>> unblockedIter = cache.entrySet().iterator();
            while (unblockedIter.hasNext() && prunedUnblocked < targetToPrune) {
                Map.Entry<String, AttemptRecord> entry = unblockedIter.next();
                if (!entry.getValue().isBlocked(now)) {
                    unblockedIter.remove();
                    prunedUnblocked++;
                }
            }

            if (prunedUnblocked > 0) {
                log.warn("Rate limiter capacity pressure: pruned {} unblocked attempt records while preserving all active lockouts.", prunedUnblocked);
            }

            // Pass 3 (Fail-Safe): If cache is STILL saturated (>=95% capacity) with active lockouts,
            // evict the lockouts closest to expiration to strictly prevent OutOfMemoryError.
            if (cache.size() >= (MAX_CACHE_ENTRIES * 0.95)) {
                int emergencyPrune = (int) (MAX_CACHE_ENTRIES * 0.1);
                List<Map.Entry<String, AttemptRecord>> sortedLockouts = new ArrayList<>(cache.entrySet());
                sortedLockouts.sort(Comparator.comparing(e -> {
                    Instant b = e.getValue().getBlockedUntil();
                    return b != null ? b : Instant.MAX;
                }));

                int removedEmergency = 0;
                for (Map.Entry<String, AttemptRecord> entry : sortedLockouts) {
                    if (removedEmergency >= emergencyPrune) {
                        break;
                    }
                    cache.remove(entry.getKey(), entry.getValue());
                    removedEmergency++;
                }
                log.error("CRITICAL RATE LIMITER SATURATION: Memory bound enforced by emergency-evicting {} active lockouts closest to expiration.", removedEmergency);
            }
        }
    }

    private String buildTargetKey(String ip, String username) {
        return "target:" + ip + ":" + username;
    }

    private String buildIpKey(String ip) {
        return "ip:" + ip;
    }

    private String sanitizeIp(String ip) {
        if (ip == null || ip.isBlank()) {
            return "unknown";
        }
        return ip.trim();
    }

    private String sanitizeUsername(String username) {
        if (username == null || username.isBlank()) {
            return null;
        }
        return username.trim().toLowerCase(Locale.ROOT);
    }

    /**
     * Internal container tracking attempt counts, inactivity timestamps, and lockout windows.
     */
    public static final class AttemptRecord {
        private int failureCount = 0;
        private Instant lastFailureTime;
        private Instant blockedUntil = null;

        public AttemptRecord() {
            this(Instant.now());
        }

        public AttemptRecord(Instant now) {
            this.lastFailureTime = now;
        }

        /**
         * Synchronously records a failure with inactivity window reset and threshold blocking.
         */
        public synchronized int recordFailure(Instant now, Duration window, Duration backoff, int maxAttempts) {
            // Case 1: Active lockout is currently in effect -> preserve lockout and do not extend
            if (blockedUntil != null && now.isBefore(blockedUntil)) {
                this.lastFailureTime = now;
                return this.failureCount;
            }

            // Case 2: Lockout expired OR inactivity window expired -> reset to 1
            boolean blockExpired = (blockedUntil != null && !now.isBefore(blockedUntil));
            boolean windowExpired = Duration.between(lastFailureTime, now).compareTo(window) > 0;

            if (blockExpired || windowExpired) {
                this.failureCount = 1;
                this.blockedUntil = null;
                this.lastFailureTime = now;
                return 1;
            }

            // Case 3: Consecutive failure within active window
            this.lastFailureTime = now;
            this.failureCount++;
            if (this.failureCount >= maxAttempts && this.blockedUntil == null) {
                this.blockedUntil = now.plus(backoff);
            }
            return this.failureCount;
        }

        public synchronized int getFailureCount() {
            return this.failureCount;
        }

        public synchronized Instant getLastFailureTime() {
            return this.lastFailureTime;
        }

        public synchronized Instant getBlockedUntil() {
            return this.blockedUntil;
        }

        public synchronized void blockUntil(Instant until) {
            this.blockedUntil = until;
        }

        public synchronized boolean isBlocked(Instant now) {
            return blockedUntil != null && now.isBefore(blockedUntil);
        }

        public synchronized boolean isExpired(Instant now, Duration window) {
            if (blockedUntil != null) {
                return !now.isBefore(blockedUntil);
            }
            return Duration.between(lastFailureTime, now).compareTo(window) > 0;
        }
    }
}
