package com.trustvault.security;

import org.apache.catalina.Valve;
import org.apache.catalina.connector.Connector;
import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.apache.catalina.valves.RemoteIpValve;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.web.ServerProperties;
import org.springframework.boot.autoconfigure.web.embedded.TomcatWebServerFactoryCustomizer;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.web.embedded.tomcat.TomcatServletWebServerFactory;
import org.springframework.core.env.Environment;
import org.springframework.mock.web.MockHttpServletRequest;

import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.event.AuthenticationFailureBadCredentialsEvent;
import org.springframework.security.web.authentication.WebAuthenticationDetails;

import java.util.Collection;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

/**
 * Validates forwarded-header processing, trusted reverse-proxy handling,
 * and rate-limiter IP resolution guarantees for Render deployments.
 *
 * <h3>Architectural Context & MockMvc Limitations:</h3>
 * <p>Spring Boot's {@code server.forward-headers-strategy: native} configures Tomcat's
 * {@link RemoteIpValve} on the embedded servlet container pipeline.
 * {@code MockMvc} operates strictly at the {@link org.springframework.web.servlet.DispatcherServlet}
 * layer using {@link MockHttpServletRequest}; it does <i>not</i> boot the underlying Tomcat
 * connector or execute container-level valves. Therefore:
 * <ul>
 *   <li>In {@code MockMvc}, {@code request.getRemoteAddr()} returns whatever the test harness
 *       explicitly sets via {@code with(request -> request.setRemoteAddr(...))}. Setting an
 *       {@code X-Forwarded-For} header in MockMvc does not automatically mutate {@code getRemoteAddr()}
 *       because the Tomcat engine is not involved.</li>
 *   <li>In live production on Render, incoming requests hit Render's router proxy (an internal IP
 *       such as {@code 10.x.x.x}). Tomcat's {@link RemoteIpValve} intercepts the request, verifies
 *       that the incoming socket originates from {@code internalProxies}, extracts the client IP
 *       from {@code X-Forwarded-For}, and calls {@code request.setRemoteAddr(clientIp)}.</li>
 *   <li>Application code (including {@link AuthenticationRateLimitingFilter} and
 *       {@link AuthenticationEventListener}) reads only {@code request.getRemoteAddr()}, never
 *       blindly trusting raw headers directly from untrusted clients.</li>
 * </ul>
 */
@SpringBootTest
class ForwardedHeaderHandlingTest {

    @Autowired
    private ServerProperties serverProperties;

    @Autowired
    private Environment environment;

    @Autowired
    private AuthenticationRateLimiter rateLimiter;

    @Autowired
    private AuthenticationEventListener authenticationEventListener;

    @Test
    @DisplayName("1. Actual application configuration binds native forward-headers-strategy and Tomcat remoteip properties")
    void testApplicationServerConfigurationBinding() {
        assertThat(serverProperties.getForwardHeadersStrategy())
                .as("server.forward-headers-strategy must be NATIVE")
                .isEqualTo(ServerProperties.ForwardHeadersStrategy.NATIVE);

        ServerProperties.Tomcat.Remoteip remoteip = serverProperties.getTomcat().getRemoteip();
        assertThat(remoteip.getRemoteIpHeader())
                .as("server.tomcat.remoteip.remote-ip-header must be x-forwarded-for")
                .isEqualTo("x-forwarded-for");
        assertThat(remoteip.getProtocolHeader())
                .as("server.tomcat.remoteip.protocol-header must be x-forwarded-proto")
                .isEqualTo("x-forwarded-proto");
        assertThat(remoteip.getInternalProxies())
                .as("server.tomcat.remoteip.internal-proxies must match the configured trusted internal CIDRs")
                .isEqualTo("10\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}|192\\.168\\.\\d{1,3}\\.\\d{1,3}|169\\.254\\.\\d{1,3}\\.\\d{1,3}|127\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}|172\\.(1[6-9]|2\\d|3[0-1])\\.\\d{1,3}\\.\\d{1,3}|0:0:0:0:0:0:0:1|::1");
        assertThat(remoteip.getTrustedProxies())
                .as("server.tomcat.remoteip.trusted-proxies must be configured")
                .isNotNull();
    }

    private RemoteIpValve getEffectiveRemoteIpValve() {
        TomcatWebServerFactoryCustomizer customizer = new TomcatWebServerFactoryCustomizer(environment, serverProperties);
        TomcatServletWebServerFactory factory = new TomcatServletWebServerFactory();
        customizer.customize(factory);

        return factory.getEngineValves().stream()
                .filter(v -> v instanceof RemoteIpValve)
                .map(v -> (RemoteIpValve) v)
                .findFirst()
                .orElseThrow(() -> new IllegalStateException("RemoteIpValve was not registered by TomcatWebServerFactoryCustomizer"));
    }

    @Test
    @DisplayName("2. TomcatWebServerFactoryCustomizer applies configured RemoteIpValve properties to Tomcat engine")
    void testTomcatCustomizerAppliesConfiguredRemoteIpValve() {
        RemoteIpValve configuredValve = getEffectiveRemoteIpValve();

        assertThat(configuredValve)
                .as("Tomcat engine must have RemoteIpValve registered by TomcatWebServerFactoryCustomizer")
                .isNotNull();
        assertThat(configuredValve.getRemoteIpHeader()).isEqualTo("x-forwarded-for");
        assertThat(configuredValve.getProtocolHeader()).isEqualTo("x-forwarded-proto");
        assertThat(configuredValve.getInternalProxies()).isEqualTo(serverProperties.getTomcat().getRemoteip().getInternalProxies());
        assertThat(configuredValve.getTrustedProxies()).isEqualTo(serverProperties.getTomcat().getRemoteip().getTrustedProxies());
    }

    @Test
    @DisplayName("3. Configured Tomcat RemoteIpValve extracts genuine client IP from X-Forwarded-For when sent by internal proxy")
    void testRemoteIpValveWithTrustedInternalProxy() throws Exception {
        RemoteIpValve valve = getEffectiveRemoteIpValve();

        // Mock next valve in pipeline to inspect modified request
        final String[] resolvedIpHolder = new String[1];
        valve.setNext(new Valve() {
            private Valve next;
            @Override public Valve getNext() { return next; }
            @Override public void setNext(Valve valve) { this.next = valve; }
            @Override public void backgroundProcess() {}
            @Override public void invoke(Request request, Response response) {
                resolvedIpHolder[0] = request.getRemoteAddr();
            }
            @Override public boolean isAsyncSupported() { return true; }
        });

        Connector connector = new Connector();
        Request request = new Request(connector);
        org.apache.coyote.Request coyoteRequest = new org.apache.coyote.Request();
        request.setCoyoteRequest(coyoteRequest);

        // Incoming TCP connection from Render's internal proxy IP
        request.setRemoteAddr("10.0.4.15");
        coyoteRequest.getMimeHeaders().addValue("x-forwarded-for").setString("203.0.113.195");
        coyoteRequest.getMimeHeaders().addValue("x-forwarded-proto").setString("https");

        valve.invoke(request, mock(Response.class));

        // RemoteIpValve must replace 10.0.4.15 with the client IP 203.0.113.195
        assertThat(resolvedIpHolder[0])
                .as("RemoteIpValve must resolve public client IP when request originates from internal proxy")
                .isEqualTo("203.0.113.195");
    }

    @Test
    @DisplayName("4. Configured Tomcat RemoteIpValve discards client-spoofed X-Forwarded-For when proxy appends real IP")
    void testRemoteIpValveDefeatsClientHeaderSpoofing() throws Exception {
        RemoteIpValve valve = getEffectiveRemoteIpValve();

        final String[] resolvedIpHolder = new String[1];
        valve.setNext(new Valve() {
            private Valve next;
            @Override public Valve getNext() { return next; }
            @Override public void setNext(Valve valve) { this.next = valve; }
            @Override public void backgroundProcess() {}
            @Override public void invoke(Request request, Response response) {
                resolvedIpHolder[0] = request.getRemoteAddr();
            }
            @Override public boolean isAsyncSupported() { return true; }
        });

        Connector connector = new Connector();
        Request request = new Request(connector);
        org.apache.coyote.Request coyoteRequest = new org.apache.coyote.Request();
        request.setCoyoteRequest(coyoteRequest);

        // Incoming connection from Render internal proxy
        request.setRemoteAddr("10.0.4.15");
        // Attacker spoofed 1.1.1.1, and Render's router appended the real attacker IP 198.51.100.88
        coyoteRequest.getMimeHeaders().addValue("x-forwarded-for").setString("1.1.1.1, 198.51.100.88");

        valve.invoke(request, mock(Response.class));

        // RemoteIpValve inspects from right to left, stopping at the first untrusted IP (198.51.100.88)
        assertThat(resolvedIpHolder[0])
                .as("RemoteIpValve must pick the rightmost untrusted IP (198.51.100.88), defeating spoofed 1.1.1.1")
                .isEqualTo("198.51.100.88");
    }

    @Test
    @DisplayName("5. Configured Tomcat RemoteIpValve ignores X-Forwarded-For if request comes directly from untrusted host")
    void testRemoteIpValveIgnoresHeadersFromUntrustedHosts() throws Exception {
        RemoteIpValve valve = getEffectiveRemoteIpValve();

        final String[] resolvedIpHolder = new String[1];
        valve.setNext(new Valve() {
            private Valve next;
            @Override public Valve getNext() { return next; }
            @Override public void setNext(Valve valve) { this.next = valve; }
            @Override public void backgroundProcess() {}
            @Override public void invoke(Request request, Response response) {
                resolvedIpHolder[0] = request.getRemoteAddr();
            }
            @Override public boolean isAsyncSupported() { return true; }
        });

        Connector connector = new Connector();
        Request request = new Request(connector);
        org.apache.coyote.Request coyoteRequest = new org.apache.coyote.Request();
        request.setCoyoteRequest(coyoteRequest);

        // Incoming connection directly from untrusted public IP (not in internalProxies)
        request.setRemoteAddr("198.51.100.22");
        coyoteRequest.getMimeHeaders().addValue("x-forwarded-for").setString("8.8.8.8");

        valve.invoke(request, mock(Response.class));

        // Because remoteAddr is not in internalProxies, X-Forwarded-For is completely ignored
        assertThat(resolvedIpHolder[0])
                .as("X-Forwarded-For must be ignored when request does not come from a trusted internal proxy")
                .isEqualTo("198.51.100.22");
    }

    @Test
    @DisplayName("6. AuthenticationRateLimitingFilter resolves IP strictly via request.getRemoteAddr()")
    void testFilterDoesNotReadRawSpoofedHeadersDirectly() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRemoteAddr("203.0.113.10");
        request.addHeader("X-Forwarded-For", "1.1.1.1");
        request.addHeader("X-Real-IP", "2.2.2.2");

        String resolved = AuthenticationRateLimitingFilter.resolveClientIp(request);

        assertThat(resolved)
                .as("Filter must read getRemoteAddr() and never parse raw client-supplied headers directly")
                .isEqualTo("203.0.113.10");
    }

    @Test
    @DisplayName("7. Committed internal-proxies regex matches complete 4-octet IPv4 addresses and rejects incomplete prefixes")
    void testInternalProxiesRegexMatchesCompleteAddresses() {
        String pattern = serverProperties.getTomcat().getRemoteip().getInternalProxies();
        java.util.regex.Pattern regex = java.util.regex.Pattern.compile(pattern);

        // Complete 4-octet IPv4 addresses across all branches
        assertThat(regex.matcher("10.0.4.15").matches()).isTrue();
        assertThat(regex.matcher("192.168.1.1").matches()).isTrue();
        assertThat(regex.matcher("169.254.1.1").matches()).isTrue();
        assertThat(regex.matcher("127.0.0.1").matches()).isTrue();
        assertThat(regex.matcher("172.16.0.1").matches()).isTrue();
        assertThat(regex.matcher("172.31.255.254").matches()).isTrue();
        assertThat(regex.matcher("::1").matches()).isTrue();
        assertThat(regex.matcher("0:0:0:0:0:0:0:1").matches()).isTrue();

        // Incomplete prefixes (must be rejected)
        assertThat(regex.matcher("192.168.1").matches()).isFalse();
        assertThat(regex.matcher("169.254.1").matches()).isFalse();
        assertThat(regex.matcher("10.1.1").matches()).isFalse();
        assertThat(regex.matcher("127.0.0").matches()).isFalse();

        // Out-of-range or public addresses (must be rejected)
        assertThat(regex.matcher("172.32.0.1").matches()).isFalse();
        assertThat(regex.matcher("203.0.113.195").matches()).isFalse();
    }

    @Test
    @DisplayName("8. Multi-hop forwarded-header chain resolves genuine client IP across trusted Cloudflare reverse proxy")
    void testRemoteIpValveWithMultiHopCloudflareProxyChain() throws Exception {
        RemoteIpValve valve = getEffectiveRemoteIpValve();

        final String[] resolvedIpHolder = new String[1];
        valve.setNext(new Valve() {
            private Valve next;
            @Override public Valve getNext() { return next; }
            @Override public void setNext(Valve valve) { this.next = valve; }
            @Override public void backgroundProcess() {}
            @Override public void invoke(Request request, Response response) {
                resolvedIpHolder[0] = request.getRemoteAddr();
            }
            @Override public boolean isAsyncSupported() { return true; }
        });

        Connector connector = new Connector();
        Request request = new Request(connector);
        org.apache.coyote.Request coyoteRequest = new org.apache.coyote.Request();
        request.setCoyoteRequest(coyoteRequest);

        // Incoming TCP connection from Render's internal router (10.0.4.15)
        request.setRemoteAddr("10.0.4.15");
        // Multi-hop header: genuine client (203.0.113.195), followed by Cloudflare edge proxy (162.158.55.76)
        coyoteRequest.getMimeHeaders().addValue("x-forwarded-for").setString("203.0.113.195, 162.158.55.76");
        coyoteRequest.getMimeHeaders().addValue("x-forwarded-proto").setString("https");

        valve.invoke(request, mock(Response.class));

        assertThat(resolvedIpHolder[0])
                .as("RemoteIpValve must traverse trusted Cloudflare proxy (162.158.55.76) and resolve genuine client IP (203.0.113.195)")
                .isEqualTo("203.0.113.195");
    }

    @Test
    @DisplayName("9. Multi-hop forwarded-header chain discards untrusted client-forged header while honoring trusted proxy")
    void testRemoteIpValveDefeatsClientForgedMultiHopHeader() throws Exception {
        RemoteIpValve valve = getEffectiveRemoteIpValve();

        final String[] resolvedIpHolder = new String[1];
        valve.setNext(new Valve() {
            private Valve next;
            @Override public Valve getNext() { return next; }
            @Override public void setNext(Valve valve) { this.next = valve; }
            @Override public void backgroundProcess() {}
            @Override public void invoke(Request request, Response response) {
                resolvedIpHolder[0] = request.getRemoteAddr();
            }
            @Override public boolean isAsyncSupported() { return true; }
        });

        Connector connector = new Connector();
        Request request = new Request(connector);
        org.apache.coyote.Request coyoteRequest = new org.apache.coyote.Request();
        request.setCoyoteRequest(coyoteRequest);

        // Incoming connection from Render internal proxy (10.0.4.15)
        request.setRemoteAddr("10.0.4.15");
        // Client at 203.0.113.195 attempted to forge 1.1.1.1.
        // Cloudflare appended 203.0.113.195, Render appended Cloudflare proxy 104.23.160.200.
        coyoteRequest.getMimeHeaders().addValue("x-forwarded-for").setString("1.1.1.1, 203.0.113.195, 104.23.160.200");

        valve.invoke(request, mock(Response.class));

        assertThat(resolvedIpHolder[0])
                .as("RemoteIpValve must step past trusted proxy 104.23.160.200 and stop at untrusted client 203.0.113.195, discarding forged 1.1.1.1")
                .isEqualTo("203.0.113.195");
    }

    @Test
    @DisplayName("10. Multi-hop request produces matching IP keys between pre-authentication filter and authentication failure listener")
    void testMultiHopRequestMatchesIpKeysBetweenFilterAndFailureListener() throws Exception {
        rateLimiter.clearAll();
        RemoteIpValve valve = getEffectiveRemoteIpValve();

        final String[] resolvedIps = new String[2];
        valve.setNext(new Valve() {
            private Valve next;
            @Override public Valve getNext() { return next; }
            @Override public void setNext(Valve valve) { this.next = valve; }
            @Override public void backgroundProcess() {}
            @Override public void invoke(Request request, Response response) {
                // 1. Filter resolves IP for rate limiting check
                resolvedIps[0] = AuthenticationRateLimitingFilter.resolveClientIp(request);

                // 2. Spring Security constructs WebAuthenticationDetails from request
                WebAuthenticationDetails webDetails = new WebAuthenticationDetails(request);
                resolvedIps[1] = webDetails.getRemoteAddress();

                // 3. Listener receives authentication failure event
                UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken("devuser", "wrong");
                auth.setDetails(webDetails);
                AuthenticationFailureBadCredentialsEvent failureEvent =
                        new AuthenticationFailureBadCredentialsEvent(auth, new BadCredentialsException("Bad credentials"));

                authenticationEventListener.onAuthenticationFailure(failureEvent);
            }
            @Override public boolean isAsyncSupported() { return true; }
        });

        Connector connector = new Connector();
        Request request = new Request(connector);
        org.apache.coyote.Request coyoteRequest = new org.apache.coyote.Request();
        request.setCoyoteRequest(coyoteRequest);

        request.setRemoteAddr("10.0.4.15");
        coyoteRequest.getMimeHeaders().addValue("x-forwarded-for").setString("203.0.113.195, 104.23.160.200");
        valve.invoke(request, mock(Response.class));

        // Filter and WebAuthenticationDetails must resolve matching client IPs
        assertThat(resolvedIps[0])
                .as("Filter IP resolution must match WebAuthenticationDetails remote address")
                .isEqualTo(resolvedIps[1])
                .isEqualTo("203.0.113.195");

        // Rate limiter must now have 1 failure recorded for target:203.0.113.195:devuser
        assertThat(rateLimiter.isBlocked(resolvedIps[0], "devuser"))
                .as("Target should not be blocked after 1 failure")
                .isFalse();
    }

    @Test
    @DisplayName("11. Sixth consecutive failed form-login attempt is blocked in multi-hop proxy environment")
    void testSixthFailedFormLoginAttemptBlockedInMultiHopEnvironment() throws Exception {
        rateLimiter.clearAll();
        RemoteIpValve valve = getEffectiveRemoteIpValve();

        // Simulate 5 consecutive failures from same client IP across rotating Cloudflare egress proxies
        String[] cloudflareProxies = {"162.158.55.76", "104.23.160.200", "104.23.160.102", "104.23.160.195", "162.158.55.76"};

        for (int i = 0; i < 5; i++) {
            valve.setNext(new Valve() {
                private Valve next;
                @Override public Valve getNext() { return next; }
                @Override public void setNext(Valve valve) { this.next = valve; }
                @Override public void backgroundProcess() {}
                @Override public void invoke(Request request, Response response) {
                    WebAuthenticationDetails details = new WebAuthenticationDetails(request);
                    UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken("devuser", "wrong");
                    auth.setDetails(details);
                    authenticationEventListener.onAuthenticationFailure(
                            new AuthenticationFailureBadCredentialsEvent(auth, new BadCredentialsException("Bad credentials")));
                }
                @Override public boolean isAsyncSupported() { return true; }
            });

            Connector connector = new Connector();
            Request request = new Request(connector);
            org.apache.coyote.Request coyoteRequest = new org.apache.coyote.Request();
            request.setCoyoteRequest(coyoteRequest);

            request.setRemoteAddr("10.0.4.15");
            coyoteRequest.getMimeHeaders().addValue("x-forwarded-for").setString("203.0.113.195, " + cloudflareProxies[i]);
            valve.invoke(request, mock(Response.class));
        }

        // On the 6th attempt, pre-authentication filter evaluates the incoming request
        final String[] resolvedFilterIp = new String[1];
        final boolean[] isBlockedHolder = new boolean[1];
        final long[] remainingSecHolder = new long[1];

        valve.setNext(new Valve() {
            private Valve next;
            @Override public Valve getNext() { return next; }
            @Override public void setNext(Valve valve) { this.next = valve; }
            @Override public void backgroundProcess() {}
            @Override public void invoke(Request request, Response response) {
                String filterIp = AuthenticationRateLimitingFilter.resolveClientIp(request);
                resolvedFilterIp[0] = filterIp;
                isBlockedHolder[0] = rateLimiter.isBlocked(filterIp, "devuser");
                remainingSecHolder[0] = rateLimiter.getRemainingBlockSeconds(filterIp, "devuser");
            }
            @Override public boolean isAsyncSupported() { return true; }
        });

        Connector connector = new Connector();
        Request request = new Request(connector);
        org.apache.coyote.Request coyoteRequest = new org.apache.coyote.Request();
        request.setCoyoteRequest(coyoteRequest);

        request.setRemoteAddr("10.0.4.15");
        coyoteRequest.getMimeHeaders().addValue("x-forwarded-for").setString("203.0.113.195, 104.23.160.200");
        valve.invoke(request, mock(Response.class));

        assertThat(resolvedFilterIp[0]).isEqualTo("203.0.113.195");

        // The 6th attempt MUST be blocked by the rate limiter
        assertThat(isBlockedHolder[0])
                .as("6th attempt from 203.0.113.195 for devuser must be blocked")
                .isTrue();
        assertThat(remainingSecHolder[0])
                .as("Remaining block duration should be greater than 0")
                .isGreaterThan(0);
    }

    @Test
    @DisplayName("12. Configured trusted-proxies regex strictly matches Cloudflare IPv4/IPv6 CIDRs and rejects invalid or malformed addresses")
    void testTrustedProxiesRegexMatchesCloudflareRangesAndRejectsIncomplete() {
        String pattern = serverProperties.getTomcat().getRemoteip().getTrustedProxies();
        assertThat(pattern)
                .as("server.tomcat.remoteip.trusted-proxies must be configured")
                .isNotNull();

        java.util.regex.Pattern regex = java.util.regex.Pattern.compile(pattern);

        // A. Real production Cloudflare proxy IPs reported in Render incident
        assertThat(regex.matcher("162.158.55.76").matches()).isTrue();
        assertThat(regex.matcher("104.23.160.200").matches()).isTrue();
        assertThat(regex.matcher("104.23.160.102").matches()).isTrue();
        assertThat(regex.matcher("104.23.160.195").matches()).isTrue();
        assertThat(regex.matcher("172.68.1.1").matches()).isTrue();

        // B. Valid addresses at exact trusted CIDR boundaries
        assertThat(regex.matcher("104.16.0.0").matches()).isTrue();
        assertThat(regex.matcher("104.27.255.255").matches()).isTrue();
        assertThat(regex.matcher("162.158.0.0").matches()).isTrue();
        assertThat(regex.matcher("162.159.255.255").matches()).isTrue();
        assertThat(regex.matcher("172.64.0.0").matches()).isTrue();
        assertThat(regex.matcher("172.71.255.255").matches()).isTrue();
        assertThat(regex.matcher("131.0.72.0").matches()).isTrue();
        assertThat(regex.matcher("131.0.75.255").matches()).isTrue();
        assertThat(regex.matcher("141.101.64.0").matches()).isTrue();
        assertThat(regex.matcher("141.101.127.255").matches()).isTrue();
        assertThat(regex.matcher("108.162.192.0").matches()).isTrue();
        assertThat(regex.matcher("108.162.255.255").matches()).isTrue();
        assertThat(regex.matcher("190.93.240.0").matches()).isTrue();
        assertThat(regex.matcher("190.93.255.255").matches()).isTrue();
        assertThat(regex.matcher("188.114.96.0").matches()).isTrue();
        assertThat(regex.matcher("188.114.111.255").matches()).isTrue();
        assertThat(regex.matcher("197.234.240.0").matches()).isTrue();
        assertThat(regex.matcher("197.234.243.255").matches()).isTrue();
        assertThat(regex.matcher("198.41.128.0").matches()).isTrue();
        assertThat(regex.matcher("198.41.255.255").matches()).isTrue();
        assertThat(regex.matcher("173.245.48.0").matches()).isTrue();
        assertThat(regex.matcher("173.245.63.255").matches()).isTrue();
        assertThat(regex.matcher("103.21.244.0").matches()).isTrue();
        assertThat(regex.matcher("103.21.247.255").matches()).isTrue();
        assertThat(regex.matcher("103.22.200.0").matches()).isTrue();
        assertThat(regex.matcher("103.22.203.255").matches()).isTrue();
        assertThat(regex.matcher("103.31.4.0").matches()).isTrue();
        assertThat(regex.matcher("103.31.7.255").matches()).isTrue();

        // C. Out-of-bounds IPv4 addresses just outside Cloudflare CIDRs
        assertThat(regex.matcher("104.15.255.255").matches()).isFalse();
        assertThat(regex.matcher("104.28.0.0").matches()).isFalse();
        assertThat(regex.matcher("162.157.255.255").matches()).isFalse();
        assertThat(regex.matcher("162.160.0.0").matches()).isFalse();
        assertThat(regex.matcher("172.63.255.255").matches()).isFalse();
        assertThat(regex.matcher("172.72.0.0").matches()).isFalse();

        // D. Invalid IPv4 octets above 255 (e.g. 256, 300, 999)
        assertThat(regex.matcher("104.23.160.999").matches()).isFalse();
        assertThat(regex.matcher("162.158.55.999").matches()).isFalse();
        assertThat(regex.matcher("104.23.160.256").matches()).isFalse();
        assertThat(regex.matcher("172.64.0.300").matches()).isFalse();
        assertThat(regex.matcher("104.16.256.1").matches()).isFalse();

        // E. Incomplete IPv4 prefixes
        assertThat(regex.matcher("104.23.160").matches()).isFalse();
        assertThat(regex.matcher("162.158.55").matches()).isFalse();
        assertThat(regex.matcher("172.64").matches()).isFalse();
        assertThat(regex.matcher("104.16.0.").matches()).isFalse();

        // F. Uppercase, lowercase, and mixed-case IPv6 Cloudflare prefixes
        assertThat(regex.matcher("2400:cb00:f00d::1").matches()).isTrue();
        assertThat(regex.matcher("2400:CB00:F00D::1").matches()).isTrue();
        assertThat(regex.matcher("2606:4700:4700::1111").matches()).isTrue();
        assertThat(regex.matcher("2606:4700:4700::1001").matches()).isTrue();
        assertThat(regex.matcher("2803:f800:abcd::1").matches()).isTrue();
        assertThat(regex.matcher("2803:F800:ABCD::1").matches()).isTrue();
        assertThat(regex.matcher("2405:b500:1::1").matches()).isTrue();
        assertThat(regex.matcher("2405:B500:1::1").matches()).isTrue();
        assertThat(regex.matcher("2405:8100:2::1").matches()).isTrue();
        assertThat(regex.matcher("2405:8100:2::1").matches()).isTrue();
        assertThat(regex.matcher("2c0f:f248::1").matches()).isTrue();
        assertThat(regex.matcher("2C0F:F248::1").matches()).isTrue();
        assertThat(regex.matcher("2a06:98c0:3600::103").matches()).isTrue();
        assertThat(regex.matcher("2A06:98C0:3600::103").matches()).isTrue();
        assertThat(regex.matcher("2a06:98c7:ffff::1").matches()).isTrue();
        assertThat(regex.matcher("2A06:98C7:FFFF::1").matches()).isTrue();

        // G. IPv6 addresses outside /29 CIDR boundary
        assertThat(regex.matcher("2a06:98c8:1::1").matches()).isFalse();

        // H. Arbitrary public IPs, non-proxy addresses, and untrusted IPv6
        assertThat(regex.matcher("203.0.113.195").matches()).isFalse();
        assertThat(regex.matcher("198.51.100.88").matches()).isFalse();
        assertThat(regex.matcher("1.1.1.1").matches()).isFalse();
        assertThat(regex.matcher("8.8.8.8").matches()).isFalse();
        assertThat(regex.matcher("2001:db8::1").matches()).isFalse();
        assertThat(regex.matcher("fe80::1").matches()).isFalse();

        // I. Malformed strings and non-IP tokens
        assertThat(regex.matcher("2400:cb00:attacker.com").matches()).isFalse();
        assertThat(regex.matcher("2400:cb00:!@#$%").matches()).isFalse();
        assertThat(regex.matcher("").matches()).isFalse();
    }
}
