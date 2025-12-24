// Populate the sidebar
//
// This is a script, and not included directly in the page, to control the total size of the book.
// The TOC contains an entry for each page, so if each page includes a copy of the TOC,
// the total size of the page becomes O(n**2).
class MDBookSidebarScrollbox extends HTMLElement {
    constructor() {
        super();
    }
    connectedCallback() {
        this.innerHTML = '<ol class="chapter"><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="introduction.html">Introduction</a></span></li><li class="chapter-item expanded "><li class="part-title">Getting Started</li></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="getting-started/installation.html"><strong aria-hidden="true">1.</strong> Installation</a></span></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="getting-started/quick-start.html"><strong aria-hidden="true">2.</strong> Quick Start</a></span></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="getting-started/basic-configuration.html"><strong aria-hidden="true">3.</strong> Basic Configuration</a></span></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="getting-started/first-route.html"><strong aria-hidden="true">4.</strong> First Route</a></span></li><li class="chapter-item expanded "><li class="part-title">Core Concepts</li></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="concepts/architecture.html"><strong aria-hidden="true">5.</strong> Architecture Overview</a></span><ol class="section"><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="concepts/pingora.html"><strong aria-hidden="true">5.1.</strong> Pingora Foundation</a></span></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="concepts/request-flow.html"><strong aria-hidden="true">5.2.</strong> Request Flow</a></span></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="concepts/components.html"><strong aria-hidden="true">5.3.</strong> Component Design</a></span></li></ol><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="concepts/routing.html"><strong aria-hidden="true">6.</strong> Routing System</a></span><ol class="section"><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="concepts/route-matching.html"><strong aria-hidden="true">6.1.</strong> Route Matching</a></span></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="concepts/route-priority.html"><strong aria-hidden="true">6.2.</strong> Priority Rules</a></span></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="concepts/path-variables.html"><strong aria-hidden="true">6.3.</strong> Path Variables</a></span></li></ol><li class="chapter-item expanded "><li class="part-title">Configuration</li></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="configuration/overview.html"><strong aria-hidden="true">7.</strong> Configuration Overview</a></span></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="configuration/kdl-format.html"><strong aria-hidden="true">8.</strong> KDL Configuration Format</a></span></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="configuration/server.html"><strong aria-hidden="true">9.</strong> Server Configuration</a></span><ol class="section"><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="configuration/listeners.html"><strong aria-hidden="true">9.1.</strong> Listeners</a></span></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="configuration/tls.html"><strong aria-hidden="true">9.2.</strong> TLS Settings</a></span></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="configuration/performance.html"><strong aria-hidden="true">9.3.</strong> Performance Tuning</a></span></li></ol><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="configuration/routes.html"><strong aria-hidden="true">10.</strong> Routes Configuration</a></span><ol class="section"><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="configuration/basic-routes.html"><strong aria-hidden="true">10.1.</strong> Basic Routes</a></span></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="configuration/advanced-routing.html"><strong aria-hidden="true">10.2.</strong> Advanced Routing</a></span></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="configuration/route-groups.html"><strong aria-hidden="true">10.3.</strong> Route Groups</a></span></li></ol><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="configuration/upstreams.html"><strong aria-hidden="true">11.</strong> Upstream Configuration</a></span><ol class="section"><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="configuration/load-balancing.html"><strong aria-hidden="true">11.1.</strong> Load Balancing</a></span></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="configuration/health-checks.html"><strong aria-hidden="true">11.2.</strong> Health Checks</a></span></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="configuration/connection-pools.html"><strong aria-hidden="true">11.3.</strong> Connection Pools</a></span></li></ol><li class="chapter-item expanded "><li class="part-title">Service Types</li></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="service-types/overview.html"><strong aria-hidden="true">12.</strong> Service Types Overview</a></span></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="service-types/web.html"><strong aria-hidden="true">13.</strong> Web Applications</a></span><ol class="section"><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="service-types/web-error-pages.html"><strong aria-hidden="true">13.1.</strong> HTML Error Pages</a></span></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="service-types/web-sessions.html"><strong aria-hidden="true">13.2.</strong> Session Handling</a></span></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="service-types/spa-support.html"><strong aria-hidden="true">13.3.</strong> SPA Support</a></span></li></ol><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="service-types/api.html"><strong aria-hidden="true">14.</strong> REST APIs</a></span><ol class="section"><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="service-types/api-validation.html"><strong aria-hidden="true">14.1.</strong> JSON Validation</a></span></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="service-types/api-schemas.html"><strong aria-hidden="true">14.2.</strong> Schema Management</a></span></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="service-types/api-errors.html"><strong aria-hidden="true">14.3.</strong> Error Responses</a></span></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="service-types/openapi.html"><strong aria-hidden="true">14.4.</strong> OpenAPI Integration</a></span></li></ol><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="service-types/static.html"><strong aria-hidden="true">15.</strong> Static Files</a></span><ol class="section"><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="service-types/file-serving.html"><strong aria-hidden="true">15.1.</strong> File Serving</a></span></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="service-types/caching.html"><strong aria-hidden="true">15.2.</strong> Caching Headers</a></span></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="service-types/directory-listing.html"><strong aria-hidden="true">15.3.</strong> Directory Listing</a></span></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="service-types/static-security.html"><strong aria-hidden="true">15.4.</strong> Security Features</a></span></li></ol><li class="chapter-item expanded "><li class="part-title">Features</li></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="features/error-handling.html"><strong aria-hidden="true">16.</strong> Error Handling</a></span><ol class="section"><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="features/custom-error-pages.html"><strong aria-hidden="true">16.1.</strong> Custom Error Pages</a></span></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="features/error-templates.html"><strong aria-hidden="true">16.2.</strong> Error Templates</a></span></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="features/content-negotiation.html"><strong aria-hidden="true">16.3.</strong> Format Negotiation</a></span></li></ol><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="features/processing.html"><strong aria-hidden="true">17.</strong> Request/Response Processing</a></span><ol class="section"><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="features/headers.html"><strong aria-hidden="true">17.1.</strong> Headers Manipulation</a></span></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="features/rewriting.html"><strong aria-hidden="true">17.2.</strong> Request Rewriting</a></span></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="features/filtering.html"><strong aria-hidden="true">17.3.</strong> Response Filtering</a></span></li></ol><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="features/observability.html"><strong aria-hidden="true">18.</strong> Observability</a></span><ol class="section"><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="features/logging.html"><strong aria-hidden="true">18.1.</strong> Logging</a></span></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="features/metrics.html"><strong aria-hidden="true">18.2.</strong> Metrics</a></span></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="features/tracing.html"><strong aria-hidden="true">18.3.</strong> Tracing</a></span></li></ol><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="features/security.html"><strong aria-hidden="true">19.</strong> Security</a></span><ol class="section"><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="features/rate-limiting.html"><strong aria-hidden="true">19.1.</strong> Rate Limiting</a></span></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="features/authentication.html"><strong aria-hidden="true">19.2.</strong> Authentication</a></span></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="features/authorization.html"><strong aria-hidden="true">19.3.</strong> Authorization</a></span></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="features/cors.html"><strong aria-hidden="true">19.4.</strong> CORS</a></span></li></ol><li class="chapter-item expanded "><li class="part-title">Advanced Topics</li></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="advanced/http3.html"><strong aria-hidden="true">20.</strong> HTTP/3 Support</a></span><ol class="section"><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="advanced/quic.html"><strong aria-hidden="true">20.1.</strong> QUIC Protocol</a></span></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="advanced/0-rtt.html"><strong aria-hidden="true">20.2.</strong> 0-RTT Configuration</a></span></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="advanced/http3-migration.html"><strong aria-hidden="true">20.3.</strong> Migration Guide</a></span></li></ol><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="advanced/performance.html"><strong aria-hidden="true">21.</strong> Performance Optimization</a></span><ol class="section"><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="advanced/caching-strategies.html"><strong aria-hidden="true">21.1.</strong> Caching Strategies</a></span></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="advanced/connections.html"><strong aria-hidden="true">21.2.</strong> Connection Management</a></span></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="advanced/memory.html"><strong aria-hidden="true">21.3.</strong> Memory Usage</a></span></li></ol><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="advanced/high-availability.html"><strong aria-hidden="true">22.</strong> High Availability</a></span><ol class="section"><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="advanced/failover.html"><strong aria-hidden="true">22.1.</strong> Failover</a></span></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="advanced/circuit-breakers.html"><strong aria-hidden="true">22.2.</strong> Circuit Breakers</a></span></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="advanced/retry.html"><strong aria-hidden="true">22.3.</strong> Retry Policies</a></span></li></ol><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="advanced/extensions.html"><strong aria-hidden="true">23.</strong> Custom Extensions</a></span><ol class="section"><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="advanced/middleware.html"><strong aria-hidden="true">23.1.</strong> Writing Middleware</a></span></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="advanced/custom-handlers.html"><strong aria-hidden="true">23.2.</strong> Custom Handlers</a></span></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="advanced/plugins.html"><strong aria-hidden="true">23.3.</strong> Plugin System</a></span></li></ol><li class="chapter-item expanded "><li class="part-title">Deployment</li></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="deployment/overview.html"><strong aria-hidden="true">24.</strong> Deployment Overview</a></span></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="deployment/docker.html"><strong aria-hidden="true">25.</strong> Docker Deployment</a></span><ol class="section"><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="deployment/docker-build.html"><strong aria-hidden="true">25.1.</strong> Building Images</a></span></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="deployment/docker-compose.html"><strong aria-hidden="true">25.2.</strong> Docker Compose</a></span></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="deployment/kubernetes.html"><strong aria-hidden="true">25.3.</strong> Kubernetes</a></span></li></ol><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="deployment/systemd.html"><strong aria-hidden="true">26.</strong> Systemd Service</a></span></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="deployment/config-management.html"><strong aria-hidden="true">27.</strong> Configuration Management</a></span></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="deployment/rolling-updates.html"><strong aria-hidden="true">28.</strong> Rolling Updates</a></span></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="deployment/monitoring.html"><strong aria-hidden="true">29.</strong> Monitoring Setup</a></span></li><li class="chapter-item expanded "><li class="part-title">Operations</li></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="operations/health-checks.html"><strong aria-hidden="true">30.</strong> Health Checks</a></span></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="operations/backup.html"><strong aria-hidden="true">31.</strong> Backup &amp; Recovery</a></span></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="operations/troubleshooting.html"><strong aria-hidden="true">32.</strong> Troubleshooting</a></span><ol class="section"><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="operations/common-issues.html"><strong aria-hidden="true">32.1.</strong> Common Issues</a></span></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="operations/debug-mode.html"><strong aria-hidden="true">32.2.</strong> Debug Mode</a></span></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="operations/perf-issues.html"><strong aria-hidden="true">32.3.</strong> Performance Issues</a></span></li></ol><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="operations/migration.html"><strong aria-hidden="true">33.</strong> Migration Guide</a></span><ol class="section"><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="operations/from-nginx.html"><strong aria-hidden="true">33.1.</strong> From Nginx</a></span></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="operations/from-haproxy.html"><strong aria-hidden="true">33.2.</strong> From HAProxy</a></span></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="operations/from-traefik.html"><strong aria-hidden="true">33.3.</strong> From Traefik</a></span></li></ol><li class="chapter-item expanded "><li class="part-title">API Reference</li></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="reference/config-schema.html"><strong aria-hidden="true">34.</strong> Configuration Schema</a></span></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="reference/env-vars.html"><strong aria-hidden="true">35.</strong> Environment Variables</a></span></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="reference/cli.html"><strong aria-hidden="true">36.</strong> Command Line Options</a></span></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="reference/error-codes.html"><strong aria-hidden="true">37.</strong> Error Codes</a></span></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="reference/metrics.html"><strong aria-hidden="true">38.</strong> Metrics Reference</a></span></li><li class="chapter-item expanded "><li class="part-title">Examples</li></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="examples/configurations.html"><strong aria-hidden="true">39.</strong> Example Configurations</a></span><ol class="section"><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="examples/simple-proxy.html"><strong aria-hidden="true">39.1.</strong> Simple Proxy</a></span></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="examples/load-balancer.html"><strong aria-hidden="true">39.2.</strong> Load Balancer</a></span></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="examples/api-gateway.html"><strong aria-hidden="true">39.3.</strong> API Gateway</a></span></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="examples/static-site.html"><strong aria-hidden="true">39.4.</strong> Static Site</a></span></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="examples/mixed-services.html"><strong aria-hidden="true">39.5.</strong> Mixed Services</a></span></li></ol><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="examples/integrations.html"><strong aria-hidden="true">40.</strong> Integration Examples</a></span><ol class="section"><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="examples/prometheus.html"><strong aria-hidden="true">40.1.</strong> With Prometheus</a></span></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="examples/grafana.html"><strong aria-hidden="true">40.2.</strong> With Grafana</a></span></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="examples/jaeger.html"><strong aria-hidden="true">40.3.</strong> With Jaeger</a></span></li></ol><li class="chapter-item expanded "><li class="part-title">Development</li></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="development/building.html"><strong aria-hidden="true">41.</strong> Building from Source</a></span></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="development/setup.html"><strong aria-hidden="true">42.</strong> Development Setup</a></span></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="development/testing.html"><strong aria-hidden="true">43.</strong> Testing</a></span><ol class="section"><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="development/unit-tests.html"><strong aria-hidden="true">43.1.</strong> Unit Tests</a></span></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="development/integration-tests.html"><strong aria-hidden="true">43.2.</strong> Integration Tests</a></span></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="development/load-testing.html"><strong aria-hidden="true">43.3.</strong> Load Testing</a></span></li></ol><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="development/contributing.html"><strong aria-hidden="true">44.</strong> Contributing</a></span><ol class="section"><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="development/code-style.html"><strong aria-hidden="true">44.1.</strong> Code Style</a></span></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="development/pr-process.html"><strong aria-hidden="true">44.2.</strong> Pull Request Process</a></span></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="development/releases.html"><strong aria-hidden="true">44.3.</strong> Release Process</a></span></li></ol><li class="chapter-item expanded "><li class="part-title">Appendices</li></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="appendix/glossary.html"><strong aria-hidden="true">45.</strong> Glossary</a></span></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="appendix/faq.html"><strong aria-hidden="true">46.</strong> FAQ</a></span></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="appendix/changelog.html"><strong aria-hidden="true">47.</strong> Changelog</a></span></li><li class="chapter-item expanded "><span class="chapter-link-wrapper"><a href="appendix/license.html"><strong aria-hidden="true">48.</strong> License</a></span></li></ol>';
        // Set the current, active page, and reveal it if it's hidden
        let current_page = document.location.href.toString().split('#')[0].split('?')[0];
        if (current_page.endsWith('/')) {
            current_page += 'index.html';
        }
        const links = Array.prototype.slice.call(this.querySelectorAll('a'));
        const l = links.length;
        for (let i = 0; i < l; ++i) {
            const link = links[i];
            const href = link.getAttribute('href');
            if (href && !href.startsWith('#') && !/^(?:[a-z+]+:)?\/\//.test(href)) {
                link.href = path_to_root + href;
            }
            // The 'index' page is supposed to alias the first chapter in the book.
            if (link.href === current_page
                || i === 0
                && path_to_root === ''
                && current_page.endsWith('/index.html')) {
                link.classList.add('active');
                let parent = link.parentElement;
                while (parent) {
                    if (parent.tagName === 'LI' && parent.classList.contains('chapter-item')) {
                        parent.classList.add('expanded');
                    }
                    parent = parent.parentElement;
                }
            }
        }
        // Track and set sidebar scroll position
        this.addEventListener('click', e => {
            if (e.target.tagName === 'A') {
                const clientRect = e.target.getBoundingClientRect();
                const sidebarRect = this.getBoundingClientRect();
                sessionStorage.setItem('sidebar-scroll-offset', clientRect.top - sidebarRect.top);
            }
        }, { passive: true });
        const sidebarScrollOffset = sessionStorage.getItem('sidebar-scroll-offset');
        sessionStorage.removeItem('sidebar-scroll-offset');
        if (sidebarScrollOffset !== null) {
            // preserve sidebar scroll position when navigating via links within sidebar
            const activeSection = this.querySelector('.active');
            if (activeSection) {
                const clientRect = activeSection.getBoundingClientRect();
                const sidebarRect = this.getBoundingClientRect();
                const currentOffset = clientRect.top - sidebarRect.top;
                this.scrollTop += currentOffset - parseFloat(sidebarScrollOffset);
            }
        } else {
            // scroll sidebar to current active section when navigating via
            // 'next/previous chapter' buttons
            const activeSection = document.querySelector('#mdbook-sidebar .active');
            if (activeSection) {
                activeSection.scrollIntoView({ block: 'center' });
            }
        }
        // Toggle buttons
        const sidebarAnchorToggles = document.querySelectorAll('.chapter-fold-toggle');
        function toggleSection(ev) {
            ev.currentTarget.parentElement.parentElement.classList.toggle('expanded');
        }
        Array.from(sidebarAnchorToggles).forEach(el => {
            el.addEventListener('click', toggleSection);
        });
    }
}
window.customElements.define('mdbook-sidebar-scrollbox', MDBookSidebarScrollbox);


// ---------------------------------------------------------------------------
// Support for dynamically adding headers to the sidebar.

(function() {
    // This is used to detect which direction the page has scrolled since the
    // last scroll event.
    let lastKnownScrollPosition = 0;
    // This is the threshold in px from the top of the screen where it will
    // consider a header the "current" header when scrolling down.
    const defaultDownThreshold = 150;
    // Same as defaultDownThreshold, except when scrolling up.
    const defaultUpThreshold = 300;
    // The threshold is a virtual horizontal line on the screen where it
    // considers the "current" header to be above the line. The threshold is
    // modified dynamically to handle headers that are near the bottom of the
    // screen, and to slightly offset the behavior when scrolling up vs down.
    let threshold = defaultDownThreshold;
    // This is used to disable updates while scrolling. This is needed when
    // clicking the header in the sidebar, which triggers a scroll event. It
    // is somewhat finicky to detect when the scroll has finished, so this
    // uses a relatively dumb system of disabling scroll updates for a short
    // time after the click.
    let disableScroll = false;
    // Array of header elements on the page.
    let headers;
    // Array of li elements that are initially collapsed headers in the sidebar.
    // I'm not sure why eslint seems to have a false positive here.
    // eslint-disable-next-line prefer-const
    let headerToggles = [];
    // This is a debugging tool for the threshold which you can enable in the console.
    let thresholdDebug = false;

    // Updates the threshold based on the scroll position.
    function updateThreshold() {
        const scrollTop = window.pageYOffset || document.documentElement.scrollTop;
        const windowHeight = window.innerHeight;
        const documentHeight = document.documentElement.scrollHeight;

        // The number of pixels below the viewport, at most documentHeight.
        // This is used to push the threshold down to the bottom of the page
        // as the user scrolls towards the bottom.
        const pixelsBelow = Math.max(0, documentHeight - (scrollTop + windowHeight));
        // The number of pixels above the viewport, at least defaultDownThreshold.
        // Similar to pixelsBelow, this is used to push the threshold back towards
        // the top when reaching the top of the page.
        const pixelsAbove = Math.max(0, defaultDownThreshold - scrollTop);
        // How much the threshold should be offset once it gets close to the
        // bottom of the page.
        const bottomAdd = Math.max(0, windowHeight - pixelsBelow - defaultDownThreshold);
        let adjustedBottomAdd = bottomAdd;

        // Adjusts bottomAdd for a small document. The calculation above
        // assumes the document is at least twice the windowheight in size. If
        // it is less than that, then bottomAdd needs to be shrunk
        // proportional to the difference in size.
        if (documentHeight < windowHeight * 2) {
            const maxPixelsBelow = documentHeight - windowHeight;
            const t = 1 - pixelsBelow / Math.max(1, maxPixelsBelow);
            const clamp = Math.max(0, Math.min(1, t));
            adjustedBottomAdd *= clamp;
        }

        let scrollingDown = true;
        if (scrollTop < lastKnownScrollPosition) {
            scrollingDown = false;
        }

        if (scrollingDown) {
            // When scrolling down, move the threshold up towards the default
            // downwards threshold position. If near the bottom of the page,
            // adjustedBottomAdd will offset the threshold towards the bottom
            // of the page.
            const amountScrolledDown = scrollTop - lastKnownScrollPosition;
            const adjustedDefault = defaultDownThreshold + adjustedBottomAdd;
            threshold = Math.max(adjustedDefault, threshold - amountScrolledDown);
        } else {
            // When scrolling up, move the threshold down towards the default
            // upwards threshold position. If near the bottom of the page,
            // quickly transition the threshold back up where it normally
            // belongs.
            const amountScrolledUp = lastKnownScrollPosition - scrollTop;
            const adjustedDefault = defaultUpThreshold - pixelsAbove
                + Math.max(0, adjustedBottomAdd - defaultDownThreshold);
            threshold = Math.min(adjustedDefault, threshold + amountScrolledUp);
        }

        if (documentHeight <= windowHeight) {
            threshold = 0;
        }

        if (thresholdDebug) {
            const id = 'mdbook-threshold-debug-data';
            let data = document.getElementById(id);
            if (data === null) {
                data = document.createElement('div');
                data.id = id;
                data.style.cssText = `
                    position: fixed;
                    top: 50px;
                    right: 10px;
                    background-color: 0xeeeeee;
                    z-index: 9999;
                    pointer-events: none;
                `;
                document.body.appendChild(data);
            }
            data.innerHTML = `
                <table>
                  <tr><td>documentHeight</td><td>${documentHeight.toFixed(1)}</td></tr>
                  <tr><td>windowHeight</td><td>${windowHeight.toFixed(1)}</td></tr>
                  <tr><td>scrollTop</td><td>${scrollTop.toFixed(1)}</td></tr>
                  <tr><td>pixelsAbove</td><td>${pixelsAbove.toFixed(1)}</td></tr>
                  <tr><td>pixelsBelow</td><td>${pixelsBelow.toFixed(1)}</td></tr>
                  <tr><td>bottomAdd</td><td>${bottomAdd.toFixed(1)}</td></tr>
                  <tr><td>adjustedBottomAdd</td><td>${adjustedBottomAdd.toFixed(1)}</td></tr>
                  <tr><td>scrollingDown</td><td>${scrollingDown}</td></tr>
                  <tr><td>threshold</td><td>${threshold.toFixed(1)}</td></tr>
                </table>
            `;
            drawDebugLine();
        }

        lastKnownScrollPosition = scrollTop;
    }

    function drawDebugLine() {
        if (!document.body) {
            return;
        }
        const id = 'mdbook-threshold-debug-line';
        const existingLine = document.getElementById(id);
        if (existingLine) {
            existingLine.remove();
        }
        const line = document.createElement('div');
        line.id = id;
        line.style.cssText = `
            position: fixed;
            top: ${threshold}px;
            left: 0;
            width: 100vw;
            height: 2px;
            background-color: red;
            z-index: 9999;
            pointer-events: none;
        `;
        document.body.appendChild(line);
    }

    function mdbookEnableThresholdDebug() {
        thresholdDebug = true;
        updateThreshold();
        drawDebugLine();
    }

    window.mdbookEnableThresholdDebug = mdbookEnableThresholdDebug;

    // Updates which headers in the sidebar should be expanded. If the current
    // header is inside a collapsed group, then it, and all its parents should
    // be expanded.
    function updateHeaderExpanded(currentA) {
        // Add expanded to all header-item li ancestors.
        let current = currentA.parentElement;
        while (current) {
            if (current.tagName === 'LI' && current.classList.contains('header-item')) {
                current.classList.add('expanded');
            }
            current = current.parentElement;
        }
    }

    // Updates which header is marked as the "current" header in the sidebar.
    // This is done with a virtual Y threshold, where headers at or below
    // that line will be considered the current one.
    function updateCurrentHeader() {
        if (!headers || !headers.length) {
            return;
        }

        // Reset the classes, which will be rebuilt below.
        const els = document.getElementsByClassName('current-header');
        for (const el of els) {
            el.classList.remove('current-header');
        }
        for (const toggle of headerToggles) {
            toggle.classList.remove('expanded');
        }

        // Find the last header that is above the threshold.
        let lastHeader = null;
        for (const header of headers) {
            const rect = header.getBoundingClientRect();
            if (rect.top <= threshold) {
                lastHeader = header;
            } else {
                break;
            }
        }
        if (lastHeader === null) {
            lastHeader = headers[0];
            const rect = lastHeader.getBoundingClientRect();
            const windowHeight = window.innerHeight;
            if (rect.top >= windowHeight) {
                return;
            }
        }

        // Get the anchor in the summary.
        const href = '#' + lastHeader.id;
        const a = [...document.querySelectorAll('.header-in-summary')]
            .find(element => element.getAttribute('href') === href);
        if (!a) {
            return;
        }

        a.classList.add('current-header');

        updateHeaderExpanded(a);
    }

    // Updates which header is "current" based on the threshold line.
    function reloadCurrentHeader() {
        if (disableScroll) {
            return;
        }
        updateThreshold();
        updateCurrentHeader();
    }


    // When clicking on a header in the sidebar, this adjusts the threshold so
    // that it is located next to the header. This is so that header becomes
    // "current".
    function headerThresholdClick(event) {
        // See disableScroll description why this is done.
        disableScroll = true;
        setTimeout(() => {
            disableScroll = false;
        }, 100);
        // requestAnimationFrame is used to delay the update of the "current"
        // header until after the scroll is done, and the header is in the new
        // position.
        requestAnimationFrame(() => {
            requestAnimationFrame(() => {
                // Closest is needed because if it has child elements like <code>.
                const a = event.target.closest('a');
                const href = a.getAttribute('href');
                const targetId = href.substring(1);
                const targetElement = document.getElementById(targetId);
                if (targetElement) {
                    threshold = targetElement.getBoundingClientRect().bottom;
                    updateCurrentHeader();
                }
            });
        });
    }

    // Takes the nodes from the given head and copies them over to the
    // destination, along with some filtering.
    function filterHeader(source, dest) {
        const clone = source.cloneNode(true);
        clone.querySelectorAll('mark').forEach(mark => {
            mark.replaceWith(...mark.childNodes);
        });
        dest.append(...clone.childNodes);
    }

    // Scans page for headers and adds them to the sidebar.
    document.addEventListener('DOMContentLoaded', function() {
        const activeSection = document.querySelector('#mdbook-sidebar .active');
        if (activeSection === null) {
            return;
        }

        const main = document.getElementsByTagName('main')[0];
        headers = Array.from(main.querySelectorAll('h2, h3, h4, h5, h6'))
            .filter(h => h.id !== '' && h.children.length && h.children[0].tagName === 'A');

        if (headers.length === 0) {
            return;
        }

        // Build a tree of headers in the sidebar.

        const stack = [];

        const firstLevel = parseInt(headers[0].tagName.charAt(1));
        for (let i = 1; i < firstLevel; i++) {
            const ol = document.createElement('ol');
            ol.classList.add('section');
            if (stack.length > 0) {
                stack[stack.length - 1].ol.appendChild(ol);
            }
            stack.push({level: i + 1, ol: ol});
        }

        // The level where it will start folding deeply nested headers.
        const foldLevel = 3;

        for (let i = 0; i < headers.length; i++) {
            const header = headers[i];
            const level = parseInt(header.tagName.charAt(1));

            const currentLevel = stack[stack.length - 1].level;
            if (level > currentLevel) {
                // Begin nesting to this level.
                for (let nextLevel = currentLevel + 1; nextLevel <= level; nextLevel++) {
                    const ol = document.createElement('ol');
                    ol.classList.add('section');
                    const last = stack[stack.length - 1];
                    const lastChild = last.ol.lastChild;
                    // Handle the case where jumping more than one nesting
                    // level, which doesn't have a list item to place this new
                    // list inside of.
                    if (lastChild) {
                        lastChild.appendChild(ol);
                    } else {
                        last.ol.appendChild(ol);
                    }
                    stack.push({level: nextLevel, ol: ol});
                }
            } else if (level < currentLevel) {
                while (stack.length > 1 && stack[stack.length - 1].level > level) {
                    stack.pop();
                }
            }

            const li = document.createElement('li');
            li.classList.add('header-item');
            li.classList.add('expanded');
            if (level < foldLevel) {
                li.classList.add('expanded');
            }
            const span = document.createElement('span');
            span.classList.add('chapter-link-wrapper');
            const a = document.createElement('a');
            span.appendChild(a);
            a.href = '#' + header.id;
            a.classList.add('header-in-summary');
            filterHeader(header.children[0], a);
            a.addEventListener('click', headerThresholdClick);
            const nextHeader = headers[i + 1];
            if (nextHeader !== undefined) {
                const nextLevel = parseInt(nextHeader.tagName.charAt(1));
                if (nextLevel > level && level >= foldLevel) {
                    const toggle = document.createElement('a');
                    toggle.classList.add('chapter-fold-toggle');
                    toggle.classList.add('header-toggle');
                    toggle.addEventListener('click', () => {
                        li.classList.toggle('expanded');
                    });
                    const toggleDiv = document.createElement('div');
                    toggleDiv.textContent = '❱';
                    toggle.appendChild(toggleDiv);
                    span.appendChild(toggle);
                    headerToggles.push(li);
                }
            }
            li.appendChild(span);

            const currentParent = stack[stack.length - 1];
            currentParent.ol.appendChild(li);
        }

        const onThisPage = document.createElement('div');
        onThisPage.classList.add('on-this-page');
        onThisPage.append(stack[0].ol);
        const activeItemSpan = activeSection.parentElement;
        activeItemSpan.after(onThisPage);
    });

    document.addEventListener('DOMContentLoaded', reloadCurrentHeader);
    document.addEventListener('scroll', reloadCurrentHeader, { passive: true });
})();

