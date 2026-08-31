# HTTP method semantics on denied requests — implementation plan

| | |
|---|---|
| **Status** | Implemented on `fix/http-method-semantics`; §14 records what implementation changed |
| **Target** | **2.4.0** (Gökhan's call; §11 records the case for a major and why it was not taken) |
| **Written** | 2026-08-31, against released 2.3.0 |
| **Verified against** | Spring Security **7.1.0**, Spring Framework **7.0.8** (via Spring Boot 4.1.0) |

**Audience note.** This document is written to be *validated*, not just followed. Every
framework claim carries a precise citation (§3), every judgement call is a numbered decision
record with its rationale and its falsifier (§13), and §10 lists the invariants a reviewer
should try to break. If you are reviewing this: start at §0.

---

## 0. How to validate this document

Resolve the exact versions this project uses, then read the cited sources:

```bash
JAVA_HOME=/opt/openjdk-bin-17 mvn -B dependency:list \
  | grep -E "spring-security-web|spring-webmvc|spring-webflux|spring-web:jar"
# expect: spring-web 7.0.8, spring-webmvc 7.0.8, spring-webflux 7.0.8,
#         spring-security-web 7.1.0, spring-security-config 7.1.0

cd "$(mktemp -d)" && for j in \
  ~/.m2/repository/org/springframework/security/spring-security-web/7.1.0/spring-security-web-7.1.0-sources.jar \
  ~/.m2/repository/org/springframework/security/spring-security-config/7.1.0/spring-security-config-7.1.0-sources.jar \
  ~/.m2/repository/org/springframework/spring-webmvc/7.0.8/spring-webmvc-7.0.8-sources.jar \
  ~/.m2/repository/org/springframework/spring-webflux/7.0.8/spring-webflux-7.0.8-sources.jar \
  ~/.m2/repository/org/springframework/spring-web/7.0.8/spring-web-7.0.8-sources.jar ; do unzip -oq "$j"; done
```

Line numbers below refer to those source jars. They are exact for these versions and will
drift on upgrade; the class and method names are the durable part.

**The single strongest validation** is the differential test in §9.2: for the same path and
verb, what this library emits on a denied request must be **identical** to what the service
itself emits when the ACL permits the request and Spring produces the 405 natively. If those
two ever disagree, this design is wrong. Everything in §5 exists to make them agree.

---

## 1. Problem and scope

QA on `dnms-681` called `PUT /dnms/681/v1/communicationMessage/{id}`. TMF-681 defines no PUT,
the service implements none, and the OAS declares only get/patch/delete on that path. They
received **403** and argued for **405**. Investigating produced three findings in one family.

| # | Item | Nature | Property-gated? |
|---|------|--------|-----------------|
| 1 | `HEAD` is denied on `GET`-listed endpoints | Defect | No — settled structurally by D8 |
| 2 | Known path + unimplemented verb answers 403, not 405 | Semantics change | Property exists; **default is 405** (D9) |
| 3 | `OPTIONS` handling, incl. CORS preflight | Part defect, part documentation | Rides item 2 |
| 4 | `Endpoint.method` accepts verbs that must not be configurable | Defect + API restriction | No — breaking, accepted (D8) |

All three land on **both stacks** (servlet + reactive) and **both sections**
(`opentmf.security.*` and `opentmf.security.management.*`), per this repository's parity
rule. `dnms-681` needs no consumer action; it is under a release freeze and this was never
its fix to make.

---

## 2. D1 — The ruling: the controller is the contract

**Decision (Gökhan, 2026-08-31): the controller is the authoritative contract. A denied
request for a verb the code does not implement must answer 405 with an `Allow` header.**

His reasoning, recorded because it drives every design choice below:

> The ACL is *deployment configuration*. A deployer can forget to add endpoints that exist,
> or list endpoints that do not. The reality is the code itself — hence the controller.

This overrules the position argued earlier in the thread — that the ACL is the contract, so
403 is honest and QA's 405 a category error. It overrules it by attacking that position's
**premise**, which is why the conclusion flips cleanly rather than being merely overridden:

> The earlier objection was that a controller-derived `Allow` "would lie", advertising verbs
> the ACL denies. **Under D1 that objection dissolves.** RFC 9110 defines `Allow` as the
> methods supported by the *target resource*, not the methods this caller may invoke. A verb
> the code implements but the ACL closes *is* supported by the resource; a caller who tries
> it gets **403**, an authorization answer, while a verb the code does not implement gets
> **405**, an existence answer. Two questions, two answers, no contradiction.
>
> What does *not* dissolve is the engineering cost of reaching the controller layer from
> inside a security filter. §5.3 addresses it; D4 picks the approach that avoids the worst
> of it.

**Nothing is being reversed.** The uniform 403 was only ever *half* intentional: the
deny-by-default posture is designed and documented — `otherEndpoints` defaults to `DENY`
with the javadoc "preserves the historical hard-coded behavior"
(`OpenTmfSecurityProperties.java:116`) — but the **403 status** is a side effect of
`anyRequest().denyAll()`. No one ever ruled that an unimplemented verb should read as 403. A
gap is being filled, not a decision revisited.

### 2.1 How the two layers separate after this change

This table is the specification. A reviewer should try to find a case it does not cover.

| # | Code implements the verb? | ACL permits it? | Path served by any controller? | Answer | Why |
|---|---|---|---|---|---|
| A | yes | yes | yes | normal response | unchanged |
| B | yes | **no** | yes | **403** | Authorization. The deployer closed it — deliberately or by mistake, and those are indistinguishable. |
| C | **no** | no | yes (other verbs) | **405** + `Allow` | The resource exists; the verb does not. This is QA's case. |
| D | n/a | no | **no** | **403** | Deny-by-default, untouched. |
| E | no | **yes** | no controller for that verb | **405 from Spring itself** | Already correct today: the ACL permits it, the request reaches the dispatcher, Spring answers natively. No security involvement. |
| F | any | path is `blacklist`ed | any | **403** | Explicit close-off wins; see D5. |
| G | any | no | any, **caller unauthenticated** | **401** | Hard constraint; see D6. |

Rows **B** and **E** are the two failure modes D1 names. E already works. B stays 403 by
design — that is the load-bearing part of the design and the easiest thing to get wrong.

---

## 3. Verified mechanics

### 3.1 The chain as it exists today

`ServletSecurityAutoConfiguration.applyOpenTmfSecurityDefinitions` registers, in order:

1. `blacklist` → `denyAll()` (path-only, no method)
2. `whitelist` → `permitAll()` (path-only, no method)
3. `allowedEndpoints` → `permitAll()` via `requestMatchers(method, path)`
4. `secureEndpoints` → `hasAnyAuthority(roles)` via `requestMatchers(method, path)`
5. `configureOtherEndpoints` → `anyRequest()` → `permitAll` / `denyAll` / `authenticated`

`ReactiveSecurityAutoConfiguration` and both management configurations
(`ServletManagementSecurityAutoConfiguration`, `ReactiveManagementSecurityAutoConfiguration`)
are structurally identical, using `pathMatchers(method, path)` and `anyExchange()`.

Defaults: main `otherEndpoints = DENY` (`OpenTmfSecurityProperties.java:116`); management
`otherEndpoints = AUTHENTICATED` (`:219`).

So an unmatched `(method, path)` falls to `anyRequest().denyAll()` → `AccessDeniedException`
→ 403 with a token, 401 without. Spring's own 405 path is unreachable because
`AuthorizationFilter` runs before `DispatcherServlet`.

### 3.2 Structural fact: every ACL entry is method-scoped

`Endpoint.method` is `@NotNull` (`model/Endpoint.java`). There is **no** way to write a
method-agnostic entry in `allowed-endpoints` or `secure-endpoints`, in either section. Only
`whitelist`/`blacklist` are path-only. The method-scoping is the shape of the model, not an
oversight in one code path.

Its **type**, however, is Spring's `HttpMethod`, which admits every verb including HEAD,
OPTIONS, TRACE and CONNECT. D8 restricts it.

### 3.3 HEAD: the framework serves it, this library denies it

| Claim | Where |
|---|---|
| A `GET` matcher does not match `HEAD` (servlet) | `PathPatternRequestMatcher$HttpMethodRequestMatcher.matches` — `this.method.name().equals(request.getMethod())`, an exact string compare |
| Same on reactive | `PathPatternParserServerWebExchangeMatcher.matches` — `this.method != null && !this.method.equals(request.getMethod())` |
| Spring MVC maps HEAD onto the GET handler | `web.servlet.mvc.condition.RequestMethodsRequestCondition.matchRequestMethod`, **line 162**: `requestMethod.equals(RequestMethod.HEAD) && getMethods().contains(RequestMethod.GET)` |
| WebFlux does the same | `web.reactive.result.condition.RequestMethodsRequestCondition.matchRequestMethod`, **line 157** |

Consequence: every HEAD probe against a GET-listed endpoint is a 403 today — monitoring
agents, reverse proxies, health-checkers, link-checkers. Independent of D1.

### 3.3.1 Authorization rules are first-match-wins

`RequestMatcherDelegatingAuthorizationManager.authorize` (**lines 72-82**) iterates the
registered mappings in order and `return`s on the **first** matcher that matches. Later rules
for the same `(method, path)` are unreachable. This is what makes D8 necessary rather than
merely tidy — see §4.2.

### 3.4 An empty methods condition matches every verb except OPTIONS

`RequestMethodsRequestCondition.getMatchingCondition` (webmvc, **lines 126-141**):

```java
if (getMethods().isEmpty()) {
    if (RequestMethod.OPTIONS.name().equals(request.getMethod()) && !DispatcherType.ERROR.equals(...)) {
        return null; // We handle OPTIONS transparently, so don't match if no explicit declarations
    }
    return this;
}
return matchRequestMethod(request.getMethod());
```

So a `@RequestMapping` with no `method` accepts **every** verb. This drives the abort rule in
§5.4 and is easy to miss.

### 3.5 How Spring itself computes the `Allow` header — the specification we must match

This is the most important subsection in the document. **Spring's 405 `Allow` and its
OPTIONS `Allow` are computed differently**, and any implementation that treats them alike is
wrong.

`RequestMappingInfoHandlerMapping.handleNoMatch` (webmvc **lines 241-261**, webflux
**lines 174-196**):

```java
PartialMatchHelper helper = new PartialMatchHelper(infos, request);
if (helper.isEmpty()) { return null; }              // no controller serves this path
if (helper.hasMethodsMismatch()) {
    Set<String> methods = helper.getAllowedMethods();
    if (HttpMethod.OPTIONS.matches(request.getMethod())) {
        return new HandlerMethod(new HttpOptionsHandler(methods, ...), HTTP_OPTIONS_HANDLE_METHOD);
    }
    throw new HttpRequestMethodNotSupportedException(request.getMethod(), methods);
}
```

**What counts as "this path is served"** — `PartialMatchHelper`'s constructor (webmvc
**line 299**, webflux **line 235**):

```java
for (RequestMappingInfo info : infos) {
    if (info.getActivePatternsCondition().getMatchingCondition(request) != null) {   // webmvc
    // if (info.getPatternsCondition().getMatchingCondition(exchange) != null)       // webflux
        this.partialMatches.add(new PartialMatch(info, request));
    }
}
```

`RequestMappingInfo.getActivePatternsCondition()` is **public** (webmvc line 249). Using it
means we never have to choose between `getPathPatternsCondition()` (which is `@Nullable`) and
the legacy condition — "active" resolves that for us.

**The declared method set** — `PartialMatchHelper.getAllowedMethods()` (webmvc **line 365**,
webflux **line 281**): the union of `info.getMethodsCondition().getMethods()` across every
partial match. **No HEAD expansion. No OPTIONS.** That raw set becomes the 405 `Allow`.

**The OPTIONS method set** — `HttpOptionsHandler.initAllowedHttpMethods` (webmvc **line 509**,
webflux **line 408**):

```java
if (declaredMethods.isEmpty()) {
    return every HttpMethod except TRACE;
} else {
    result = new LinkedHashSet<>(declaredMethods);
    if (result.contains(GET)) { result.add(HEAD); }
    result.add(OPTIONS);
    return result;
}
```

⚠ **This corrects an earlier draft of this plan**, which said to add HEAD wherever GET is
present when building the 405 `Allow`. That is wrong: Spring's 405 `Allow` does **not**
include HEAD. Adding it would mean two 405s from the same service — one from security, one
from Spring on a permitted path — carrying different `Allow` headers, which is exactly the
inconsistency §0's differential test exists to catch.

**Ordering:** webmvc collects into a `LinkedHashSet`, webflux into `Collectors.toSet()` (a
`HashSet`). `Allow` header **order is not deterministic** — compare as sets in tests, never
as strings (§9.2).

### 3.6 Pattern matching requires a parsed request path

`PathPatternsRequestCondition.getMatchingCondition` (webmvc **line 191**) begins:

```java
PathContainer path = ServletRequestPathUtils.getParsedRequestPath(request).pathWithinApplication();
```

and `ServletRequestPathUtils.getParsedRequestPath` (spring-web **line 79-83**) asserts the
attribute is present. `DispatcherServlet` caches it — but that happens *after* the filter
chain, so inside an `AccessDeniedHandler` it is **absent**.

Spring Security solves the same problem in `PathPatternRequestMatcher.getPathContainer`
(**lines 147-158**) and this is the precedent to copy exactly:

```java
if (ServletRequestPathUtils.hasParsedRequestPath(request)) {
    path = ServletRequestPathUtils.getParsedRequestPath(request);
} else {
    path = ServletRequestPathUtils.parseAndCache(request);
    ServletRequestPathUtils.clearParsedRequestPath(request);   // leave no trace
}
```

Reactive needs none of this: `exchange.getRequest().getPath()` is always available.

### 3.7 OPTIONS and CORS — corrects an earlier claim

An earlier read in this thread said `.cors(withDefaults())` "configures nothing" without a
`CorsConfigurationSource` bean. **That is wrong on the servlet stack**, and the correction
changes what the OPTIONS symptom actually is.

**Servlet.** `CorsConfigurer.getCorsFilter` falls back to
`MvcCorsFilter.getMvcCorsConfigurationSource`, which returns the `mvcHandlerMappingIntrospector`
bean present in any Boot MVC app — so a `CorsFilter` **is** installed. Then:

- `CorsFilter.doFilterInternal` (spring-web) ends with
  `if (!isValid || CorsUtils.isPreFlightRequest(request)) { return; }` — **a preflight never
  continues the filter chain** and so never reaches the security ACL.
- `DefaultCorsProcessor.processRequest` returns `true` immediately when `config == null`,
  writing nothing to the response.

⇒ A **real preflight** (`OPTIONS` + `Origin` + `Access-Control-Request-Method`) against a
service with no CORS configuration gets a bare **200 with no CORS headers**, which the
browser then fails. Not a 403, and not an ACL problem.

⇒ A **bare `OPTIONS`** (no `Origin`) is not a preflight, passes the `CorsFilter`, reaches the
ACL and hits `denyAll()` → **403**. This is the case `dnms-681` measured, and it is in the
same family as HEAD and PUT: Spring would have answered it via `HttpOptionsHandler` (§3.5).

**Reactive.** `ServerHttpSecurity.CorsSpec.getCorsFilter()` returns `null` when no
`CorsConfigurationSource` bean exists and **no filter is added at all** — WebFlux does CORS
inside `AbstractHandlerMapping`, i.e. *after* security. So on WebFlux a preflight **does**
reach the ACL and **does** get 403.

⚠ **Genuine cross-stack divergence**, to be documented rather than papered over: the same
deployment answers a preflight with 200-and-no-headers on servlet and 403 on reactive.

**Limitation to state plainly in the README:** this library can stop the 403; it **cannot
make CORS work**. A browser needs `Access-Control-Allow-Origin`, which requires the service
to supply a `CorsConfigurationSource` bean or MVC `addCorsMappings`. Answering OPTIONS from
the controller layer is not a CORS feature and must not be sold as one.

---

## 4. Items 1 and 4 — HEAD follows GET, over a restricted verb set

### 4.1 The change

When expanding `allowedEndpoints` / `secureEndpoints`, an entry whose method is `GET`
registers its rule for **both** `GET` and `HEAD`, with identical authorization (`permitAll`,
or the same `hasAnyAuthority(roles)`).

```java
private static HttpMethod[] methodsFor(Endpoint endpoint) {
  return EndpointMethod.GET == endpoint.getMethod()
      ? new HttpMethod[] {HttpMethod.GET, HttpMethod.HEAD}
      : new HttpMethod[] {endpoint.getMethod().toHttpMethod()};
}
```

Applied in all four configuration classes (servlet/reactive × main/management).

### 4.2 D8 — `Endpoint.method` becomes a restricted enum

**Decision (Gökhan, 2026-08-31): replace Spring's `HttpMethod` on `Endpoint.method` with a
restricted `EndpointMethod` enum — `GET`, `POST`, `PUT`, `PATCH`, `DELETE`. Nothing else is
configurable.**

```java
public enum EndpointMethod {
  GET, POST, PUT, PATCH, DELETE;
  public HttpMethod toHttpMethod() { return HttpMethod.valueOf(name()); }
}
```

**Rationale — it fixes a defect, it is not only tidying.** With `HttpMethod`, a deployer can
write both `GET /x roles=[A]` and `HEAD /x roles=[B]`. §4.1 would then register `GET→A`,
`HEAD→A`, and finally the deployer's `HEAD→B`. Because authorization is first-match-wins
(§3.3.1), the auto-registered `HEAD→A` **silently shadows** the explicit `HEAD→B`: a
deliberate configuration line stops taking effect, with no error and no log. The only
alternative fix is to detect the conflict, which means reasoning about *overlapping path
patterns* rather than equal strings — precisely the kind of logic that goes subtly wrong.
D8 removes the case by construction.

Three further reasons, in descending weight:

- **TRACE must not be configurable.** It echoes the request back for debugging and is a
  Cross-Site Tracing (XST) vector; it is disabled by default in most containers and stripped
  by most proxies. Spring itself excludes TRACE from the OPTIONS `Allow` set
  (`HttpOptionsHandler.initAllowedHttpMethods`, §3.5). There is no legitimate ACL use.
- **OPTIONS never needs an ACL entry.** CORS preflight is answered before security reaches
  it when CORS is configured, and when it is not configured an ACL entry cannot help, because
  the browser needs `Access-Control-Allow-Origin` headers no ACL can produce (§3.7). Bare
  OPTIONS is answered from the controller layer by item 2.
- **Config metadata.** Spring's `HttpMethod` is a `final class`, not an enum
  (`spring-web`, `HttpMethod.java` line 34), so Boot's configuration-metadata generator emits
  no value hints and `method:` gets no IDE completion. A real enum yields completion over
  exactly five values, making the constraint self-documenting rather than something a
  deployer discovers at boot.

**Breaking change, accepted.** Any existing config carrying `method: HEAD`, `OPTIONS`,
`TRACE` or `CONNECT` will **fail to bind at startup**. Gökhan, 2026-08-31: *"YES, let them
fail."*

⚠ **Who this hits, so the migration note can be written for them.** The population most
likely to hold such entries is exactly the population bitten by the bugs this release fixes:
someone who added explicit `HEAD` entries because HEAD was returning 403 (§3.3), or `OPTIONS`
entries because preflight was returning 403 on the reactive stack (§3.7). The CHANGELOG and
README migration note must address them directly — *delete the HEAD entries, they are now
automatic; delete the OPTIONS entries and configure CORS instead.*

**Capabilities genuinely lost**, stated rather than buried:

1. **A HEAD-only entry** — permitting existence probing without permitting GET. Exotic, and
   never a clean separation anyway, since the framework serves HEAD from the GET handler.
2. **Permitting bare OPTIONS when `unmatched-method-response: DENY`.** Previously an OPTIONS
   ACL entry could do it; now nothing can. Under D9's default this does not arise, because
   the default answers bare OPTIONS from the controller layer — it only bites a deployment
   that has explicitly opted back to `DENY`.

### 4.3 D2 — resolved by D8, no longer a decision

D2 asked whether HEAD-follows-GET should be property-gated. It was previously answered
"no, recommended" on the grounds that the widening is harmless. **D8 settles it
structurally**: with HEAD unconfigurable there is no competing interpretation to protect and
no explicit rule to shadow, so registering HEAD alongside GET is the only possible semantics
rather than a choice between two. No `head-follows-get` property is needed, and none should
be added.

HEAD against a path listed only for POST stays denied, correctly — that is an item-2 case and
answers 405.

## 5. Item 2 — 405 with a controller-derived `Allow`

### 5.1 The algorithm

On a denial, and only on a denial (§5.6):

```
 1. if request path matches any `blacklist` entry            -> 403 (D5)
 2. supported := supportedMethods(request)                    // §5.3
 3. if supported.pathUnknown                                  -> 403        (row D)
 4. if supported.acceptsAnyMethod && method != OPTIONS        -> 403        (§3.4)
 5. if supported.declared.contains(request.method)            -> 403        (row B)
 6. if request.method == OPTIONS                              -> 200, Allow = optionsAllow(declared)
 7. otherwise                                                 -> 405, Allow = declared
```

where, reproducing §3.5 exactly:

```
optionsAllow(declared) =
    declared.isEmpty() ? (all HttpMethod values except TRACE)
                       : declared + (declared.contains(GET) ? {HEAD} : {}) + {OPTIONS}
```

Step 5 is row **B** of §2.1 and is the load-bearing rule: a verb the code implements but the
ACL closes stays a **403**. Step 7's `declared` is the raw set — **no HEAD, no OPTIONS** —
because that is what Spring's own 405 emits (§3.5).

### 5.2 Invariant

> **The response this library produces on a denied request must be indistinguishable from
> the response the service itself would produce for the same request if the ACL had
> permitted it and Spring had answered natively** — same status, same `Allow` set.

Everything in §5.3–§5.5 exists to hold this invariant. §9.2 tests it directly.

### 5.3 D4 — Reading supported verbs from the controller layer

**Decision:** iterate `RequestMappingHandlerMapping.getHandlerMethods()` and reuse Spring's
own condition objects for matching. **Do not call `getHandler(request)`.**

**Rejected: `getHandler(request)` + catch the exception.** The obvious approach, and worse:

- `AbstractHandlerMapping.getHandler` runs `initLookupPath`, builds the interceptor chain and
  resolves CORS configuration — all on a request that will never be dispatched.
- It needs a parsed `RequestPath` that is absent inside the filter chain (§3.6), and it
  caches one without clearing it.
- The signal differs per stack — `HttpRequestMethodNotSupportedException` (servlet) vs
  `MethodNotAllowedException` (reactive) — and on **both** stacks OPTIONS returns a
  `HandlerMethod` wrapping a package-private `HttpOptionsHandler` instead of throwing, so the
  OPTIONS branch would need reflection to extract its `Allow`.

**Chosen shape** (servlet; reactive is symmetric with `exchange` and
`getPatternsCondition()`):

```java
Result supportedMethods(HttpServletRequest request) {
  RequestMappingHandlerMapping mapping = this.mappingProvider.getIfAvailable();
  if (mapping == null) {
    return Result.pathUnknown();                       // graceful degradation
  }
  boolean parsedHere = !ServletRequestPathUtils.hasParsedRequestPath(request);
  if (parsedHere) {
    ServletRequestPathUtils.parseAndCache(request);     // §3.6, mirrors Spring Security
  }
  try {
    Set<HttpMethod> declared = new LinkedHashSet<>();
    boolean matchedAnyPath = false;
    boolean acceptsAnyMethod = false;
    for (RequestMappingInfo info : this.infos.get()) {  // §5.4 cached snapshot
      if (info.getActivePatternsCondition().getMatchingCondition(request) == null) {
        continue;                                       // path does not match
      }
      matchedAnyPath = true;
      Set<RequestMethod> methods = info.getMethodsCondition().getMethods();
      if (methods.isEmpty()) {
        acceptsAnyMethod = true;                        // §3.4
      }
      methods.forEach(m -> declared.add(HttpMethod.valueOf(m.name())));
    }
    return matchedAnyPath ? Result.of(declared, acceptsAnyMethod) : Result.pathUnknown();
  } finally {
    if (parsedHere) {
      ServletRequestPathUtils.clearParsedRequestPath(request);
    }
  }
}
```

Two things make this faithful rather than a re-implementation:

- **Path matching is Spring's own.** `info.getActivePatternsCondition().getMatchingCondition(request)`
  is the *identical* call `PartialMatchHelper`'s constructor makes (§3.5). No pattern syntax,
  context-path or trailing-slash semantics can drift, because none of it is ours.
- **The method union is Spring's own.** The loop body reproduces
  `PartialMatchHelper.getAllowedMethods()` line for line.

**Coverage limits, to be documented in the README.** Only annotation-based controllers
contribute. Functional routing (`RouterFunction`), resource handlers and any other
`HandlerMapping` are invisible, so a path served only that way keeps answering 403. If no
`RequestMappingHandlerMapping` bean exists, the feature degrades silently to today's
behaviour — hence `ObjectProvider`, not a hard dependency.

⚠ **Resolve the `ObjectProvider` lazily, never at filter-chain construction time.** Forcing
`RequestMappingHandlerMapping` to initialize while the `SecurityFilterChain` bean is being
built risks initializing MVC infrastructure too early, which has historically produced
subtle breakage (the same class of problem as `HandlerMappingIntrospector` early-init). The
first resolution must happen on the first denial, long after context refresh.

### 5.4 D3 — Cache the `RequestMappingInfo` snapshot, lazily

**Decision (Gökhan, 2026-08-31): build the lazy cache.**

`getHandlerMethods()` acquires a read lock and builds a fresh map on every call. Denials are
rare but can be attacker-driven, so recomputing per denied request hands a flood of 403s a
cost multiplier.

**Cache the snapshot, not a derived index:**

```java
private final Supplier<Set<RequestMappingInfo>> infos = SingletonSupplier.of(() -> {
  RequestMappingHandlerMapping mapping = this.mappingProvider.getIfAvailable();
  return (mapping != null) ? Set.copyOf(mapping.getHandlerMethods().keySet()) : Set.of();
});
```

`org.springframework.util.function.SingletonSupplier` gives thread-safe, once-only
initialization with no double-checked-locking to get wrong.

**Why the snapshot and not a precomputed `pattern -> methods` index:** an index would force
us to do our own `PathPattern` matching, which is precisely the drift D4 avoids. Caching
`Set<RequestMappingInfo>` removes the expensive map construction while leaving
`getActivePatternsCondition().getMatchingCondition(request)` — Spring's own matcher — on the
per-request path. The per-denial cost becomes O(number of mappings) condition evaluations,
paid only on a denial.

**Accepted consequence:** mappings registered dynamically after first use are not reflected.
This is vanishingly rare in these services and gets a javadoc line. **Falsifier:** if any
consumer registers mappings at runtime, switch to recomputing per denial (always correct,
just costlier under a 403 flood).

### 5.5 D5 — Blacklisted paths always answer 403

**Decision:** if the request path matches a `blacklist` entry, emit 403 with no `Allow`,
regardless of the property.

**Rationale.** The deployer explicitly closed that path. Answering uniformly discloses
nothing about what the code does or does not implement there. This is the one place the ACL
still participates in the response, and it is a **disclosure** choice, not a correctness one
— under D1, a 405 there would be semantically defensible. Uniformity is easier to explain
and matches deployer intent.

Note this rule requires path-only matching against the blacklist. Reuse the same
`PathPatternRequestMatcher.Builder` the registry uses — obtained from the `ApplicationContext`
the way `AbstractRequestMatcherRegistry` does (it holds a `PathPatternRequestMatcher.Builder`,
line 57, sourced from the context at line 159) — so blacklist matching here cannot diverge
from blacklist matching in the chain.

### 5.6 D6 — Hard constraint: never on the `AuthenticationEntryPoint` path

**Decision:** the 405/OPTIONS branch applies **only** to the `AccessDeniedHandler`
(servlet) / `ServerAccessDeniedHandler` (reactive) path. An anonymous request keeps
answering **401**, never 405.

**Rationale.** If an unauthenticated caller can obtain a 405 with an `Allow` header, the
deployed application's method surface becomes enumerable **without a token**, and the
disclosure argument in §5.7 — which rests entirely on the caller already being authenticated
— stops holding. This is the constraint most likely to be lost in a refactor; §9.1 tests it.

The authorization **decision is never changed** anywhere in this design. The request is
already denied and still never reaches a controller. Only the status line and one header
differ.

### 5.7 Consequences accepted deliberately

- **`Allow` reveals verbs the ACL denies.** A deployment that closes DELETE while the code
  implements it will advertise `Allow: GET, PATCH, DELETE` on a 405 for some other verb.
  Correct under D1 — `Allow` describes the resource — and the residual disclosure is bounded:
  the 405 is reachable only by an authenticated caller (D6), who can already read the OAS at
  `GET /openapi/**`.
- **`Allow` is not intersected with the caller's granted authorities, and must not be.**
  405 describes the *resource*, not the *principal*. Intersecting would make the response
  vary by caller and re-open the question D6 closes.
- **A path in the ACL with no controller behind it produces no spurious 405** — it is
  permitted by the ACL, reaches the dispatcher, and Spring answers 405 natively (row E). An
  earlier ACL-derived design had this as a caveat; D1 removes it.

### 5.8 D7 — The library owns the 405 response

**Decision (Gökhan, 2026-08-31): option (a) — when the 405/OPTIONS case matches, this
library writes the response and a consumer-supplied `AccessDeniedHandler` is not invoked.**

2.2.0 lets consumers publish their own `AccessDeniedHandler` (resolved via
`UniqueBeanResolver`), and the dnms template is heading toward ProblemDetail handlers. The
405 branch must compose with that. The options were:

| | Approach | Verdict |
|---|---|---|
| **(a)** | Library writes status + `Allow`, no body (matching Spring's own bodiless 405); consumer handler not invoked | **Chosen.** Simple, predictable, never inconsistent |
| (b) | Wrap the response to pin the status at 405 while the consumer renders the body | Rejected — a ProblemDetail body would carry `"status": 403` under a 405 status line |
| (c) | Delegate with a typed `AccessDeniedException` subclass the consumer can `instanceof`-check | Rejected — a handler that does not know the type hardcodes 403 and silently defeats the feature |

**Document plainly:** "when `unmatched-method-response` is `METHOD_NOT_ALLOWED`, a matched
request bypasses a consumer-supplied `AccessDeniedHandler`."

The decorator must still delegate to the wrapped handler for **every** non-matching denial,
so rows B, D, F and G of §2.1 keep whatever behaviour the consumer configured.

⚠ **D9 raises the stakes on this decision.** D7 was easy to accept while the feature was
opt-in. With `METHOD_NOT_ALLOWED` as the default, a bodiless 405 (D7a) becomes what **every**
consumer gets by default, including services whose every other error is a ProblemDetail.
That inconsistency is accepted deliberately — see §5.8.1.

### 5.8.1 D7a — the 405 carries no body

**Decision (Gökhan, 2026-08-31): option (i) — `setStatus(405)` plus the `Allow` header, no
response body.**

Note that §5.2's invariant is scoped to **status and `Allow`**, not the body, so this choice
does not weaken it. For the record, the alternatives and why they lost:

| | Approach | Verdict |
|---|---|---|
| **(i)** | `setStatus(405)` + `Allow`, no body | **Chosen.** Fully under our control, identical on both stacks, nothing container-dependent |
| (ii) | Set `Allow`, then `response.sendError(405)` so the container's error dispatch renders Boot's normal error body | Rejected — `sendError` clears the buffer and `Allow` header retention is implementation-dependent, so it would need per-container verification on Tomcat and Netty and could silently drop the header |
| (iii) | Write a minimal `ProblemDetail` ourselves | Rejected — hard-codes a body format the consumer may not use |

**Known consequence, to be documented in the README.** In a Boot application Spring's own 405
*is* rendered through the error machinery and does carry a body, so a service whose other
errors are ProblemDetail will emit a bodiless 405 here. That inconsistency is accepted in
exchange for a response that is predictable and container-independent. A consumer who needs a
body can set `unmatched-method-response: DENY` and keep their own `AccessDeniedHandler`'s
403, or ask for a dedicated handler bean in a later release.

## 6. Item 3 — OPTIONS

Falls out of §5.1 step 6 with no extra machinery: bare `OPTIONS` on a served path answers
**200** with `Allow` computed by `optionsAllow(declared)`, reproducing Spring's
`HttpOptionsHandler` (§3.5) including its HEAD-for-GET expansion and the
empty-declared-methods case.

CORS preflight is **out of scope and must be documented as such** (§3.7): on servlet it never
reaches security at all, and on neither stack can this library produce the CORS response
headers a browser requires.

---

## 7. Property surface

```yaml
opentmf:
  security:
    unmatched-method-response: METHOD_NOT_ALLOWED   # default | DENY
    management:
      unmatched-method-response: METHOD_NOT_ALLOWED # default | DENY
```

New enum: `org.opentmf.security.model.UnmatchedMethodResponse` — `METHOD_NOT_ALLOWED`
(default) and `DENY`.

- **Enum, not boolean** — consistent with `OtherEndpoints`, and leaves room for a third mode.
- **Symmetric name and symmetric default across both sections.** The two sections diverge on
  `other-endpoints` for a stated reason; there is no such reason here, so they match.
- **`DENY` remains** as the opt-out for a deployment that wants the pre-2.4.0 uniform 403 —
  a compliance posture that declines to advertise its method surface, or a consumer with 403
  assertions it cannot change quickly.

### D9 — the default is `METHOD_NOT_ALLOWED`, not `DENY`

**Decision (Gökhan, 2026-08-31): default to 405.**

**Rationale — this is the completion of D1, not a separate risk.** D1 rules that deployment
configuration must not determine the contract. Row **E** of §2.1 already returns 405
natively today, whenever the ACL happens to permit a path the code does not serve for that
verb. So keeping `DENY` as the default would let an *ACL accident* decide the status code for
one and the same semantic situation: list the path and the caller gets 405 from Spring, omit
it and the caller gets 403 from us. That is exactly the coupling D1 rejects. Defaulting to
405 makes the answer depend only on the code, which is what D1 says it should depend on.

A secondary argument: making the correct answer opt-in means every consumer must set the
property to get correct behaviour, which is a poor default by construction.

**Consequences accepted knowingly:**

1. **Observable change for every consumer on upgrade.** Anything asserting 403 — a test, an
   alert, a dashboard keyed on 403 rates — changes. This is a headline CHANGELOG item, not a
   footnote.
2. **Disclosure becomes the default.** Every deployment now advertises its code's method
   surface to authenticated callers without opting in. Correct under D1 and bounded by D6
   (never anonymous) and by the OAS already being readable, but it is a change in what a
   service reveals by default, and `DENY` exists for deployments that decline it.
3. **D7 becomes default-on** — see the warning in §5.8 and the open question in §5.8.1.

**Falsifier.** If a consumer demonstrates a caller that treats 403 and 405 differently in a
way that breaks on upgrade, that is an argument for a slower rollout, not for changing the
default back — the default is correct; the rollout is a release-management question.

## 8. Implementation steps

1. **`model/EndpointMethod.java`** (new) — the restricted enum from D8, with
   `toHttpMethod()`. Change `Endpoint.method` to this type. Grep the whole tree for
   `HttpMethod` on the properties path; the `@NotNull` stays.
2. **`model/UnmatchedMethodResponse.java`** — new enum, javadoc'd in the house style
   (`OtherEndpoints` is the model to follow), defaulting to `METHOD_NOT_ALLOWED` (D9).
3. **`model/OpenTmfSecurityProperties.java`** — add the field to the outer class and to the
   nested `Management` class, both defaulting to `METHOD_NOT_ALLOWED`, both javadoc'd.
4. **`config/EndpointMethods.java`** (new, package-private) — `methodsFor(Endpoint)` for
   item 1, and the blacklist path matchers for D5, built from the context's
   `PathPatternRequestMatcher.Builder`.
5. **`config/ServletSupportedMethodsResolver.java`** / **`config/ReactiveSupportedMethodsResolver.java`**
   (new) — §5.3 and §5.4. Each holds an `ObjectProvider<RequestMappingHandlerMapping>` plus
   the `SingletonSupplier` snapshot and answers a small result type carrying
   `declared` / `pathUnknown` / `acceptsAnyMethod`.
6. **`config/MethodNotAllowedAccessDeniedHandler.java`** / **`config/MethodNotAllowedServerAccessDeniedHandler.java`**
   (new) — the §5.1 algorithm and D7's response writing, decorating the effective handler.
7. **Wire item 1** into all four configuration classes.
8. **Wire item 2's decorator** into the `exceptionHandling` **and** `oauth2ResourceServer`
   denied-handler slots in each of the four, so a bearer-token-path denial behaves
   identically to an `ExceptionTranslationFilter` denial. 2.2.0 established that both slots
   must be set together; failing to do so here would make behaviour depend on *why* the
   request was denied.
9. **README** — an "HTTP method semantics" section covering HEAD-follows-GET, the property,
   the D1 rationale, the §5.7 consequences, the §5.3 coverage limits, D7's handler bypass,
   the CORS limitation and the servlet/reactive preflight divergence (§3.7).

`Endpoint.method`'s type change (D8) is the one deliberate break. Nothing else in the public
API may change shape: consumers are on 2.3.0 and every other constructor and bean signature
stays as it is.

---

## 9. Test plan

Follow existing naming (`Servlet*IT` / `Reactive*IT`, `Management*IT`) and mint tokens with
`TestIssuer`. The test controllers need: a path serving GET+PATCH but not PUT; a path served
only by POST; and a path with a method-less `@RequestMapping`.

### 9.1 Behavioural matrix

One test per row of §2.1, on each stack, in `ServletMethodSemanticsIT` /
`ReactiveMethodSemanticsIT`:

| Case | Setup | Expected |
|---|---|---|
| Item 1 | `HEAD` on a `GET`-listed secure endpoint, valid role | **200** (was 403) |
| Item 1 | same, token lacking the role | **403** |
| Item 1 | same, anonymous | **401** |
| Row C | `PUT` on a GET/PATCH path, property **unset** | **405**, `Allow` = {GET, PATCH} — proves D9's default |
| Opt-out | same, `unmatched-method-response: DENY` | **403**, no `Allow` — proves the escape hatch |
| **Row B** | verb the code implements, omitted from the ACL, default property | **403**, no `Allow` — *the most important test here* |
| Row G | anonymous `PUT`, default property | **401**, never 405 (D6) |
| Row F | path in `blacklist`, both property values | **403**, no `Allow` (D5) |
| Row D | path no controller serves, default property | **403** (deny-by-default intact) |
| §3.4 | path with a method-less `@RequestMapping`, default property | **403** (acceptsAnyMethod abort) |
| Item 3 | bare `OPTIONS` on a served path, default property | **200**, `Allow` = {GET, HEAD, PATCH, OPTIONS} |
| D7 | consumer `AccessDeniedHandler` present + row C | library's 405, consumer handler **not** invoked |
| D8 | config with `method: HEAD` (or `OPTIONS`, `TRACE`) | context **fails to start**, message names the property |
| D7 | consumer `AccessDeniedHandler` present + row B | consumer's 403 body, handler **is** invoked |
| D7a | row C response body | **empty**; `Content-Length: 0` or no body written |

`ManagementMethodSemanticsServletIT` / `...ReactiveIT` repeat the core rows on the management
port, including a case with management `other-endpoints: DENY` so the property is reachable
there at all.

### 9.2 The differential test — the strongest validation

For the same path and verb, assert that the library's denied-path response equals the
response Spring produces natively when the request is permitted:

1. Run the request with the path **whitelisted**, so it reaches the dispatcher and Spring
   emits its own 405. Capture status and `Allow`.
2. Run the identical request with the path governed by the ACL and denied, property on.
   Capture status and `Allow`.
3. Assert equal status and **equal `Allow` as a `Set<HttpMethod>`** — never as a string, since
   header ordering is non-deterministic (§3.5).

Repeat for the OPTIONS branch against Spring's `HttpOptionsHandler` output. This is the test
that would have caught the HEAD-in-`Allow` error corrected in §3.5, and it will catch the
next such drift on a Spring upgrade.

### 9.3 Unit tests

For the resolvers: pattern matching including `**` and `{id}` templates; multi-mapping unions
on one path; the `acceptsAnyMethod` abort; `pathUnknown` when nothing matches; the
absent-`RequestMappingHandlerMapping` degradation path; and that the parsed request path is
**cleared** afterwards when the resolver parsed it (§3.6) — assert
`ServletRequestPathUtils.hasParsedRequestPath(request)` is false on exit.

### 9.4 Gate

`JAVA_HOME=/opt/openjdk-bin-17 mvn -Psonar clean verify` must finish with the quality gate
green and **zero new violations**. Per the standing rule, no Sonar finding is dismissed or
marked accepted without Gökhan's explicit per-finding approval.

---

## 10. Invariants a reviewer should try to break

1. **No request that is served today becomes denied.** Item 1 only widens; item 2 only
   relabels an existing denial.
2. **No request that is denied today becomes served.** The authorization decision is never
   consulted or altered by the 405 machinery.
3. **An unauthenticated request never receives 405 or `Allow`** (D6).
4. **A verb the code implements never receives 405** — it receives 403 (row B). Breaking this
   turns an authorization answer into an existence answer and misleads the caller.
5. **The `Allow` set equals Spring's own** for the same path (§5.2, tested by §9.2).
6. **A blacklisted path discloses nothing** (D5).
7. **With `unmatched-method-response: DENY`, behaviour is byte-identical to 2.3.0** except
   for item 1's HEAD widening. That is what makes the escape hatch a real escape hatch, and
   it is the invariant D9's default flip must not quietly break.
8. **Both stacks and both ports behave identically** wherever the underlying frameworks do
   (§3.7 documents the one place they do not).

---

## 11. Versioning and CHANGELOG

**Released as `2.4.0`** (Gökhan, 2026-08-31). `pom.xml` moves from `2.3.1-SNAPSHOT` to
`2.4.0-SNAPSHOT`, and the CHANGELOG gets a new `## [2.4.0] - YYYY-MM-DD` section above
`## [2.3.0]`.

The case for calling it a major was put and not taken, and is recorded so nobody re-opens it:
three changes here are not backward compatible, and one of them stops a service booting.

| Change | Severity |
|---|---|
| D8 — `method: HEAD` / `OPTIONS` / `TRACE` no longer binds | Fails to start |
| D9 — unmatched verbs now answer 405 instead of 403 by default | Observable behaviour change |
| Item 1 — HEAD reaches GET-listed endpoints | Widening, no opt-out |

The counter-argument, which carried: this library's consumers are the opentmf services, they are
upgraded deliberately rather than by range resolution, and the one breaking case fails loudly at
boot with a message naming the property rather than misbehaving in production. The CHANGELOG
carries the migration instead.

**The CHANGELOG must lead with the migration**, not bury it:

- `### Removed` / `### Changed` — the `Endpoint.method` restriction, naming the four rejected
  verbs and telling the reader what to do: *delete HEAD entries (now automatic), delete
  OPTIONS entries (configure CORS instead)*. Address the workaround population directly
  (§4.2).
- `### Changed` — the 405 default, with `unmatched-method-response: DENY` named as the
  one-line way back to the old behaviour.
- `### Changed` — HEAD now reaches GET-listed endpoints.
- `### Added` — the property itself, the `Allow` header, and the OPTIONS answer.

Per the repository's CHANGELOG rule, nothing introduced and fixed inside this unreleased
cycle gets an entry; all four items above were present in 2.3.0 and are visible to its
audience, so all four belong.

## 12. Rejected alternatives

- **ACL-derived `Allow`** — the position argued before D1. It cannot distinguish "the code
  does not implement this verb" from "the deployer did not list it", which is exactly the
  distinction 405 exists to express, and it inherits every mistake in the deployment
  configuration. D1 rejects it on the merits.
- **`getHandler(request)` at deny time** — D4. Side effects on an undispatched request, a
  parsed-path prerequisite, per-stack signals, and reflection needed for OPTIONS.
- **A precomputed `pattern -> methods` index** — D3. Forces our own pattern matching and
  reintroduces the drift D4 exists to avoid.
- **Flipping `other-endpoints` to `AUTHENTICATED`** (in the library or a service) — buys a
  better error message with a real posture change: every unlisted *path* then reaches a
  handler.
- **Enumerating unsupported verbs in the ACL** — a verb denylist maintained beside the
  allowlist, growing forever, destroying the property that the ACL reads as "exactly what is
  reachable".
- **Fixing it in one service** — gives QA per-service behaviour, which is worse for them than
  a uniform 403.
- **Blanket `permitAll()` for `OPTIONS`** — a common library shortcut; it opens a verb on
  every path including blacklisted ones, and does not produce working CORS anyway (§3.7).
- **Intersecting `Allow` with the caller's authorities** — §5.7.

---

## 13. Decision log

| ID | Decision | Where | Decided by |
|---|---|---|---|
| **D1** | The controller is the authoritative contract; unimplemented verb → 405 | §2 | Gökhan, 2026-08-31 |
| **D2** | HEAD-follows-GET ships ungated | §4.3 | Superseded — settled structurally by D8 |
| **D3** | Cache the `RequestMappingInfo` snapshot lazily via `SingletonSupplier` | §5.4 | Gökhan, 2026-08-31 |
| **D4** | Read supported verbs from `getHandlerMethods()` + Spring's own conditions, not `getHandler()` | §5.3 | Design, from source analysis |
| **D5** | Blacklisted paths always answer 403 with no `Allow` | §5.5 | Design; disclosure choice |
| **D6** | 405 only on the denied path, never the entry-point path | §5.6 | Hard constraint |
| **D7** | The library owns the 405 response; consumer `AccessDeniedHandler` is bypassed for it | §5.8 | Gökhan, 2026-08-31 |
| **D7a** | The 405 carries no body — `setStatus` + `Allow` only | §5.8.1 | Gökhan, 2026-08-31 |
| **D8** | `Endpoint.method` restricted to a five-value `EndpointMethod` enum; HEAD/OPTIONS/TRACE configs fail to bind | §4.2 | Gökhan, 2026-08-31 |
| **D9** | `unmatched-method-response` defaults to `METHOD_NOT_ALLOWED` | §7 | Gökhan, 2026-08-31 |

---

## 14. What implementation changed

Two things the source reading in §3 did not predict. Both are recorded here because they
qualify claims made above.

### 14.1 On the reactive stack, Spring's own 405 loses its `Allow` header

§5.2's invariant says our response must match what the framework answers natively. It holds on
the servlet stack. On the reactive stack it holds for the **status** but not for the header, and
the reason is not ours:

- WebFlux raises `MethodNotAllowedException`, whose `getHeaders()` **does** build an `Allow`
  header (`spring-web`, `MethodNotAllowedException.getHeaders()`).
- Spring Boot's `DefaultErrorWebExceptionHandler.renderErrorResponse` builds the response as
  `ServerResponse.status(status).contentType(APPLICATION_JSON).body(errorAttributes)` and
  **never copies the exception's headers**. The `Allow` header is dropped before the response
  is written.

RFC 9110 requires a 405 to carry `Allow`, so this library emits it rather than reproducing
Boot's omission. **The divergence is deliberate and in the RFC-correct direction.**
`ReactiveUnmatchedMethodDenyIT.webFluxOwnMethodNotAllowed_hasTheSameStatusButLosesTheAllowHeader`
pins Boot's current behaviour, so a Boot release that starts propagating those headers is
noticed here first.

Restated invariant: **the status matches natively on both stacks; the `Allow` header matches
natively on servlet, and on reactive it is present where Boot's rendering omits it.**

### 14.2 The servlet management chain must read the management child context's mappings

A correctness bug the plan would have shipped. §5.3 said to inject
`ObjectProvider<RequestMappingInfoHandlerMapping>` — but *which context's* mappings that
resolves is not the same on the two stacks:

- **Reactive** management config is `@ManagementContextConfiguration(CHILD)`, so it already
  resolves the child context's mappings: the actuator's. Correct as planned.
- **Servlet** management config lives in the **main** context by design (2.2.0: Boot exposes the
  parent's `springSecurityFilterChain` on the management port). Injecting the provider there
  resolves the **main** context's mappings — the business API. A denied management-port request
  would then have been answered from the wrong context, advertising methods that port does not
  serve.

Fix: both resolvers now take a `Supplier<Stream<RequestMappingInfoHandlerMapping>>` rather than
an `ObjectProvider`, so each chain names the context that actually dispatches its requests. The
servlet management chain captures the child `ApplicationContext` from the same
`WebServerInitializedEvent` it already listens to for the port, and reads its bean provider on
first denial. `ManagementMethodSemanticsServletIT.aPathServedOnlyByTheMainPort_staysForbidden`
is the regression test — it fails against the design as originally written.

### 14.3 Everything else held

- All 302 pre-existing tests passed unchanged under the new default, which is the strongest
  evidence that D9's flip and item 1's widening break nothing consumers depended on.
- Spring's split between the 405 `Allow` (raw declared set) and the OPTIONS `Allow` (plus HEAD,
  plus OPTIONS) is reproduced exactly, and the servlet differential test in
  `ServletUnmatchedMethodDenyIT` confirms it against Spring's own output.
- Reusing `getActivePatternsCondition().getMatchingCondition(request)` (D4) needed no adjustment
  for the servlet context path — MVC's condition strips it itself — and this is covered on a
  real server by `ServletCustomErrorHandlersIT`.

### 14.4 Stack isolation — verified, not assumed

Both auto-configuration layers ship in one jar and a consumer only ever has one stack, because
`spring-boot-starter-webmvc` and `spring-boot-starter-webflux` are both `optional` here. This
change made each layer name a type from its own stack that the other's consumer does not have
(`RequestMappingInfoHandlerMapping`, in the webmvc and webflux flavours respectively), so the
question of whether either layer can fail because of the other's absence had to be answered
rather than assumed. `StackIsolationTest` answers it three ways:

1. **Servlet with WebFlux hidden** and **reactive with Spring MVC hidden** — and the stricter
   case, **reactive with `jakarta.servlet` hidden too** — each start, create exactly their own
   filter chain, and do not create the other's. Uses `FilteredClassLoader`.
2. **Bytecode check.** Those runner tests hand Spring already-loaded `Class` objects, so they
   prove the conditions skip the wrong stack's *beans*, not that its class was safe to *load*.
   In production Boot loads auto-configurations by name and skips a non-matching one via
   ASM-read metadata, never loading it. The test that pins what that guarantee rests on reads
   each compiled class's constant pool directly and asserts no servlet class names
   `org/springframework/web/reactive` or `reactor/core/publisher`, and no reactive class names
   `org/springframework/web/servlet` or `jakarta/servlet`.
3. **The one configuration that cannot work is unchanged by this release.** A servlet app with
   no Spring MVC at all (Jersey) fails — but on
   `NoSuchBeanDefinitionException: CorsConfigurationSource`, raised by the `.cors(withDefaults())`
   call that has been in the chain since long before 2.4.0. `CorsConfigurer` needs either a
   `CorsConfigurationSource` bean or the `mvcHandlerMappingIntrospector`. So Spring MVC was
   already required on the servlet path, and the new webmvc reference adds no constraint that
   was not there already. Verified by probe, not reasoned.

---

## 15. What review changed

Fable reviewed the first implementation and found four defects and three cleanups. All were
verified from source or by probe before being acted on; two were things this plan asserted and
got wrong.

### 15.1 The management-context fix in §14.2 was incomplete

§14.2 correctly identified that the servlet management chain must read the *child* context's
mappings, and fixed it with `context.getBeanProvider(...).stream()`. **That does not scope the
lookup.** `ObjectProvider.stream()` resolves through `beanNamesForTypeIncludingAncestors`, which
excludes a parent bean only when the child defines one under the **same name**. Boot's management
child context happens to define `requestMappingHandlerMapping`, shadowing the parent's — so the
isolation held by coincidence, and any mapping in the main context under another name (Spring
Integration's `integrationRequestMappingHandlerMapping`, a second mapping for a versioned API)
would have leaked in.

Probed directly: a child context asked for a type the parent also declares under a different name
answers **2** through `getBeanProvider().stream()` and **1** through `getBeansOfType()`. Both
management chains now use `getBeansOfType`, which does not traverse ancestors.

**The §14.2 regression test could not have caught this**, which is the more useful lesson: it used
`PUT /car`, and `/car` implements `PUT`, so the "the code implements this verb" rule returns 403
whether or not the main context leaked in. The test now uses `PATCH`, which nothing implements on
`/car`, and adds a mapping registered in the main context under a name the child does not shadow.
Re-introducing `getBeanProvider().stream()` makes it fail with `405` and an `Allow` header — the
disclosure the isolation exists to prevent. The reactive management port, which had no
method-semantics coverage at all, now has its own test.

### 15.2 The blacklist was matched by two independently built matcher sets

The authorization registry resolves blacklist patterns with the parser the application configured
(`PathPatternRequestMatcherBuilderFactoryBean` reads the `mvcPatternParser` bean and a base path;
reactive `AuthorizeExchangeSpec.getPathPatternParser()` prefers the WebFlux mapping's parser). The
denied-request handler re-parsed the same strings with a bare default builder. An application with
a customised parser would have a registry that denies more than the handler recognises — and a
blacklisted path whose denial is then rewritten to 405 with an `Allow` header, disclosing exactly
what the blacklist exists to hide.

Sharing the matcher instances would fix it, but the better answer is not to match twice at all:
**the rule that makes the decision now records it.** `ServletBlacklistDenial` /
`ReactiveBlacklistDenial` replace `denyAll()` on blacklist entries, deny identically, and mark the
request; the handler reads the mark. No second matcher exists to disagree, and the handler learns
which rule denied rather than guessing.

### 15.3 The resolvers could turn a denial into a 500

`mappings.get()` — the lazy snapshot — ran outside the `try` whose comment promised that a
resolution failure never becomes a server error. `SingletonSupplier` does not cache failures, so a
snapshot that throws (a denial in flight during context shutdown) would escape the handler on that
request and every later one. Both resolvers now take the snapshot inside the `try`.

### 15.4 A dead decorator, and duplicated decision logic

- Setting `exceptionHandling`'s denied handler makes it global and Spring then ignores the
  resource server's per-matcher registration, so with a consumer-supplied handler the second
  decorator built for the bearer slot was unreachable — while still holding its own resolver and
  its own parsed blacklist. Each chain now decides its handlers once, in a `DeniedHandlers` holder,
  and installs exactly the one slot that is consulted.
- `resolveAllowed()` and `serves()` were character-identical across the two handlers, so a fix to
  one stack would silently diverge from the other while each stack's tests kept passing. The
  decision moved to `EndpointRules.allowedFor(HttpMethod, SupportedMethods)`, shared by both.

### 15.5 A behaviour change nobody had noticed: lowercase method values

Not something this plan introduced, but something it exposes. Under the previous `HttpMethod`
type, Boot bound `method: get` through `HttpMethod.valueOf`, which is **case-preserving** —
`valueOf("get")` returns `new HttpMethod("get")`, not the `GET` constant — and both stacks'
matchers compare the verb by exact string. A lowercase rule therefore **never matched**: the path
fell through to `other-endpoints` and was denied. Enum binding is case-insensitive, so on 2.4.0
the same line binds to `GET` and the rule takes effect: an `allowed-endpoints` entry becomes
anonymous `permitAll`, a `secure-endpoints` entry starts granting.

Nothing can warn about this at startup, because after binding the configuration is
indistinguishable from one that was always correct. It is called out in the CHANGELOG and README
as a pre-upgrade check, and pinned by a test.

### 15.6 Left as it is, deliberately

The review also flagged that a more-disclosing, handler-bypassing behaviour ships as the **default**
of a minor release, and that §11 records the case for gating it behind a major. That is D9 and the
version decision, both made knowingly (§7, §11). What the review added that was not previously
written down is the audit consequence: a consumer whose `AccessDeniedHandler` is also where they
audit denied requests will not see 405/200 responses. That is now stated in the README next to the
opt-out.

---

## 16. Second review round

Seven acted on, two deferred with reasons. The notable ones:

**A `NoClassDefFoundError` could turn every denial into a 500.** `catch (RuntimeException)` does
not catch an `Error`, and on a servlet application built without Spring MVC the first touch of a
handler-mapping type raises `NoClassDefFoundError`. §14.4 concluded such an application "was
already unsupported" because `.cors(withDefaults())` fails at startup without a
`CorsConfigurationSource` — **that conclusion was too quick.** A consumer who publishes their own
`CorsConfigurationSource` bean, which is exactly what a service doing CORS properly does, starts
fine and then 500s on every denied request. Both resolvers now catch `RuntimeException |
LinkageError`; `OutOfMemoryError` and friends still propagate. Not reproducible in
`StackIsolationTest`, because the runner hands Spring already-loaded `Class` objects, so the class
literal resolves through the app classloader where MVC is present — the fix rests on the reasoning,
which is why the catch says so in a comment.

**A startup race could disable the management port's semantics permanently.**
`captureManagementPort` set the port before the context, and the chain matches on the port alone,
so a denial arriving between the two writes found a null context, snapshotted an empty mapping
set — and `SingletonSupplier` caches *successes*, so that empty snapshot would stand for the life
of the process, silently. Two changes: the context is now written first, and a null context
*throws* rather than returning `Stream.empty()`, so the resolver's catch turns it into a
one-request `notServed()` and the next denial retries. The throw is what fixes the class of
problem; the reordering only closes this instance of it.

**The `Allow` rendering did not match Spring's on the OPTIONS path.** Spring renders its 405
`Allow` with `", "` (`HttpRequestMethodNotSupportedException.getHeaders`) and its OPTIONS `Allow`
with a bare `","` (`HttpOptionsHandler` → `HttpHeaders.setAllow`). The hand-rolled joiner used
`", "` for both, so the OPTIONS answer differed by a space from the one the application gives when
the request is allowed through — a small breach of §5.2's invariant that the differential test
could not see, since it compares sets. Each branch now uses the framework's own rendering.

**Legacy Ant-matched mappings made the feature silently inert.** `PatternsRequestCondition` is
deprecated-for-removal but still reachable, and its `getMatchingCondition` calls
`UrlPathHelper.getResolvedLookupPath`, which throws unless the `DispatcherServlet` populated that
attribute — never true out in the filter chain. So on such an application every denial threw once
per scan, was swallowed at debug, and no 405 ever appeared. The servlet resolver now prepares that
path form alongside the parsed one, and cleans up both.

**The blacklist mark outlived its dispatch.** A servlet request survives an ERROR dispatch, so a
bare flag set on a blacklisted path was still there when `/error` was re-authorized, labelling
that denial blacklist-caused. The mark now records the URI it was set for and `denied()` compares.

**Two documentation defects, both about upgrades.** The HEAD change was written up purely as a
loosening; it also *tightens* — a `HEAD` that previously fell through `other-endpoints` to
`permitAll` now carries the `GET` rule's roles, and the management section's `authenticated`
default means a role-restricted management `GET` rule tightens `HEAD` there by default. And
removing `method: OPTIONS` left anonymous plain-`OPTIONS` probes with no narrow replacement: the
405/200 handling never applies to anonymous callers by design, so the only substitute is a
`whitelist` entry, which is strictly broader. Both now stated where an operator will meet them.

### 16.1 Deferred, with reasons

- **Wider de-duplication** across the four configurations (the slot decision, the `getBeansOfType`
  lookup and its rationale, the resolver skeleton). The observation is right, and the LeakProbe
  test guards only the servlet management copy of that lookup. It is a structural refactor of
  code that has just been reworked twice under review; doing it in the same round trades a
  reviewed diff for an unreviewed one. Worth its own change, with the missing guard tests for the
  other three copies written first.
- **Short-circuiting `match()`** once `serves(...)` is true, and warming the snapshot off the
  Netty event loop. The efficiency argument is fair — the denial path is attacker-reachable — but
  an early return makes `declared` conditionally complete, and `SupportedMethods` is the input to
  the one shared decision that exists precisely so the two stacks cannot diverge. Trading a clear
  invariant for microseconds on a path that is already bounded by the mapping count is the wrong
  order of priorities while the semantics are this new.

## 17. Third review round

Nine findings; two were re-records of the §16.1 deferrals, which stand unchanged. The rest are
fixed in this round.

**The `Allow` order was not Spring's.** Two halves. `optionsAllow` appended `HEAD` at the end,
while Spring's `HttpOptionsHandler` slots it in immediately after `GET` — the delimiter half of
this invariant was fixed in round two, the ordering half is fixed now, the same way: copy the
declared methods and insert `HEAD` right after `GET`. And both resolvers snapshotted the mappings
with `Collectors.toUnmodifiableSet`, whose iteration order is salted per JVM run, so a path served
by several mappings advertised its methods in an order that changed across restarts. The snapshot
now keeps registration order in a `LinkedHashSet`. Byte-identical to the allowed-through answer,
run after run, is the invariant — §5.2 — and now both halves of it hold.

**The reactive handler wrote to a possibly-committed response.** A committed reactive response has
read-only headers; `setAllow` on it throws inside `Mono.fromRunnable` and turns the denial into an
error signal, where the servlet container just ignores late writes. The handler now checks
`isCommitted()` and leaves a committed response alone — the servlet twin's semantics, made
explicit.

**The legacy-Ant path was resolved with the wrong helper.** Round two prepared the Ant-style
lookup path with `UrlPathHelper.defaultInstance`; an application that configured its own helper
(`alwaysUseFullPath`, `urlDecode=false`) was then matched differently by the resolver than by its
own `DispatcherServlet`. The snapshot now also captures the mapping's configured helper — the
accessor is deprecated together with the matching style it serves, and both leave together.

**The 405 behaviour toggled on an unrelated bean.** The decoration was installed on the resource
server's bearer-token slot when no consumer handler existed, and on the global exception-handling
slot when one did — so a denial of an authenticated-but-non-bearer caller (an application adding
its own pre-authentication beside this library) answered 403 or 405 depending on whether some
consumer handler bean happened to exist. The handler now always lives on the exception-handling
slot, which covers every authorization denial regardless of how the request authenticated; without
a consumer handler the delegate is the same RFC 6750 bearer handler the resource server would have
installed, so bearer callers see identical answers, and the non-bearer caller's remaining 403s
take the RFC 6750 shape instead of the framework error page. The management chains moved the same
way, and the slot truth-table collapsed to one field in passing.

**The blacklist mark became a typed decision.** The request-attribute marker was a public string
key any filter could set, guarded by a URI-equality heuristic that had already needed one round of
repair for ERROR dispatches. Spring Security 7 carries the denying rule's own
`AuthorizationResult` to the handler inside `AuthorizationDeniedException`, so the rule now
returns (servlet) or raises (reactive — `verify()` would collapse the result to a bare
`AccessDeniedException`) a `BlacklistDecision`, and the handlers check the exception's result by
type. Both marker attributes, both `denied()` heuristics and every dispatch-lifetime concern are
gone by construction.

**The management capture is one reference again.** Port and child context were two atomics filled
from one event, held consistent by a write-ordering comment. The configuration now stores the
`WebServerInitializedEvent` itself and derives both, so "port matched but context missing" is
unrepresentable rather than merely ordered away.

**And a constant stopped being rebuilt.** The all-methods-except-`TRACE` answer for a no-method
mapping's `OPTIONS` is knowable at class-load time and now is.
