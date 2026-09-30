use vcl_compiler::{compile, CompileOptions, IncludeResolver};

#[test]
fn every_shipped_vcl_policy_compiles() {
    for (name, source) in [
        ("default.vcl", include_str!("policies/default.vcl")),
        (
            "media_edge.vcl",
            include_str!("policies/media_edge.vcl"),
        ),
        (
            "controller/shop.vcl",
            include_str!("policies/controller/shop.vcl"),
        ),
        (
            "controller/api.vcl",
            include_str!("policies/controller/api.vcl"),
        ),
        (
            "controller/wildcard.vcl",
            include_str!("policies/controller/wildcard.vcl"),
        ),
        (
            "controller/not_found.vcl",
            include_str!("policies/controller/not_found.vcl"),
        ),
    ] {
        compile(source, CompileOptions::default())
            .unwrap_or_else(|error| panic!("{name} is outside the supported VCL surface: {error}"));
    }
}

#[test]
fn representative_vcl_4_0_policy_compiles_unchanged() {
    let source = r#"
vcl 4.0;
import std;

sub vcl_recv {
    if (req.http.Authorization || std.strstr(req.url, "/private")) {
        return (pass);
    }
    std.log({"carapace
compatibility corpus"});
    set req.http.X-Policy = {"carapace compatibility corpus"};
    return (hash);
}

sub vcl_backend_response {
    if (beresp.status >= 500) {
        return (abandon);
    }
    set beresp.ttl = 30s;
    return (deliver);
}

sub vcl_deliver {
    set resp.http.X-Cache = "edge";
    return (deliver);
}
"#;

    compile(source, CompileOptions::default()).expect("compile representative VCL 4.0 policy");
}

#[test]
fn controller_root_template_is_a_pinned_migration_guide() {
    let source = include_str!("policies/controller/upstream/root.vcl");
    let diagnostics = compile(source, CompileOptions::default()).unwrap_err();
    let messages = diagnostics
        .diagnostics
        .iter()
        .map(|diagnostic| diagnostic.message.as_str())
        .collect::<Vec<_>>();
    assert_eq!(
        messages,
        [
            "unsupported VCL module 'file'",
            "unsupported VCL module 'accounting'",
            "backend declarations are not supported",
            "unsupported statement 'accounting.create_namespace'",
            "VCL objects are not supported",
            // `urlplus` and `headerplus` now parse, so their calls are no
            // longer rejected here. What the template still asks of them --
            // a `urlplus.write()` in `vcl_recv` and Varnish's workspace
            // rollback -- is refused by the type checker instead, which
            // `urlplus_and_headerplus_rejections_name_their_owner` pins.
            "unsupported statement 'accounting.set_namespace'",
            "unsupported statement 'accounting.add_keys'",
            "return (vcl(...)) is not supported",
        ]
    );
    assert!(diagnostics.diagnostics.iter().all(|diagnostic| {
        diagnostic
            .help
            .as_deref()
            .is_some_and(|help| !help.is_empty())
    }));

    let temporary = include_str!("policies/controller/upstream/temp_root.vcl");
    let temporary = compile(temporary, CompileOptions::default()).unwrap_err();
    assert_eq!(
        temporary
            .diagnostics
            .iter()
            .map(|diagnostic| diagnostic.message.as_str())
            .collect::<Vec<_>>(),
        [
            "unsupported VCL module 'file'",
            "backend declarations are not supported",
            "VCL objects are not supported",
        ]
    );
}

/// The two things the Controller template asks of `urlplus` and `headerplus`
/// that carapace will not do, and what each diagnostic has to name.
///
/// These live apart from the template because the parser refuses that file
/// before the type checker ever sees a `vcl_recv` body: a rejection that
/// belongs to a later stage has to be provoked from a file that parses.
#[test]
fn urlplus_and_headerplus_rejections_name_their_owner() {
    let source = r#"
vcl 4.1;
import urlplus;
import headerplus;
sub vcl_recv {
    urlplus.url_delete_range(0, 0);
    urlplus.write();
    headerplus.init(req);
    headerplus.write_req0();
    return (hash);
}
"#;
    let diagnostics = compile(source, CompileOptions::default()).unwrap_err();
    let reported: Vec<(&str, &str)> = diagnostics
        .diagnostics
        .iter()
        .map(|diagnostic| {
            (
                diagnostic.message.as_str(),
                diagnostic.help.as_deref().unwrap_or_default(),
            )
        })
        .collect();

    // Mutating the state and reading it back is fine anywhere; it is the
    // *write* that would move the cache key, so that is what is refused, and
    // the diagnostic names the declarative owner.
    assert_eq!(reported.len(), 2, "{reported:?}");
    assert_eq!(reported[0].0, "urlplus.write is not valid in vcl_recv");
    assert!(
        reported[0].1.contains("the cache key belongs to the Varnish VCL"),
        "the diagnostic must name the owner: {}",
        reported[0].1
    );
    assert_eq!(
        reported[1].0,
        "unsupported headerplus function 'headerplus.write_req0'"
    );
    assert!(
        reported[1].1.starts_with("supported: "),
        "an unsupported function lists the ones that are: {}",
        reported[1].1
    );
}

/// Every Varnish variable the checker knows the name of gets a line saying
/// *which kind* of absence it is: a decision Carapace made declaratively, a
/// host capability that does not exist, or a spelling that does exist under
/// another name. "unknown or unsupported VCL variable" on its own tells a
/// migrating author nothing, and they meet these one at a time.
#[test]
fn absent_variables_name_which_kind_of_absence_they_are() {
    for (variable, needle) in [
        // Declarative: the answer is the Varnish VCL.
        ("req.backend_hint", "backends and directors belong"),
        ("bereq.backend", "backends and directors belong"),
        ("bereq.first_byte_timeout", "timeouts belong to the Varnish VCL"),
        ("req.hash_always_miss", "return (pass)"),
        // No host data, under any spelling.
        ("req.restarts", "no host data"),
        ("bereq.retries", "no host data"),
        ("req.xid", "no host data"),
        ("obj.hits", "no host data"),
        ("server.hostname", "no host data"),
        ("local.ip", "no host data"),
        ("beresp.backend.name", "no host data"),
        // Use X instead.
        ("req.ttl", "set beresp.ttl"),
        ("obj.uncacheable", "beresp.uncacheable"),
        ("client.port", "use client.ip"),
        // Body mutation crosses a line the whole design draws.
        ("beresp.do_gzip", "immutable response body"),
    ] {
        let source =
            format!("vcl 4.1; sub vcl_recv {{ set req.http.X = {variable}; return (hash); }}");
        let diagnostics = compile(&source, CompileOptions::default())
            .unwrap_err()
            .render("absent.vcl");
        assert!(
            diagnostics.contains(needle),
            "{variable} must be refused with {needle:?}:\n{diagnostics}"
        );
    }

    // A write to a variable no sub owns must not be answered with "move it to
    // the sub that owns it": there is not one.
    for (statement, needle) in [
        ("set resp.status = 503;", "return (synth("),
        ("set beresp.status = 503;", "return (synth("),
        ("set req.url = \"/x\";", "rewriting req.url and Host belongs"),
    ] {
        let phase = if statement.contains("beresp") {
            "vcl_backend_response"
        } else if statement.contains("resp.status") {
            "vcl_deliver"
        } else {
            "vcl_recv"
        };
        let source = format!("vcl 4.1; sub {phase} {{ {statement} }}");
        let diagnostics = compile(&source, CompileOptions::default())
            .unwrap_err()
            .render("absent.vcl");
        assert!(
            diagnostics.contains(needle),
            "{statement} must be refused with {needle:?}:\n{diagnostics}"
        );
        assert!(
            !diagnostics.contains("move this assignment to the VCL sub"),
            "{statement} names a sub that does not own it:\n{diagnostics}"
        );
    }

    // And `set req.url` in vcl_backend_fetch has a real answer.
    let source = "vcl 4.1; sub vcl_backend_fetch { set req.url = \"/x\"; }";
    let diagnostics = compile(source, CompileOptions::default())
        .unwrap_err()
        .render("absent.vcl");
    assert!(diagnostics.contains("bereq.url"), "{diagnostics}");
}

/// The Controller template's health include, pinned.
///
/// It is a *library* — no version marker — so it only reaches the compiler
/// through an `include`, which is why nothing compiled it before and its
/// verdicts drifted unpinned. Two things it asks for and one of them is
/// refused: `beresp.do_gzip` would mutate an immutable body, and
/// `beresp.ttl = 0.1s` is truncated to whole seconds with a warning rather
/// than refused — `Cache-Control: max-age` is `delta-seconds`, so `0.1s` can
/// only ever mean `0s` here, and refusing the file over it buys nothing the
/// warning does not.
#[test]
fn the_controller_health_include_is_pinned() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/policies/controller/upstream");
    let main = "vcl 4.1;\n\
                include \"traffic_router_health.vcl\";\n\
                sub vcl_recv { return (traffic_router_health); }\n\
                sub vcl_backend_response { return (health_backend_response); }\n";

    let options = CompileOptions::default().with_include_resolver(directory(&root));
    let messages: Vec<String> = compile(main, options)
        .unwrap_err()
        .diagnostics
        .iter()
        .map(|diagnostic| diagnostic.message.clone())
        .collect();
    assert_eq!(
        messages,
        ["beresp.do_gzip would mutate an immutable response body"]
    );

    // Without the body filter, the file compiles and says what it truncated.
    let patched = std::fs::read_to_string(root.join("traffic_router_health.vcl"))
        .expect("read the include")
        .replace("set beresp.do_gzip = true;", "");
    let temp = tempfile::TempDir::new().expect("temp dir");
    std::fs::write(temp.path().join("traffic_router_health.vcl"), patched).expect("write include");
    let options = CompileOptions::default().with_include_resolver(directory(temp.path()));
    let compiled = compile(main, options).expect("the rest of the include compiles");
    let warnings = compiled.warnings.render("traffic_router_health.vcl");
    assert!(
        warnings.contains("beresp.ttl is truncated to 0s"),
        "{warnings}"
    );
}

/// `return (synth(...))` from `vcl_deliver`, the Varnish shape a migrated
/// policy writes. `sub vcl_synth` is folded into *both* dispatching hooks
/// (`docs/plans/vcl-deliver-synth.md` D3), so the decoration a 503 needs — a
/// `Content-Type`, a `Retry-After` — is reachable from either one.
#[test]
fn vcl_deliver_dispatches_the_folded_vcl_synth() {
    let source = r#"
vcl 4.1;

sub vcl_recv {
    if (req.url ~ "^/deny") {
        return (synth(403, "denied"));
    }
    return (hash);
}

sub vcl_deliver {
    if (resp.status == 500) {
        return (synth(503, "origin is unwell"));
    }
    return (deliver);
}

sub vcl_synth {
    set resp.http.Content-Type = "text/plain";
    set resp.http.Retry-After = "30";
    synthetic("the page is unavailable");
    return (deliver);
}
"#;
    compile(source, CompileOptions::default()).expect("a deliver synth compiles");

    let ir = vcl_compiler::dump_ir(source, CompileOptions::default()).expect("dump");
    // The unoptimized section only: the later passes repeat both hooks.
    let hooks = ir
        .split_once("== lowered (O0) ==")
        .expect("lowered section")
        .1
        .split("\n== ")
        .next()
        .expect("section body");
    let (recv, deliver) = hooks
        .split_once("fn on_deliver")
        .expect("both hooks are lowered");
    // The fold is in each: the dispatch's own `set_outcome`, then the
    // `vcl_synth` body's header writes, then `synthetic()`'s second outcome.
    // That order is what lets the host discard the delivered response's
    // headers on the transition and keep `vcl_synth`'s own.
    for (name, body) in [("on_recv", recv), ("on_deliver", deliver)] {
        assert_eq!(
            body.matches("set_outcome").count(),
            2,
            "{name} should carry the dispatch and the folded synthetic:\n{body}"
        );
        assert!(
            body.contains("\"Retry-After\""),
            "{name} is missing the folded vcl_synth body:\n{body}"
        );
    }
}

/// The status floor, as a diagnostic. The host refuses the same statuses at
/// runtime — that gate is the rule — but a migrated policy should hear about
/// it at compile time, and hear *why*.
#[test]
fn a_deliver_synth_below_400_names_the_routing_owner() {
    for source in [
        "vcl 4.1; sub vcl_deliver { return (synth(301, \"moved\")); }",
        "vcl 4.1; sub vcl_deliver { return (synth(200, \"fine\")); }",
    ] {
        let error = compile(source, CompileOptions::default())
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("must name a status of 400 or more"),
            "{error}"
        );
        assert!(error.contains("routing decision that belongs to the Varnish VCL"), "{error}");
    }
}

/// `sub vcl_synth` now has two hooks that can dispatch it, so it is reachable
/// from either one — and unreachable only when neither is present.
#[test]
fn vcl_synth_reachability_counts_vcl_deliver() {
    let deliver_only = "vcl 4.1; \
         sub vcl_deliver { return (synth(503, \"nope\")); } \
         sub vcl_synth { set resp.http.X = \"1\"; }";
    let compiled = compile(deliver_only, CompileOptions::default())
        .expect("vcl_deliver alone dispatches a synth");
    assert!(
        compiled.warnings.render("policy.vcl").is_empty(),
        "{}",
        compiled.warnings.render("policy.vcl")
    );

    // Neither hook present: the sub cannot be dispatched at all.
    let orphan = "vcl 4.1; sub vcl_backend_response { return (deliver); } \
                  sub vcl_synth { set resp.http.X = \"1\"; }";
    let error = compile(orphan, CompileOptions::default())
        .unwrap_err()
        .to_string();
    assert!(
        error.contains("requires sub vcl_recv or sub vcl_deliver"),
        "{error}"
    );

    // Present but never returning a synth: a warning, not an error.
    let staged = "vcl 4.1; sub vcl_deliver { return (deliver); } \
                  sub vcl_synth { set resp.http.X = \"1\"; }";
    let compiled = compile(staged, CompileOptions::default()).expect("staged policy compiles");
    let warnings = compiled.warnings.render("policy.vcl");
    assert!(
        warnings.contains("sub vcl_synth is never reached"),
        "{warnings}"
    );
    assert!(warnings.contains("vcl_recv or vcl_deliver"), "{warnings}");
}

/// The fold is charged against the inline budget, across the whole program.
///
/// `attach_synth` clones the `vcl_synth` body into every `return (synth)`
/// site and used to charge nothing for it; with the body folded into two
/// hooks the worst case doubles, so the copies have to be budgeted rather
/// than counted after the fact.
#[test]
fn an_oversized_synth_fold_is_refused() {
    let body: String = (0..400)
        .map(|i| format!("    set resp.http.X-{i} = \"{i}\";\n"))
        .collect();
    let sites: String = (0..40)
        .map(|i| {
            format!(
                "    if (resp.status == {}) {{ return (synth(503)); }}\n",
                500 + i % 60
            )
        })
        .collect();
    let source =
        format!("vcl 4.1;\nsub vcl_deliver {{\n{sites}    return (deliver);\n}}\nsub vcl_synth {{\n{body}}}\n");

    let error = compile(&source, CompileOptions::default())
        .unwrap_err()
        .to_string();
    assert!(
        error.contains("the folded sub vcl_synth exceeds the limit"),
        "{error}"
    );

    // One site's worth of the same body is still legal, so the ceiling is the
    // multiplier and not the body.
    let single = format!(
        "vcl 4.1;\nsub vcl_deliver {{\n    if (resp.status == 500) {{ return (synth(503)); }}\n    return (deliver);\n}}\nsub vcl_synth {{\n{body}}}\n"
    );
    compile(&single, CompileOptions::default()).expect("one dispatch site fits");
}

/// A resolver that reads a test tree. The confinement the host applies lives
/// in `carapace::vcl_source`; `vcl-compiler` opens nothing itself, and the
/// compiler has already normalized the name it asks for.
fn directory(root: &std::path::Path) -> IncludeResolver {
    let root = root.to_path_buf();
    IncludeResolver::new(root.clone(), move |relative: &std::path::Path| {
        std::fs::read_to_string(root.join(relative)).map_err(|error| error.to_string())
    })
}
