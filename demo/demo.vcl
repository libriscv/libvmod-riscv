vcl 4.1;
import riscv;
import std;

backend default {
	.host = "127.0.0.1";
	.port = "8081";
}

sub vcl_recv {
	if (req.url == "/riscv") {
		/* Select a tenant to handle this request */
		riscv.fork("xpizza.com");
		/* Add CDNs custom header fields */
		set req.http.X-Tenant = riscv.current_name();
		/* We can call VCL-like functions */
		riscv.run();
		/* We can query what the machine wants to happen */
		if (riscv.want_result() == "synth") {
			/* And then do it for them */
			return (synth(riscv.want_status()));
		} else if (riscv.want_result() == "backend") {
			set req.http.X-Backend-Func = riscv.result_value(1);
			set req.http.X-Backend-Arg  = riscv.result_value(2);
			if (riscv.result_value(0) == 0) {
				return (pass);
			} else {
				return (hash);
			}
		}
		set req.url = "/";
	} else if (req.url == "/varnish") {
		set req.url = "/";
		set req.http.X-TenantV = "varnish";
		set req.http.X-Hello = "url=" + req.url;
		set req.http.X-Match = regsub(req.url, "varnish", "");
		if (req.http.X-Match == "/") {
			set req.http.X-Match = "true";
		} else {
			set req.http.X-Match = "false";
		}
	} else {
		/* Unknown URL */
		return (synth(404, "Not Found"));
	}
}

sub vcl_deliver {
	if (req.http.X-Tenant) {
		riscv.run();
	} else if (req.http.X-TenantV) {
		set resp.http.X-Goodbye = "Varnish";
		set resp.http.X-Hello = req.http.X-Hello;
		set resp.http.X-Match = req.http.X-Match;
	}
}

sub vcl_backend_fetch {
	if (bereq.http.X-Tenant) {
		if (riscv.fork(bereq.http.X-Tenant)) {
			riscv.run();
			if (bereq.http.X-Backend-Func) {
				set bereq.backend = riscv.vm_backend(
						bereq.http.X-Backend-Func,
						bereq.http.X-Backend-Arg);
			}
		}
	}
}
sub vcl_backend_response {
	if (bereq.http.X-Tenant) {
		riscv.run();
	}
	set beresp.http.varnish-director = bereq.backend;
	set beresp.http.varnish-backend = beresp.backend;
}

sub vcl_init {
	/* Initialize some tenants from JSON */
	riscv.embed_tenants("""{
		"xpizza.com": {
			"filename": "/home/gonzo/github/libvmod-riscv/program/basic.cpp",
			"arguments": ["Hello from RISC-V!"]
		}
	}""");
}
