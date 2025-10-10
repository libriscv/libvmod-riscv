# RISC-V Multi-Tenancy in Varnish

A Varnish Module (VMOD) that enables **ultra-fast multi-tenancy** using ephemeral RISC-V virtual machines. Each tenant can execute custom logic to configure HTTP requests and responses with VCL-like capabilities, with VM creation/destruction overhead of less than **1 microsecond**.

## Key Features

- **Blazing Fast**: ~1μs overhead per request compared to native VCL
- **Sandboxed Execution**: Isolated RISC-V VMs for each tenant
- **Developer-Friendly**: Write tenant logic in C++ with a familiar API
- **Ephemeral VMs**: VMs are created and destroyed per-request for zero state leakage
- **VCL Integration**: Seamlessly integrates with existing Varnish configurations
- **JSON/XML Support**: Built-in JSON and XML parsing, validation

## Use Cases

- **Multi-tenant CDNs**: Give each customer programmable edge logic
- **Request customization**: Per-tenant header manipulation, URL rewriting, and routing
- **Dynamic backends**: Programmatically select backends based on custom logic
- **Edge computing**: Run lightweight computations at the edge with microsecond latency

## Quick Start

Check out the [demo VCL](demo/demo.vcl) and [example tenant program](program/basic.cpp) to see it in action.

### Example: Tenant Program

Here's a minimal example of what tenant code looks like:

```cpp
#include <api.h>
namespace varnish = api;

static void on_recv(varnish::Request req) {
    // Manipulate request headers
    req.append("X-Hello: url=" + req.url());

    // Return a JSON response
    forge(varnish::Cached, [] (auto bereq, auto beresp) {
        nlohmann::json json;
        json["message"] = "Hello from RISC-V!";
        return varnish::response{200, "application/json", json.dump()};
    });
}

int main() {
    varnish::wait_for_requests(on_recv);
}
```

### Example: VCL Configuration

```vcl
sub vcl_init {
    riscv.embed_tenants("""{
        "customer1.com": {
            "filename": "/path/to/tenant_program"
        }
    }""");
}

sub vcl_recv {
    riscv.fork("customer1.com");
    riscv.run();
}
```
Note: If you have the custom RISC-V compiler from below installed, you can use source files directly as the filename for a tenant, and it will be compiled, cached and loaded automatically: `"filename": "/my/source.cpp"`.

## Benchmarks

Performance comparison showing the minimal overhead of RISC-V VMs:

**RISC-V ephemeral VMs** configuring the request:
```sh
$ ./wrk -c1 -t1 -L http://127.0.0.1:8000/riscv
Running 10s test @ http://127.0.0.1:8000/riscv
  1 threads and 1 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency    11.62us    2.53us 266.00us   98.65%
    Req/Sec    84.51k     0.94k   86.88k    72.73%
  Latency Distribution
     50%   11.00us
     75%   12.00us
     90%   12.00us
     99%   15.00us
  184992 requests in 2.20s, 63.98MB read
Requests/sec:  84083.68
Transfer/sec:     29.08MB
```

A regular Varnish cache hit, with equivalent work to RISC-V above:
```sh
$ ./wrk -c1 -t1 -L http://127.0.0.1:8000/varnish
Running 10s test @ http://127.0.0.1:8000/varnish
  1 threads and 1 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency    10.70us    7.30us 703.00us   99.75%
    Req/Sec    92.33k     2.12k   94.84k    88.46%
  Latency Distribution
     50%   10.00us
     75%   11.00us
     90%   11.00us
     99%   14.00us
  238839 requests in 2.60s, 215.02MB read
Requests/sec:  91862.25
Transfer/sec:     82.70MB
```

We can see that the single-threaded overhead from ephemeral VMs configuring the request is only ~1 microsecond.

Ubuntu Linux 6.14.0-33-generic, AMD Ryzen 9 7950X

## Building the VMOD

Requirements:
```sh
sudo apt install build-essential cmake g++
```

Open-source Varnish:
```sh
./build.sh --32
```

Enterprise Varnish:
```sh
./build.sh --32 --enterprise
```

## Custom RISC-V compiler

A custom compiler is needed to make the most efficient programs. Clone the [RISC-V GNU toolchain](https://github.com/riscv-collab/riscv-gnu-toolchain), and build it like so:

```sh
./configure --prefix=$HOME/riscv --with-arch=rv32g_zba_zbb_zbc_zbs --with-abi=ilp32d
make
```

After completion, expose the compiler by adding `~/riscv/bin` to PATH. Verify with:

```sh
$ riscv32-unknown-elf-g++ 
riscv32-unknown-elf-g++: fatal error: no input files
```

A 64-bit compiler is supported, but it's not necessary for what this VMOD is trying to achieve.

## Running

```sh
cd demo
./run.sh
```

It will automatically build a basic program, however the filepath might be wrong on your system. Please edit the [Demo VCL](demo/demo.vcl) with your path to the example program.
