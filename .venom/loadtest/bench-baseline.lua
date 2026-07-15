-- VENOM Load Test Script
-- Generated for: http://httpbin.org/get
-- Duration: 60s, Concurrent: 10, Target RPS: 100

wrk.host = "http://httpbin.org/get"
wrk.path = "/"
wrk.threads = 2
wrk.connections = 10


response = function(status, headers, body)
  if status ~= 200 then
    io.stderr:write("Error: " .. status .. "\n")
  end
end

done = function(summary, latency, requests)
  print("=== VENOM Load Test Results ===")
  print(string.format("Requests: %d", summary.requests))
  print(string.format("Duration: %.2fs", summary.duration / 1e6))
  print(string.format("Errors: %d", summary.errors.connect + summary.errors.read + summary.errors.write + summary.errors.status + summary.errors.timeout))
  print(string.format("Latency (avg): %.2fms", latency.mean / 1000))
  print(string.format("Latency (p50): %.2fms", latency.percentile(50) / 1000))
  print(string.format("Latency (p95): %.2fms", latency.percentile(95) / 1000))
  print(string.format("Latency (p99): %.2fms", latency.percentile(99) / 1000))
  print(string.format("Throughput: %.2f req/s", summary.requests / (summary.duration / 1e6)))
end
