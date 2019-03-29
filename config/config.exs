use Mix.Config

app = Mix.Project.config()[:app]

config :logger, backends: [{GelfAMQPHandler, app}]

config :logger, app,
  bind_opts: [
    arguments: [],
    nowait: false,
    routing_key: ""
  ],
  connection_opts: [
    channel_max: 0,
    client_properties: [],
    connection_timeout: 60_000,
    frame_max: 0,
    heartbeat: 10,
    host: "localhost",
    port: 5672,
    ssl_options: :none,
    vhost: "/"
  ],
  exchange_name: "test_exchange",
  exchange_opts: [
    auto_delete: false,
    durable: true,
    internal: false,
    passive: false,
    type: :direct
  ],
  queue_name: "test_queue",
  queue_opts: [
    auto_delete: false,
    durable: true,
    exclusive: false,
    passive: false
  ]

### Imports ###

import_config "#{Mix.env()}.exs"

if File.exists?("#{__DIR__}/#{Mix.env()}.secrets.exs") do
  import_config "#{Mix.env()}.secrets.exs"
end
