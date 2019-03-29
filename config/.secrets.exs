# Template secrets configuration.
#
# Clone this file & rename it to {dev | prod | staging}.secrets.exs.
# Then edit it to configure the application credentials for your enviroment.

use Mix.Config

app = Mix.Project.config()[:app]

config :logger, app,
  username: "guest",
  password: "guest"
