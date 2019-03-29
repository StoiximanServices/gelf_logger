defmodule Config do
  @moduledoc """
  Provides access to configuration values.
  """

  import Application, only: [get_env: 3]

  @app Mix.Project.config()[:app]

  @gelf_opts get_env(:logger, @app, [])

  @spec bind_opts :: keyword
  def bind_opts, do: Keyword.get(@gelf_opts, :bind_opts)

  @spec connection_host :: String.t()
  def connection_host, do: Keyword.get(@gelf_opts, :connection_opts)[:host]

  @spec connection_opts :: keyword
  def connection_opts, do: Keyword.get(@gelf_opts, :connection_opts)

  @spec exchange_name :: String.t()
  def exchange_name, do: Keyword.get(@gelf_opts, :exchange_name)

  @spec exchange_opts :: keyword
  def exchange_opts, do: Keyword.get(@gelf_opts, :exchange_opts)

  @spec exchange_type :: atom
  def exchange_type, do: Keyword.get(@gelf_opts, :exchange_opts)[:type]

  @spec queue_name :: String.t()
  def queue_name, do: Keyword.get(@gelf_opts, :queue_name)

  @spec queue_opts :: keyword
  def queue_opts, do: Keyword.get(@gelf_opts, :queue_opts)

  @spec routing_key :: String.t()
  def routing_key, do: Keyword.get(@gelf_opts, :bind_opts)[:routing_key]
end
