defmodule Backend.RabbitMQ do
  @moduledoc false

  alias Config

  @exchange_name Config.exchange_name()
  @routing_key Config.routing_key()

  def init_conn do
    connection_opts = Config.connection_opts()
    queue_opts = Config.queue_opts()
    exchange_opts = Config.exchange_opts()
    bind_opts = Config.bind_opts()

    queue_name = Config.queue_name()
    type = Config.exchange_type()

    with {:ok, connection} <- AMQP.Connection.open(connection_opts),
         {:ok, channel} <- AMQP.Channel.open(connection),
         {:ok, _} <- AMQP.Queue.declare(channel, queue_name, queue_opts),
         :ok <- AMQP.Exchange.declare(channel, @exchange_name, type, exchange_opts),
         :ok <- AMQP.Queue.bind(channel, queue_name, @exchange_name, bind_opts) do
      channel
    else
      error -> {:error, error}
    end
  end

  def publish_gelf(message, channel),
    do: AMQP.Basic.publish(channel, @exchange_name, @routing_key, message)
end
